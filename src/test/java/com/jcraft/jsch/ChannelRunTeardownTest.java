package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Session.run() is not the only read loop that has to clean up after itself. It is also what starts
 * the channel threads for forwarded-tcpip, x11 and auth-agent channels, and those run() methods had
 * the shape its teardown used to have: catch (Exception), then cleanup that an Error on its way up
 * walks straight past. A channel that ends without disconnect() stays registered on the session
 * with its local socket open, which is the same leak by another route.
 *
 * <p>
 * ChannelX11 and ChannelForwardedTCPIP took the identical change but are not covered here: their
 * run() opens a real socket to the display or forward target on its first statement, so there is no
 * way into either without standing up a live listener.
 */
class ChannelRunTeardownTest {

  private static Session connectedSession() throws Exception {
    Session session = new Session(new JSch(), null, null, 0);
    Field isConnected = Session.class.getDeclaredField("isConnected");
    isConnected.setAccessible(true);
    isConnected.setBoolean(session, true);
    return session;
  }

  @SuppressWarnings("unchecked")
  private static List<Channel> channelsOf(Session session) throws Exception {
    Field channels = Session.class.getDeclaredField("channels");
    channels.setAccessible(true);
    return (List<Channel>) channels.get(session);
  }

  private static void setIo(Channel channel, IO value) throws Exception {
    Field io = Channel.class.getDeclaredField("io");
    io.setAccessible(true);
    io.set(channel, value);
  }

  /** The heap is gone; the next read is where the channel thread finds out. */
  private static IO dyingInput() {
    IO io = new IO();
    io.setInputStream(new InputStream() {
      @Override
      public int read() {
        throw new OutOfMemoryError("injected");
      }

      @Override
      public int read(byte[] b, int off, int len) {
        throw new OutOfMemoryError("injected");
      }
    });
    return io;
  }

  /** A direct-tcpip channel whose very first act -- sendChannelOpen() -- dies with an Error. */
  private static final class DyingDirect extends ChannelDirectTCPIP {
    int disconnects;

    @Override
    public void disconnect() {
      disconnects++;
      super.disconnect();
    }

    @Override
    protected void sendChannelOpen() {
      throw new OutOfMemoryError("injected");
    }
  }

  /**
   * The auth-agent channel, whose run() is nothing but sendOpenConfirmation(). This is the channel
   * the reported heap exhaustion was driven through, which makes it the likeliest of the three to
   * meet an OutOfMemoryError rather than the least.
   */
  private static final class DyingAgentForwarding extends ChannelAgentForwarding {
    int disconnects;

    @Override
    public void disconnect() {
      disconnects++;
      super.disconnect();
    }

    @Override
    protected void sendOpenConfirmation() {
      throw new OutOfMemoryError("injected");
    }
  }

  /** A session channel whose read loop dies with an Error rather than an Exception. */
  private static final class DyingSessionChannel extends ChannelSession {
    int disconnects;

    @Override
    public void disconnect() {
      disconnects++;
      super.disconnect();
    }
  }

  @Test
  @DisplayName("an Error out of ChannelDirectTCPIP.run() still disconnects the channel")
  void directTcpip() throws Exception {
    Session session = connectedSession();
    DyingDirect channel = new DyingDirect();
    channel.setSession(session);
    channelsOf(session).add(channel);

    // 'connected' is deliberately left false, which is the state run() is entered in: the flag is
    // set on the last line of sendChannelOpen(), so a sendChannelOpen() that fails never sets it.
    // Setting it here by hand would be a state the production path cannot reach, and would hide
    // whether disconnect() does anything -- Channel.disconnect() returns on its own first line when
    // the flag is false.
    OutOfMemoryError thrown = assertThrows(OutOfMemoryError.class, channel::run);

    assertEquals("injected", thrown.getMessage(), "the Error must reach the caller unchanged");
    assertEquals(1, channel.disconnects,
        "an Error out of run() must not skip the channel's disconnect()");
    assertFalse(channel.isConnected(), "the channel must not still report itself connected");
    // Set by disconnect() past its early return, so this is what says the teardown really ran
    // rather than returning on its first line.
    assertTrue(channel.eof_local && channel.eof_remote,
        "disconnect() must have torn the channel down, not returned on its guard");
    assertFalse(channelsOf(session).contains(channel),
        "a channel that has torn down must not stay registered on the session");
  }

  @Test
  @DisplayName("an Error out of ChannelAgentForwarding.run() still disconnects the channel")
  void agentForwarding() throws Exception {
    Session session = connectedSession();
    DyingAgentForwarding channel = new DyingAgentForwarding();
    channel.setSession(session);
    channelsOf(session).add(channel);

    OutOfMemoryError thrown = assertThrows(OutOfMemoryError.class, channel::run);

    assertEquals("injected", thrown.getMessage(), "the Error must reach the caller unchanged");
    assertEquals(1, channel.disconnects,
        "an Error out of run() must not skip the channel's disconnect()");
    assertTrue(channel.close, "the Exception path sets close, and the Error path must too");
    assertFalse(channelsOf(session).contains(channel),
        "a channel that has torn down must not stay registered on the session");
  }

  @Test
  @DisplayName("an Error out of ChannelSession.run() still clears the channel's thread")
  void sessionChannel() throws Exception {
    Session session = connectedSession();
    DyingSessionChannel channel = new DyingSessionChannel();
    channel.setSession(session);
    channel.connected = true;
    channelsOf(session).add(channel);
    setIo(channel, dyingInput());
    channel.thread = Thread.currentThread();

    OutOfMemoryError thrown = assertThrows(OutOfMemoryError.class, channel::run);

    assertEquals("injected", thrown.getMessage(), "the Error must reach the caller unchanged");
    // thread == null is half of run()'s own loop condition and is how the channel says its reader
    // has finished. An Error used to skip it, leaving the field pointing at a thread that is gone.
    assertNull(channel.thread, "an Error out of run() must not leave a dead thread behind");
  }

  /** Guards the ordinary path: an IOException is still swallowed, and still tears down. */
  @Test
  @DisplayName("an Exception out of ChannelSession.run() is still swallowed, and still clears up")
  void sessionChannelException() throws Exception {
    Session session = connectedSession();
    DyingSessionChannel channel = new DyingSessionChannel();
    channel.setSession(session);
    channel.connected = true;
    channelsOf(session).add(channel);
    IO io = new IO();
    io.setInputStream(new InputStream() {
      @Override
      public int read() throws IOException {
        throw new IOException("injected");
      }

      @Override
      public int read(byte[] b, int off, int len) throws IOException {
        throw new IOException("injected");
      }
    });
    setIo(channel, io);
    channel.thread = Thread.currentThread();

    channel.run();

    assertNull(channel.thread, "the Exception path must clear the thread as it always did");
  }
}
