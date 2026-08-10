package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Session.run() is the session's only read loop, and the teardown that follows it is the only thing
 * that closes the transport once that loop ends. These tests inject a failure into the loop and
 * check that the teardown -- disconnect() plus clearing isConnected -- runs exactly once on each
 * way out, including the one where an Error is on its way up the stack.
 *
 * <p>
 * Every session here is given a channel first. Without one, disconnect() has nothing to close and
 * returns down an all-no-op path, which would leave these tests asserting that a no-op ran rather
 * than that the session was actually torn down.
 */
class SessionRunTeardownTest {

  /**
   * A session whose read loop fails immediately. The failure is held as an Error or an Exception
   * rather than a Throwable, so that read() hands it back without a cast: a Throwable that was
   * neither would otherwise become a ClassCastException, which run() swallows as just another
   * Exception, and the case would look covered while testing nothing.
   */
  private static class FailingSession extends Session {
    private final Error error;
    private final Exception exception;
    private final boolean exitNormally;
    int disconnectCount;

    private FailingSession(Error error, Exception exception, boolean exitNormally)
        throws JSchException {
      super(new JSch(), null, null, 0);
      this.error = error;
      this.exception = exception;
      this.exitNormally = exitNormally;
    }

    static FailingSession failingWith(Error error) throws JSchException {
      return new FailingSession(error, null, false);
    }

    static FailingSession failingWith(Exception exception) throws JSchException {
      return new FailingSession(null, exception, false);
    }

    /** A session that takes one harmless message and then falls off the end of the loop. */
    static FailingSession exitingNormally() throws JSchException {
      return new FailingSession(null, null, true);
    }

    @Override
    Buffer read(Buffer buf) throws Exception {
      if (error != null) {
        throw error;
      }
      if (exception != null) {
        throw exception;
      }
      if (exitNormally) {
        // Ends the loop through its own condition rather than by throwing. Clearing thread rather
        // than isConnected is deliberate: disconnect() opens with "if (!isConnected) return;", so
        // an exit that cleared isConnected would leave the teardown with nothing to do and this
        // test asserting that a no-op ran.
        thread = null;
        return windowAdjustForUnknownChannel();
      }
      throw new AssertionError("read() must not have been reached");
    }

    @Override
    public void disconnect() {
      disconnectCount++;
      super.disconnect();
    }
  }

  /**
   * A window adjustment for a channel that does not exist -- the one message run()'s switch handles
   * with a plain break, so the loop comes round to its condition having done nothing at all.
   */
  private static Buffer windowAdjustForUnknownChannel() {
    Buffer buf = new Buffer(64);
    buf.putInt(0); // packet length, read and ignored
    buf.putByte((byte) 0); // padding length
    buf.putByte((byte) Session.SSH_MSG_CHANNEL_WINDOW_ADJUST); // getCommand() reads buffer[5]
    buf.putInt(Integer.MAX_VALUE); // no channel has this id
    return buf;
  }

  /** Padding is filled from a Random that only a completed connect() installs. */
  private static final class ZeroRandom implements Random {
    @Override
    public void fill(byte[] foo, int start, int len) {
      Arrays.fill(foo, start, start + len, (byte) 0);
    }
  }

  private Random previousRandom;

  @BeforeEach
  void installRandom() throws Exception {
    Field field = Packet.class.getDeclaredField("random");
    field.setAccessible(true);
    previousRandom = (Random) field.get(null);
    Packet.setRandom(new ZeroRandom());
  }

  @AfterEach
  void restoreRandom() {
    Packet.setRandom(previousRandom);
  }

  /** Puts the session into the state run()'s loop condition requires, without a real connection. */
  private static void markConnected(Session session) throws Exception {
    Field isConnected = Session.class.getDeclaredField("isConnected");
    isConnected.setAccessible(true);
    isConnected.setBoolean(session, true);
  }

  @SuppressWarnings("unchecked")
  private static List<Channel> channelsOf(Session session) throws Exception {
    Field channels = Session.class.getDeclaredField("channels");
    channels.setAccessible(true);
    return (List<Channel>) channels.get(session);
  }

  /**
   * Gives the session something for the teardown to actually do. disconnect() closes the session's
   * channels, and Channel.close() is a write -- so with a channel attached the teardown exercises
   * the path that matters, rather than returning immediately from an empty channel list.
   */
  private static Channel attachChannel(Session session) throws Exception {
    Channel channel = session.openChannel("shell");
    assertNotNull(channel);
    channel.setRecipient(0);
    channel.connected = true;
    return channel;
  }

  private static void assertTornDown(FailingSession session, Channel channel) throws Exception {
    assertEquals(1, session.disconnectCount, "disconnect() must run exactly once");
    assertFalse(session.isConnected(), "a session with no read loop must not report itself alive");
    assertFalse(channel.isConnected(), "the teardown must have closed the session's channels");
    assertTrue(channelsOf(session).isEmpty(),
        "and must have deregistered them, or the session leaks them for ever");
  }

  @Test
  @DisplayName("an Error out of the read loop still tears the session down, and still propagates")
  void errorFromReadLoop() throws Exception {
    FailingSession session = FailingSession.failingWith(new OutOfMemoryError("injected"));
    markConnected(session);
    Channel channel = attachChannel(session);

    OutOfMemoryError thrown = assertThrows(OutOfMemoryError.class, session::run);

    assertEquals("injected", thrown.getMessage(), "the Error must reach the caller unchanged");
    assertTornDown(session, channel);
  }

  @Test
  @DisplayName("an Exception out of the read loop is still swallowed, and still tears down")
  void exceptionFromReadLoop() throws Exception {
    FailingSession session = FailingSession.failingWith(new IOException("injected"));
    markConnected(session);
    Channel channel = attachChannel(session);

    session.run();

    assertTornDown(session, channel);
  }

  @Test
  @DisplayName("an Error out of disconnect() itself still clears isConnected, and is not reported")
  void errorFromTeardown() throws Exception {
    FailingSession session =
        new FailingSession(new OutOfMemoryError("from the read loop"), null, false) {
          @Override
          public void disconnect() {
            super.disconnect();
            // disconnect() allocates, and the heap that the read loop exhausted is still exhausted.
            throw new OutOfMemoryError("from the teardown");
          }
        };
    markConnected(session);
    Channel channel = attachChannel(session);

    OutOfMemoryError thrown = assertThrows(OutOfMemoryError.class, session::run);

    // The teardown's own failure must not stand in for the one that killed the session: Java
    // discards, not suppresses, a Throwable replaced from a finally, so the caller would otherwise
    // be left with an allocation stack trace and no sign of the original.
    assertEquals("from the read loop", thrown.getMessage(),
        "the teardown's own Error must not replace the one on its way up");
    assertEquals(1, session.disconnectCount, "disconnect() must still have been attempted");
    assertFalse(session.isConnected(),
        "isConnected must be cleared even when disconnect() fails with an Error");
    assertFalse(channel.isConnected(),
        "the work disconnect() did before it failed must not be undone");
  }

  @Test
  @DisplayName("an Error out of disconnect() with nothing else on its way up is still reported")
  void errorFromTeardownOnly() throws Exception {
    // The other side of the case above. There the teardown's Error had to give way to the one that
    // killed the read loop; here the loop ended normally, so nothing is propagating, and swallowing
    // it anyway would leave a session that reports itself cleanly disconnected while its socket and
    // streams are still open -- with no exception and nothing logged to say so.
    FailingSession session = new FailingSession(null, null, true) {
      @Override
      public void disconnect() {
        super.disconnect();
        throw new OutOfMemoryError("from the teardown");
      }
    };
    markConnected(session);
    Channel channel = attachChannel(session);

    OutOfMemoryError thrown = assertThrows(OutOfMemoryError.class, session::run);

    assertEquals("from the teardown", thrown.getMessage(),
        "a teardown Error with nothing to mask must reach the caller");
    assertEquals(1, session.disconnectCount, "disconnect() must run exactly once");
    assertFalse(session.isConnected(), "isConnected must be cleared before the Error is rethrown");
    assertFalse(channel.isConnected(),
        "the work disconnect() did before it failed must not be undone");
  }

  @Test
  @DisplayName("a normal loop exit tears the session down too, not just the failing ones")
  void normalLoopExit() throws Exception {
    // The plain fall-off-the-end exit: nothing is thrown, so the catch is never entered and the
    // teardown is reached through the finally alone.
    FailingSession session = FailingSession.exitingNormally();
    markConnected(session);
    Channel channel = attachChannel(session);

    session.run();

    assertTornDown(session, channel);
  }
}
