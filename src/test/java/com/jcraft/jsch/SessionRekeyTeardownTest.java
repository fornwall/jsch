package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * in_kex parks every write() in a ten-millisecond sleep loop, and only the read loop ever clears
 * it. If the read loop dies while a key exchange is in flight, the flag is left set on a session
 * that can never finish one -- so the parked writers never come back, and neither does the teardown
 * itself, because disconnect() closes the channels and Channel.close() is a write.
 */
class SessionRekeyTeardownTest {

  /**
   * A session whose read loop dies on its first read with an Error rather than an Exception. That
   * is the interesting case: the catch in run() clears in_kex on its way past, so on the Exception
   * path the flag is already down by the time the teardown runs. An Error skips the catch, and the
   * normal loop exit never enters it, so those two reach the teardown with the flag still set.
   */
  private static class DyingSession extends Session {
    DyingSession() throws JSchException {
      super(new JSch(), null, null, 0);
    }

    @Override
    Buffer read(Buffer buf) {
      throw new OutOfMemoryError("injected");
    }
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
    // A session that was up and has since been torn down leaves this set. Without it the packet
    // writes below would die in padding() with a NullPointerException, and these tests would be
    // measuring a static field that is never null in a real session.
    Field field = Packet.class.getDeclaredField("random");
    field.setAccessible(true);
    previousRandom = (Random) field.get(null);
    Packet.setRandom(new ZeroRandom());
  }

  @AfterEach
  void restoreRandom() {
    Packet.setRandom(previousRandom);
  }

  private static void set(Session session, String name, boolean value) throws Exception {
    Field field = Session.class.getDeclaredField(name);
    field.setAccessible(true);
    field.setBoolean(session, value);
  }

  private static boolean get(Session session, String name) throws Exception {
    Field field = Session.class.getDeclaredField(name);
    field.setAccessible(true);
    return field.getBoolean(session);
  }

  private static Packet channelDataPacket(Channel channel) {
    Buffer buf = new Buffer(100);
    Packet packet = new Packet(buf);
    packet.reset();
    buf.putByte((byte) Session.SSH_MSG_CHANNEL_DATA);
    buf.putInt(channel.getRecipient());
    buf.putInt(1);
    buf.putByte((byte) 'x');
    return packet;
  }

  @Test
  @DisplayName("a read loop that dies mid-rekey releases its parked writers, and itself")
  void readLoopDiesMidRekey() throws Exception {
    DyingSession session = new DyingSession();
    set(session, "isConnected", true);

    Channel channel = session.openChannel("shell");
    assertNotNull(channel, "the channel is what makes disconnect() write during the teardown");
    channel.setRecipient(0);
    channel.connected = true;
    // No remote window, so the writer has to reach the c.close check rather than just sending.
    channel.rwsize = 0;

    // A key exchange is in flight. getTimeout() is 0 by default, so nothing bounds the wait.
    set(session, "in_kex", true);

    Packet packet = channelDataPacket(channel);
    AtomicReference<Throwable> writerResult = new AtomicReference<>();
    Thread writer = new Thread(() -> {
      try {
        session.write(packet, channel, 1);
      } catch (Throwable t) {
        writerResult.set(t);
      }
    }, "test writer");
    writer.setDaemon(true);
    writer.start();

    // Give it time to park in the kex loop, and confirm that is where it is.
    Thread.sleep(200);
    assertTrue(writer.isAlive(), "the writer should be waiting for the key exchange");
    assertNull(writerResult.get(), "the writer should not have failed yet");

    // The read loop dies. Its teardown closes the channel, and Channel.close() writes an
    // SSH_MSG_CHANNEL_CLOSE, which write(Packet) does not let through during a key exchange -- so a
    // teardown that did not clear in_kex first would park here and never return.
    assertTimeoutPreemptively(Duration.ofSeconds(10),
        () -> assertThrows(OutOfMemoryError.class, session::run),
        "the teardown parked waiting for a key exchange that can never complete");

    assertFalse(get(session, "in_kex"), "a session with no read loop cannot be in a key exchange");
    assertFalse(session.isConnected());

    writer.join(10_000);
    assertFalse(writer.isAlive(), "the parked writer must be released by the teardown");
    assertNotNull(writerResult.get(), "and must be told the write failed, not that it succeeded");
  }

  @Test
  @DisplayName("rekey() on a session that is down is refused, and does not arm in_kex")
  void rekeyOnDownSession() throws Exception {
    Session session = new Session(new JSch(), null, null, 0);

    Throwable thrown = assertThrows(Throwable.class, session::rekey);

    // The flag matters more than the exception: send_kexinit() arms it before it builds the
    // proposal, so a rekey that fails partway used to leave it armed, and every later write on the
    // session would then park in the kex loop with no read loop left to release it.
    assertFalse(get(session, "in_kex"), "a rekey that did not happen must not leave in_kex armed");
    assertTrue(thrown instanceof JSchException, "expected a JSchException, got " + thrown);
    assertEquals("session is down", thrown.getMessage());
  }
}
