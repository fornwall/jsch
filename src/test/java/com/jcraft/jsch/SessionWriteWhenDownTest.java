package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Field;
import java.util.Arrays;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * _write() is the one place every outgoing packet passes through, and it used to encode the packet,
 * find no transport to put it on, and return normally. A write on a session whose transport is gone
 * therefore looked to its caller exactly like a write that succeeded.
 */
class SessionWriteWhenDownTest {

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
    // A session that was up and has since been torn down leaves this set, so encode() succeeds and
    // the packet reaches the io check. Without it the old code died in padding() with a
    // NullPointerException, which would prove something other than what this test is about.
    previousRandom = packetRandom();
    Packet.setRandom(new ZeroRandom());
  }

  @AfterEach
  void restoreRandom() {
    Packet.setRandom(previousRandom);
  }

  private static Random packetRandom() throws Exception {
    Field field = Packet.class.getDeclaredField("random");
    field.setAccessible(true);
    return (Random) field.get(null);
  }

  private static Packet channelClosePacket() {
    Buffer buf = new Buffer(100);
    Packet packet = new Packet(buf);
    packet.reset();
    buf.putByte((byte) Session.SSH_MSG_CHANNEL_CLOSE);
    buf.putInt(0);
    return packet;
  }

  @Test
  @DisplayName("write() with no transport fails instead of reporting a success it did not have")
  void writeWithNoTransport() throws Exception {
    Session session = new Session(new JSch(), null, null, 0);

    JSchException e = assertThrows(JSchException.class, () -> session.write(channelClosePacket()));

    assertEquals("session is down", e.getMessage());
  }
}
