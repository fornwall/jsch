package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class ChannelAgentForwardingTest {

  private static final byte SSH_AGENT_FAILURE = 5;
  private static final byte SSH2_AGENTC_REQUEST_IDENTITIES = 11;
  private static final byte SSH2_AGENT_IDENTITIES_ANSWER = 12;
  private static final byte UNKNOWN_REQUEST = 99;

  /** A session that records the agent replies a channel hands to the transport. */
  static class RecordingSession extends Session {
    final List<byte[]> sent = new ArrayList<>();

    RecordingSession() throws JSchException {
      super(new JSch(), null, null, 0);
    }

    @Override
    void write(Packet packet, Channel c, int length) {
      Buffer buf = packet.buffer;
      buf.setOffSet(5);
      assertEquals(Session.SSH_MSG_CHANNEL_DATA, buf.getByte());
      buf.getInt(); // recipient
      buf.getInt(); // data length
      sent.add(buf.getString());
    }

    @Override
    void write(Packet packet) {
      // SSH_MSG_CHANNEL_CLOSE and friends; not interesting here.
    }
  }

  private static ChannelAgentForwarding newChannel(Session session) {
    ChannelAgentForwarding channel = new ChannelAgentForwarding();
    channel.setSession(session);
    channel.setRecipient(0);
    channel.setRemotePacketSize(0x4000);
    return channel;
  }

  /** {@code len} messages of {@code SSH2_AGENTC_REQUEST_IDENTITIES}, back to back. */
  private static byte[] requestIdentities(int count) {
    byte[] chunk = new byte[5 * count];
    for (int i = 0; i < chunk.length; i += 5) {
      chunk[i + 3] = 1; // message length
      chunk[i + 4] = SSH2_AGENTC_REQUEST_IDENTITIES;
    }
    return chunk;
  }

  @Test
  void oversizedLengthPrefixIsRefusedWithoutBufferingAnything() throws Exception {
    RecordingSession session = new RecordingSession();
    ChannelAgentForwarding channel = newChannel(session);

    // A message announcing 32 MiB: this is what used to leave rbuf.buffer at 33554436 bytes.
    byte[] header = new byte[] {0x02, 0x00, 0x00, 0x00, UNKNOWN_REQUEST};
    channel.write(header, 0, header.length);

    assertArrayEquals(new byte[] {SSH_AGENT_FAILURE}, session.sent.get(0));
    assertEquals(1, session.sent.size());
    assertTrue(channel.isClosed(), "the channel should have been closed");
    assertEquals(ChannelAgentForwarding.RBUF_INITIAL_SIZE, channel.rbuf.buffer.length);
  }

  @Test
  void queuedRequestsCannotGrowTheBufferWithoutBound() throws Exception {
    // A peer that keeps sending complete requests without waiting for the replies: only one is
    // dispatched per SSH_MSG_CHANNEL_DATA, so the remainder queues up in the reassembly buffer.
    RecordingSession session = new RecordingSession();
    ChannelAgentForwarding channel = newChannel(session);

    byte[] chunk = requestIdentities(3276); // 16380 bytes, just under lmpsize
    int limit = 2 * (4 + ChannelAgentForwarding.MAX_MESSAGE_LENGTH);

    int written = 0;
    while (!channel.isClosed() && written < 32 * 1024 * 1024) {
      channel.write(chunk, 0, chunk.length);
      written += chunk.length;
      assertTrue(channel.rbuf.buffer.length <= limit,
          "rbuf grew to " + channel.rbuf.buffer.length + " after " + written + " bytes");
    }

    assertTrue(channel.isClosed(), "the channel should have been closed");
    assertTrue(written < 1024 * 1024, "refused only after " + written + " bytes");
    assertArrayEquals(new byte[] {SSH_AGENT_FAILURE}, session.sent.get(session.sent.size() - 1));
  }

  @Test
  void wellFormedRequestsAreAnsweredAndTheBufferIsCompacted() throws Exception {
    RecordingSession session = new RecordingSession();
    ChannelAgentForwarding channel = newChannel(session);

    byte[] request = requestIdentities(1);
    for (int i = 0; i < 100; i++) {
      channel.write(request, 0, request.length);
      assertEquals(0, channel.rbuf.index, "nothing should be retained after a dispatch");
      assertEquals(0, channel.rbuf.s);
    }

    assertFalse(channel.isClosed());
    assertEquals(100, session.sent.size());
    assertEquals(SSH2_AGENT_IDENTITIES_ANSWER, session.sent.get(0)[0]);
    assertEquals(ChannelAgentForwarding.RBUF_INITIAL_SIZE, channel.rbuf.buffer.length);
  }

  @Test
  void aLargeButLegalMessageIsStillAccepted() throws Exception {
    RecordingSession session = new RecordingSession();
    ChannelAgentForwarding channel = newChannel(session);

    // 200 KiB: far above anything the agent protocol needs, still below the 256 KiB bound.
    int mlen = 200 * 1024;
    Buffer message = new Buffer(4 + mlen);
    message.putInt(mlen);
    message.putByte(UNKNOWN_REQUEST);
    message.putByte(new byte[mlen - 1]);

    int chunkSize = 0x4000;
    for (int off = 0; off < message.index; off += chunkSize) {
      channel.write(message.buffer, off, Math.min(chunkSize, message.index - off));
    }

    assertFalse(channel.isClosed(), "a 200 KiB message must not be refused");
    assertEquals(1, session.sent.size());
    assertArrayEquals(new byte[] {SSH_AGENT_FAILURE}, session.sent.get(0));
    assertEquals(ChannelAgentForwarding.RBUF_INITIAL_SIZE, channel.rbuf.buffer.length,
        "the high-water mark should have been released again");
  }

  @Test
  void theMaximumIsConfigurable() throws Exception {
    RecordingSession session = new RecordingSession();
    session.setConfig(ChannelAgentForwarding.MAX_MESSAGE_LENGTH_KEY, "1024");
    ChannelAgentForwarding channel = newChannel(session);

    byte[] header = new byte[] {0x00, 0x00, 0x10, 0x00, UNKNOWN_REQUEST}; // 4096 bytes
    channel.write(header, 0, header.length);

    assertTrue(channel.isClosed(), "the channel should have been closed");
    assertArrayEquals(new byte[] {SSH_AGENT_FAILURE}, session.sent.get(0));
  }
}
