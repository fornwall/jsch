package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Vector;
import org.junit.jupiter.api.Test;

class ChannelAgentForwardingTest {

  private static final byte SSH_AGENTC_REQUEST_RSA_IDENTITIES = 1;
  private static final byte SSH_AGENT_RSA_IDENTITIES_ANSWER = 2;
  private static final byte SSH_AGENT_FAILURE = 5;
  private static final byte SSH_AGENT_SUCCESS = 6;
  private static final byte SSH2_AGENTC_REQUEST_IDENTITIES = 11;
  private static final byte SSH2_AGENT_IDENTITIES_ANSWER = 12;
  private static final byte SSH2_AGENTC_SIGN_REQUEST = 13;
  private static final byte SSH2_AGENTC_ADD_IDENTITY = 17;
  private static final byte SSH2_AGENTC_EXTENSION = 27;
  private static final byte SSH2_AGENT_FAILURE = 30;
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

  /** An identity repository that records the blob every {@code add} was handed. */
  static class RecordingRepository implements IdentityRepository {
    final List<byte[]> added = new ArrayList<>();

    @Override
    public String getName() {
      return "recording";
    }

    @Override
    public int getStatus() {
      return RUNNING;
    }

    @Override
    public Vector<Identity> getIdentities() {
      return new Vector<>();
    }

    @Override
    public boolean add(byte[] identity) {
      added.add(identity);
      return true;
    }

    @Override
    public boolean remove(byte[] blob) {
      return true;
    }

    @Override
    public void removeAll() {}
  }

  /** Prefixes {@code body} with its length, giving one complete agent message. */
  private static byte[] framed(Buffer body) {
    Buffer out = new Buffer(4 + body.index);
    out.putInt(body.index);
    out.putByte(body.buffer, 0, body.index);
    return out.buffer;
  }

  /** One request of {@code type} carrying no payload. */
  private static byte[] bare(byte type) {
    Buffer body = new Buffer(1);
    body.putByte(type);
    return framed(body);
  }

  /**
   * A real {@code session-bind@openssh.com}, which modern OpenSSH sends down every forwarded agent
   * channel. It arrives as {@code SSH2_AGENTC_EXTENSION}, a type this agent does not implement, so
   * it is the reachable case of the unknown-type branch.
   */
  private static byte[] sessionBind() {
    Buffer body = new Buffer(512);
    body.putByte(SSH2_AGENTC_EXTENSION);
    body.putString(Util.str2byte("session-bind@openssh.com"));
    body.putString(Util.str2byte("host key blob"));
    body.putString(Util.str2byte("session identifier"));
    body.putString(Util.str2byte("signature over the session identifier"));
    body.putByte((byte) 1); // is_forwarding
    return framed(body);
  }

  /** A signature request for a key no repository here holds, so the answer is a failure. */
  private static byte[] signRequest() {
    Buffer body = new Buffer(512);
    body.putByte(SSH2_AGENTC_SIGN_REQUEST);
    body.putString(Util.str2byte("public key blob of a key nobody has"));
    body.putString(Util.str2byte("data to be signed"));
    body.putInt(0); // flags
    return framed(body);
  }

  private static byte[] addIdentity(byte[] payload) {
    Buffer body = new Buffer(1 + payload.length);
    body.putByte(SSH2_AGENTC_ADD_IDENTITY);
    body.putByte(payload);
    return framed(body);
  }

  private static byte[] concat(byte[]... parts) {
    int length = 0;
    for (byte[] part : parts) {
      length += part.length;
    }
    byte[] out = new byte[length];
    int offset = 0;
    for (byte[] part : parts) {
      System.arraycopy(part, 0, out, offset, part.length);
      offset += part.length;
    }
    return out;
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
    // A peer that keeps sending complete requests without waiting for the replies. Whatever the
    // channel does with them, the reassembly buffer must not be a place the peer can grow.
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

  @Test
  void bothPipelinedRequestsAreAnsweredInOrder() throws Exception {
    RecordingSession session = new RecordingSession();
    ChannelAgentForwarding channel = newChannel(session);

    // Two different requests, so the replies also say which was answered first.
    byte[] chunk =
        concat(bare(SSH2_AGENTC_REQUEST_IDENTITIES), bare(SSH_AGENTC_REQUEST_RSA_IDENTITIES));
    channel.write(chunk, 0, chunk.length);

    assertFalse(channel.isClosed());
    assertEquals(2, session.sent.size(), "both pipelined requests should have been answered");
    assertEquals(SSH2_AGENT_IDENTITIES_ANSWER, session.sent.get(0)[0]);
    assertEquals(SSH_AGENT_RSA_IDENTITIES_ANSWER, session.sent.get(1)[0]);
    assertEquals(0, channel.rbuf.getLength(), "nothing should be left over");
  }

  @Test
  void anUnknownTypeDoesNotSwallowWhatFollowsIt() throws Exception {
    RecordingSession session = new RecordingSession();
    ChannelAgentForwarding channel = newChannel(session);

    byte[] chunk = concat(sessionBind(), signRequest());
    channel.write(chunk, 0, chunk.length);

    assertFalse(channel.isClosed());
    assertEquals(2, session.sent.size(), "the request behind session-bind was destroyed");
    assertArrayEquals(new byte[] {SSH_AGENT_FAILURE}, session.sent.get(0),
        "an extension this agent does not implement is a failure");
    assertEquals(SSH2_AGENT_FAILURE, session.sent.get(1)[0],
        "no identity matches, but the sign request must still be answered");
    assertEquals(0, channel.rbuf.getLength());
  }

  @Test
  void addIdentityTakesItsOwnPayloadAndNoMore() throws Exception {
    RecordingSession session = new RecordingSession();
    RecordingRepository repository = new RecordingRepository();
    session.setIdentityRepository(repository);
    ChannelAgentForwarding channel = newChannel(session);

    byte[] payload = Util.str2byte("the private key blob of an identity being added");
    byte[] chunk = concat(addIdentity(payload), bare(SSH2_AGENTC_REQUEST_IDENTITIES));
    channel.write(chunk, 0, chunk.length);

    assertFalse(channel.isClosed());
    assertEquals(1, repository.added.size());
    assertArrayEquals(payload, repository.added.get(0),
        "the repository was handed the message behind the add as part of the key");
    assertEquals(2, session.sent.size(), "the request behind the add was destroyed");
    assertArrayEquals(new byte[] {SSH_AGENT_SUCCESS}, session.sent.get(0));
    assertEquals(SSH2_AGENT_IDENTITIES_ANSWER, session.sent.get(1)[0]);
    assertEquals(0, channel.rbuf.getLength());
  }

  @Test
  void aMessageSplitAcrossTwoPacketsIsStillReassembled() throws Exception {
    RecordingSession session = new RecordingSession();
    ChannelAgentForwarding channel = newChannel(session);

    // The split falls inside the key blob, so neither half is a message on its own.
    byte[] request = signRequest();
    int split = 9;
    channel.write(request, 0, split);
    assertEquals(0, session.sent.size(), "half a message must not be answered");

    channel.write(request, split, request.length - split);

    assertFalse(channel.isClosed());
    assertEquals(1, session.sent.size());
    assertEquals(SSH2_AGENT_FAILURE, session.sent.get(0)[0]);
    assertEquals(0, channel.rbuf.getLength());
  }

  @Test
  void aSplitInsideTheLengthPrefixIsStillReassembled() throws Exception {
    RecordingSession session = new RecordingSession();
    ChannelAgentForwarding channel = newChannel(session);

    byte[] request = bare(SSH2_AGENTC_REQUEST_IDENTITIES);
    channel.write(request, 0, 2);
    assertEquals(0, session.sent.size(), "half a length prefix must not be answered");

    channel.write(request, 2, request.length - 2);

    assertFalse(channel.isClosed());
    assertEquals(1, session.sent.size());
    assertEquals(SSH2_AGENT_IDENTITIES_ANSWER, session.sent.get(0)[0]);
  }

  @Test
  void aTrailingPartialMessageSurvivesTheDrain() throws Exception {
    RecordingSession session = new RecordingSession();
    ChannelAgentForwarding channel = newChannel(session);

    // Two complete requests and the first three bytes of a third: the drain must answer the two
    // and leave the fragment where the next packet can complete it.
    byte[] third = bare(SSH2_AGENTC_REQUEST_IDENTITIES);
    byte[] chunk = concat(bare(SSH2_AGENTC_REQUEST_IDENTITIES),
        bare(SSH_AGENTC_REQUEST_RSA_IDENTITIES), new byte[] {third[0], third[1], third[2]});
    channel.write(chunk, 0, chunk.length);

    assertEquals(2, session.sent.size());
    assertEquals(3, channel.rbuf.getLength(), "the fragment should still be buffered");
    assertEquals(0, channel.rbuf.s, "and it should have been shifted to the front");

    channel.write(third, 3, third.length - 3);

    assertFalse(channel.isClosed());
    assertEquals(3, session.sent.size());
    assertEquals(SSH2_AGENT_IDENTITIES_ANSWER, session.sent.get(2)[0]);
  }

  @Test
  void aPacketMayNotCarryUnboundedlyManyMessages() throws Exception {
    RecordingSession session = new RecordingSession();
    ChannelAgentForwarding channel = newChannel(session);

    int count = ChannelAgentForwarding.MAX_MESSAGES_PER_PACKET + 1;
    byte[] chunk = requestIdentities(count);
    channel.write(chunk, 0, chunk.length);

    assertTrue(channel.isClosed(), "the channel should have been closed");
    assertEquals(ChannelAgentForwarding.MAX_MESSAGES_PER_PACKET + 1, session.sent.size(),
        "the cap should be answered up to, then refused");
    assertEquals(SSH2_AGENT_IDENTITIES_ANSWER,
        session.sent.get(ChannelAgentForwarding.MAX_MESSAGES_PER_PACKET - 1)[0]);
    assertArrayEquals(new byte[] {SSH_AGENT_FAILURE}, session.sent.get(session.sent.size() - 1));
  }

  @Test
  void aPacketAtTheCapIsAnsweredInFull() throws Exception {
    RecordingSession session = new RecordingSession();
    ChannelAgentForwarding channel = newChannel(session);

    byte[] chunk = requestIdentities(ChannelAgentForwarding.MAX_MESSAGES_PER_PACKET);
    channel.write(chunk, 0, chunk.length);

    assertFalse(channel.isClosed(), "exactly the cap is not too many");
    assertEquals(ChannelAgentForwarding.MAX_MESSAGES_PER_PACKET, session.sent.size());
    assertEquals(0, channel.rbuf.getLength());
  }
}
