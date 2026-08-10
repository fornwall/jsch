package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ChannelAgentForwardingTest {

  private static final byte SSH_AGENT_FAILURE = 5;
  private static final byte SSH_AGENT_SUCCESS = 6;
  private static final byte SSH2_AGENTC_REQUEST_IDENTITIES = 11;
  private static final byte SSH2_AGENT_IDENTITIES_ANSWER = 12;
  private static final byte SSH2_AGENTC_ADD_IDENTITY = 17;
  private static final byte UNKNOWN_REQUEST = 99;
  private static final long WAIT_TIMEOUT_MILLIS = 5000;

  private final List<ChannelAgentForwarding> channels = new ArrayList<>();
  private final List<Thread> workers = new ArrayList<>();

  private static class RecordingSession extends Session {
    private final List<byte[]> sent = new ArrayList<>();
    private boolean channelOpened = false;

    RecordingSession() throws JSchException {
      super(new JSch(), null, null, 0);
    }

    @Override
    synchronized void write(Packet packet) {
      channelOpened = true;
      notifyAll();
    }

    @Override
    synchronized void write(Packet packet, Channel channel, int length) {
      Buffer buffer = packet.buffer;
      buffer.setOffSet(5);
      assertEquals(Session.SSH_MSG_CHANNEL_DATA, buffer.getByte());
      buffer.getInt();
      buffer.getInt();
      sent.add(buffer.getString());
      notifyAll();
    }

    synchronized void awaitChannelOpen() throws InterruptedException {
      long deadline = System.currentTimeMillis() + WAIT_TIMEOUT_MILLIS;
      long remaining;
      while (!channelOpened && (remaining = deadline - System.currentTimeMillis()) > 0) {
        wait(remaining);
      }
      assertTrue(channelOpened);
    }

    synchronized void awaitSent(int count) throws InterruptedException {
      long deadline = System.currentTimeMillis() + WAIT_TIMEOUT_MILLIS;
      long remaining;
      while (sent.size() < count && (remaining = deadline - System.currentTimeMillis()) > 0) {
        wait(remaining);
      }
      assertEquals(count, sent.size());
    }

    synchronized int sentSize() {
      return sent.size();
    }

    synchronized byte[] sent(int index) {
      return sent.get(index);
    }

    @Override
    public boolean isConnected() {
      return true;
    }
  }

  private static final class FlowControlledSession extends RecordingSession {
    private final CountDownLatch windowExhausted = new CountDownLatch(1);
    private long availableWindow;
    private boolean windowReleased = false;

    FlowControlledSession(long availableWindow) throws JSchException {
      this.availableWindow = availableWindow;
    }

    @Override
    void write(Packet packet, Channel channel, int length) {
      synchronized (this) {
        while (availableWindow < length && !windowReleased && !channel.isClosed()) {
          windowExhausted.countDown();
          try {
            wait(100);
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return;
          }
        }
        if (channel.isClosed()) {
          return;
        }
        if (!windowReleased) {
          availableWindow -= length;
        }
      }
      super.write(packet, channel, length);
    }

    void awaitWindowExhausted() throws InterruptedException {
      assertTrue(windowExhausted.await(WAIT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));
    }

    synchronized void releaseWindow() {
      windowReleased = true;
      notifyAll();
    }
  }

  private static final class RecordingIdentityRepository implements IdentityRepository {
    private final List<byte[]> added = new ArrayList<>();

    @Override
    public String getName() {
      return "test";
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
      return false;
    }

    @Override
    public void removeAll() {}
  }

  private static final class BlockingIdentityRepository implements IdentityRepository {
    private final CountDownLatch entered = new CountDownLatch(1);
    private final CountDownLatch release = new CountDownLatch(1);

    @Override
    public String getName() {
      return "blocking-test";
    }

    @Override
    public int getStatus() {
      return RUNNING;
    }

    @Override
    public Vector<Identity> getIdentities() {
      entered.countDown();
      try {
        release.await();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
      return new Vector<>();
    }

    @Override
    public boolean add(byte[] identity) {
      return false;
    }

    @Override
    public boolean remove(byte[] blob) {
      return false;
    }

    @Override
    public void removeAll() {}

    void awaitEntered() throws InterruptedException {
      assertTrue(entered.await(WAIT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));
    }

    void release() {
      release.countDown();
    }
  }

  private static final class ConcurrentIdentityRepository implements IdentityRepository {
    private final AtomicInteger calls = new AtomicInteger();
    private final CountDownLatch firstEntered = new CountDownLatch(1);
    private final CountDownLatch secondEntered = new CountDownLatch(1);
    private final CountDownLatch releaseFirst = new CountDownLatch(1);

    @Override
    public String getName() {
      return "concurrent-test";
    }

    @Override
    public int getStatus() {
      return RUNNING;
    }

    @Override
    public Vector<Identity> getIdentities() {
      if (calls.incrementAndGet() == 1) {
        firstEntered.countDown();
        try {
          releaseFirst.await();
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      } else {
        secondEntered.countDown();
      }
      return new Vector<>();
    }

    @Override
    public boolean add(byte[] identity) {
      return false;
    }

    @Override
    public boolean remove(byte[] blob) {
      return false;
    }

    @Override
    public void removeAll() {}

    void awaitFirstEntered() throws InterruptedException {
      assertTrue(firstEntered.await(WAIT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));
    }

    boolean secondEntered(long timeoutMillis) throws InterruptedException {
      return secondEntered.await(timeoutMillis, TimeUnit.MILLISECONDS);
    }

    void releaseFirst() {
      releaseFirst.countDown();
    }
  }

  @AfterEach
  void stopWorkers() throws InterruptedException {
    for (ChannelAgentForwarding channel : channels) {
      channel.disconnect();
    }
    for (Thread worker : workers) {
      worker.join(WAIT_TIMEOUT_MILLIS);
      assertFalse(worker.isAlive());
    }
  }

  private ChannelAgentForwarding newChannel(RecordingSession session) throws Exception {
    ChannelAgentForwarding channel = new ChannelAgentForwarding();
    channel.setSession(session);
    return startChannel(session, channel);
  }

  private ChannelAgentForwarding newRegisteredChannel(RecordingSession session) throws Exception {
    ChannelAgentForwarding channel = new ChannelAgentForwarding();
    assertSame(channel, session.addChannel(channel));
    return startChannel(session, channel);
  }

  private ChannelAgentForwarding startChannel(RecordingSession session,
      ChannelAgentForwarding channel) throws Exception {
    channel.setRecipient(0);
    channel.setRemotePacketSize(0x4000);
    channels.add(channel);
    Thread worker = new Thread(channel::run);
    worker.setDaemon(true);
    workers.add(worker);
    worker.start();
    session.awaitChannelOpen();
    return channel;
  }

  private static byte[] requestIdentities(int count) {
    byte[] requests = new byte[5 * count];
    for (int i = 0; i < requests.length; i += 5) {
      requests[i + 3] = 1;
      requests[i + 4] = SSH2_AGENTC_REQUEST_IDENTITIES;
    }
    return requests;
  }

  private static byte[] unknownRequest(int messageLength) {
    Buffer request = new Buffer(4 + messageLength);
    request.putInt(messageLength);
    request.putByte(UNKNOWN_REQUEST);
    request.putByte(new byte[messageLength - 1]);
    return request.buffer;
  }

  @Test
  void rejectsInvalidMessageLengths() throws Exception {
    int[] invalidLengths = {0, ChannelAgentForwarding.MAX_MESSAGE_LENGTH + 1, -1};

    for (int length : invalidLengths) {
      RecordingSession session = new RecordingSession();
      ChannelAgentForwarding channel = newChannel(session);
      Buffer header = new Buffer(4);
      header.putInt(length);

      IOException exception =
          assertThrows(IOException.class, () -> channel.write(header.buffer, 0, header.index));

      assertEquals("Illegal agent message length: " + (length & 0xffffffffL),
          exception.getMessage());
      assertEquals(0, session.sentSize());
      assertEquals(0, channel.rbuf.index);
      assertEquals(ChannelAgentForwarding.RBUF_INITIAL_SIZE, channel.rbuf.buffer.length);
    }
  }

  @Test
  void acceptsFragmentedLengthPrefix() throws Exception {
    RecordingSession session = new RecordingSession();
    ChannelAgentForwarding channel = newChannel(session);
    byte[] request = requestIdentities(1);

    for (int i = 0; i < request.length; i++) {
      channel.write(request, i, 1);
      if (i < request.length - 1) {
        assertEquals(0, session.sentSize());
      }
    }

    session.awaitSent(1);
    assertEquals(SSH2_AGENT_IDENTITIES_ANSWER, session.sent(0)[0]);
  }

  @Test
  void drainsPipelinedRequests() throws Exception {
    RecordingSession session = new RecordingSession();
    ChannelAgentForwarding channel = newChannel(session);

    byte[] requests = requestIdentities(100);
    channel.write(requests, 0, requests.length);

    session.awaitSent(100);
    assertFalse(channel.isClosed());
    assertEquals(100, session.sentSize());
    assertEquals(0, channel.rbuf.index);
  }

  @Test
  void drainsRequestsWithoutBlockingTheSessionReader() throws Exception {
    FlowControlledSession session = new FlowControlledSession(9);
    ChannelAgentForwarding channel = newChannel(session);
    ExecutorService sessionReader = Executors.newSingleThreadExecutor();
    Future<?> write = null;

    try {
      byte[] requests = requestIdentities(2);
      write = sessionReader.submit(() -> {
        channel.write(requests, 0, requests.length);
        return null;
      });

      session.awaitWindowExhausted();
      write.get(1, TimeUnit.SECONDS);
      assertEquals(1, session.sentSize());
    } finally {
      session.releaseWindow();
      if (write != null) {
        write.get(WAIT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
      }
      sessionReader.shutdownNow();
    }

    session.awaitSent(2);
  }

  @Test
  void boundsQueuedRequestsWhileReplyWindowIsExhausted() throws Exception {
    FlowControlledSession session = new FlowControlledSession(0);
    ChannelAgentForwarding channel = newChannel(session);

    try {
      byte[] maximumRequest = unknownRequest(ChannelAgentForwarding.MAX_MESSAGE_LENGTH);
      channel.write(maximumRequest, 0, maximumRequest.length);
      session.awaitWindowExhausted();
      channel.write(maximumRequest, 0, maximumRequest.length);

      byte[] additionalRequest = unknownRequest(1);
      IOException exception = assertThrows(IOException.class,
          () -> channel.write(additionalRequest, 0, additionalRequest.length));

      assertEquals(
          "Agent request queue exceeds " + ChannelAgentForwarding.MAX_MESSAGE_LENGTH + " bytes",
          exception.getMessage());
    } finally {
      session.releaseWindow();
    }

    session.awaitSent(2);
  }

  @Test
  void boundsQueuedRequestCountWhileReplyWindowIsExhausted() throws Exception {
    FlowControlledSession session = new FlowControlledSession(0);
    ChannelAgentForwarding channel = newChannel(session);
    byte[] request = unknownRequest(1);

    try {
      channel.write(request, 0, request.length);
      session.awaitWindowExhausted();
      for (int i = 0; i < ChannelAgentForwarding.MAX_QUEUED_MESSAGES; i++) {
        channel.write(request, 0, request.length);
      }

      IOException exception =
          assertThrows(IOException.class, () -> channel.write(request, 0, request.length));

      assertEquals(
          "Agent request queue exceeds " + ChannelAgentForwarding.MAX_QUEUED_MESSAGES + " messages",
          exception.getMessage());
    } finally {
      session.releaseWindow();
    }

    session.awaitSent(ChannelAgentForwarding.MAX_QUEUED_MESSAGES + 1);
  }

  @Test
  void boundsAgentForwardingChannelsPerSession() throws Exception {
    RecordingSession session = new RecordingSession();
    BlockingIdentityRepository repository = new BlockingIdentityRepository();
    session.setIdentityRepository(repository);
    List<ChannelAgentForwarding> accepted = new ArrayList<>();
    ChannelAgentForwarding blocked = newRegisteredChannel(session);
    Thread blockedWorker = workers.get(workers.size() - 1);
    accepted.add(blocked);
    byte[] request = requestIdentities(1);
    blocked.write(request, 0, request.length);
    repository.awaitEntered();

    try {
      for (int i = 1; i < ChannelAgentForwarding.MAX_CHANNELS_PER_SESSION; i++) {
        ChannelAgentForwarding channel = new ChannelAgentForwarding();
        assertSame(channel, session.addChannel(channel));
        accepted.add(channel);
        channels.add(channel);
      }

      assertNull(session.addChannel(new ChannelAgentForwarding()));

      blocked.disconnect();
      assertNull(session.addChannel(new ChannelAgentForwarding()));
    } finally {
      repository.release();
    }

    blockedWorker.join(WAIT_TIMEOUT_MILLIS);
    assertFalse(blockedWorker.isAlive());

    try {
      ChannelAgentForwarding replacement = new ChannelAgentForwarding();
      assertSame(replacement, session.addChannel(replacement));
      accepted.add(replacement);
      channels.add(replacement);
    } finally {
      for (ChannelAgentForwarding channel : accepted) {
        channel.disconnect();
      }
    }
  }

  @Test
  void serializesIdentityRepositoryAccessAcrossChannels() throws Exception {
    RecordingSession session = new RecordingSession();
    ConcurrentIdentityRepository repository = new ConcurrentIdentityRepository();
    session.setIdentityRepository(repository);
    ChannelAgentForwarding first = newChannel(session);
    ChannelAgentForwarding second = newChannel(session);
    byte[] request = requestIdentities(1);

    first.write(request, 0, request.length);
    repository.awaitFirstEntered();

    try {
      second.write(request, 0, request.length);
      assertFalse(repository.secondEntered(200));
    } finally {
      repository.releaseFirst();
    }

    assertTrue(repository.secondEntered(WAIT_TIMEOUT_MILLIS));
    session.awaitSent(2);
  }

  @Test
  void keepsPipelinedAddIdentityWithinItsMessage() throws Exception {
    RecordingSession session = new RecordingSession();
    RecordingIdentityRepository repository = new RecordingIdentityRepository();
    session.setIdentityRepository(repository);

    byte[] identity = {1, 2, 3};
    Buffer requests = new Buffer(4 + 1 + identity.length + 5);
    requests.putInt(1 + identity.length);
    requests.putByte(SSH2_AGENTC_ADD_IDENTITY);
    requests.putByte(identity);
    requests.putByte(requestIdentities(1));
    ChannelAgentForwarding channel = newChannel(session);
    channel.write(requests.buffer, 0, requests.index);

    session.awaitSent(2);
    assertEquals(1, repository.added.size());
    assertArrayEquals(identity, repository.added.get(0));
    assertEquals(2, session.sentSize());
    assertArrayEquals(new byte[] {SSH_AGENT_SUCCESS}, session.sent(0));
    assertEquals(SSH2_AGENT_IDENTITIES_ANSWER, session.sent(1)[0]);
  }

  @Test
  void releasesBufferAfterLargeMessage() throws Exception {
    RecordingSession session = new RecordingSession();
    ChannelAgentForwarding channel = newChannel(session);

    int messageLength = 200 * 1024;
    Buffer message = new Buffer(4 + messageLength);
    message.putInt(messageLength);
    message.putByte(UNKNOWN_REQUEST);
    message.putByte(new byte[messageLength - 1]);

    int chunkSize = 0x4000;
    for (int offset = 0; offset < message.index; offset += chunkSize) {
      channel.write(message.buffer, offset, Math.min(chunkSize, message.index - offset));
      assertTrue(channel.rbuf.buffer.length <= 4 + ChannelAgentForwarding.MAX_MESSAGE_LENGTH);
    }

    session.awaitSent(1);
    assertFalse(channel.isClosed());
    assertArrayEquals(new byte[] {SSH_AGENT_FAILURE}, session.sent(0));
    assertEquals(ChannelAgentForwarding.RBUF_INITIAL_SIZE, channel.rbuf.buffer.length);
  }
}
