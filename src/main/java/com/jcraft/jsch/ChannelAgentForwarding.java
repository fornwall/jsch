/*
 * Copyright (c) 2006-2018 ymnk, JCraft,Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions
 * and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other materials provided with
 * the distribution.
 *
 * 3. The names of the authors may not be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL JCRAFT, INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.jcraft.jsch;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Vector;

class ChannelAgentForwarding extends Channel {

  private static final int LOCAL_WINDOW_SIZE_MAX = 0x20000;
  private static final int LOCAL_MAXIMUM_PACKET_SIZE = 0x4000;

  private static final byte SSH_AGENTC_REQUEST_RSA_IDENTITIES = 1;
  private static final byte SSH_AGENT_RSA_IDENTITIES_ANSWER = 2;
  private static final byte SSH_AGENTC_RSA_CHALLENGE = 3;
  private static final byte SSH_AGENT_RSA_RESPONSE = 4;
  private static final byte SSH_AGENT_FAILURE = 5;
  private static final byte SSH_AGENT_SUCCESS = 6;
  private static final byte SSH_AGENTC_ADD_RSA_IDENTITY = 7;
  private static final byte SSH_AGENTC_REMOVE_RSA_IDENTITY = 8;
  private static final byte SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES = 9;

  private static final byte SSH2_AGENTC_REQUEST_IDENTITIES = 11;
  private static final byte SSH2_AGENT_IDENTITIES_ANSWER = 12;
  private static final byte SSH2_AGENTC_SIGN_REQUEST = 13;
  private static final byte SSH2_AGENT_SIGN_RESPONSE = 14;
  private static final byte SSH2_AGENTC_ADD_IDENTITY = 17;
  private static final byte SSH2_AGENTC_REMOVE_IDENTITY = 18;
  private static final byte SSH2_AGENTC_REMOVE_ALL_IDENTITIES = 19;
  private static final byte SSH2_AGENT_FAILURE = 30;

  // static private final int SSH_AGENT_OLD_SIGNATURE=0x1;
  private static final int SSH_AGENT_RSA_SHA2_256 = 0x2;
  private static final int SSH_AGENT_RSA_SHA2_512 = 0x4;

  static final int RBUF_INITIAL_SIZE = 1024 * 10 * 2;
  static final int MAX_MESSAGE_LENGTH = 256 * 1024;
  static final int MAX_CHANNELS_PER_SESSION = 32;
  static final int MAX_QUEUED_MESSAGES = 1024;
  private static final int MAX_QUEUED_MESSAGE_LENGTH = MAX_MESSAGE_LENGTH;

  Buffer rbuf = null;
  private Buffer wbuf = null;
  private Packet packet = null;
  private Buffer mbuf = null;
  private final ArrayDeque<Buffer> requestQueue = new ArrayDeque<>();
  private int queuedMessageLength = 0;
  private boolean requestQueueClosed = false;

  ChannelAgentForwarding() {
    super();

    lwsize_max = LOCAL_WINDOW_SIZE_MAX;
    lwsize = LOCAL_WINDOW_SIZE_MAX;
    lmpsize = LOCAL_MAXIMUM_PACKET_SIZE;

    type = Util.str2byte("auth-agent@openssh.com");
    rbuf = new Buffer(RBUF_INITIAL_SIZE);
    rbuf.reset();
    // wbuf=new Buffer(rmpsize);
    // packet=new Packet(wbuf);
    mbuf = new Buffer();
    connected = true;
  }

  @Override
  void run() {
    thread = Thread.currentThread();
    Session session = null;
    try {
      session = getSession();
      sendOpenConfirmation();
      while (thread != null) {
        Buffer request = takeRequest();
        if (request == null) {
          break;
        }
        byte[] response;
        synchronized (session.getAgentForwardingLock()) {
          if (isClosed()) {
            break;
          }
          response = processMessage(request, session);
        }
        send(response);
      }
    } catch (Exception e) {
      // The channel is closed in the finally block.
    } finally {
      eof();
      disconnect();
      if (session != null) {
        session.agentForwardingWorkerFinished(this);
      }
    }
  }

  @Override
  void write(byte[] foo, int s, int l) throws IOException {
    while (l > 0) {
      if (rbuf.index < 4) {
        int chunk = Math.min(l, 4 - rbuf.index);
        appendToReadBuffer(foo, s, chunk);
        s += chunk;
        l -= chunk;
        if (rbuf.index < 4) {
          return;
        }
      }

      int mlen = getMessageLength();
      int chunk = Math.min(l, 4 + mlen - rbuf.index);
      appendToReadBuffer(foo, s, chunk);
      s += chunk;
      l -= chunk;
      if (rbuf.index < 4 + mlen) {
        return;
      }

      rbuf.getInt();
      Buffer request = new Buffer(mlen);
      request.putByte(rbuf.buffer, rbuf.s, mlen);
      resetReadBuffer();
      enqueueRequest(request);
    }
  }

  private void enqueueRequest(Buffer request) throws IOException {
    synchronized (requestQueue) {
      if (requestQueueClosed) {
        throw new IOException("Agent request queue is closed");
      }
      if (requestQueue.size() >= MAX_QUEUED_MESSAGES) {
        throw new IOException("Agent request queue exceeds " + MAX_QUEUED_MESSAGES + " messages");
      }
      int length = request.getLength();
      if (queuedMessageLength > MAX_QUEUED_MESSAGE_LENGTH - length) {
        throw new IOException(
            "Agent request queue exceeds " + MAX_QUEUED_MESSAGE_LENGTH + " bytes");
      }
      requestQueue.addLast(request);
      queuedMessageLength += length;
      requestQueue.notifyAll();
    }
  }

  private Buffer takeRequest() throws InterruptedException {
    synchronized (requestQueue) {
      while (requestQueue.isEmpty() && !requestQueueClosed) {
        requestQueue.wait();
      }
      if (requestQueue.isEmpty()) {
        return null;
      }
      Buffer request = requestQueue.removeFirst();
      queuedMessageLength -= request.getLength();
      return request;
    }
  }

  private int getMessageLength() throws IOException {
    rbuf.rewind();
    int length = rbuf.getInt();
    rbuf.rewind();
    if (length < 1 || length > MAX_MESSAGE_LENGTH) {
      resetReadBuffer();
      throw new IOException("Illegal agent message length: " + (length & 0xffffffffL));
    }
    return length;
  }

  private void appendToReadBuffer(byte[] data, int offset, int length) {
    int required = rbuf.index + length;
    if (rbuf.buffer.length < required) {
      int size = Math.min(rbuf.buffer.length * 2, 4 + MAX_MESSAGE_LENGTH);
      if (size < required) {
        size = required;
      }
      byte[] buffer = new byte[size];
      System.arraycopy(rbuf.buffer, 0, buffer, 0, rbuf.index);
      rbuf.buffer = buffer;
    }
    rbuf.putByte(data, offset, length);
  }

  private void resetReadBuffer() {
    rbuf.reset();
    if (rbuf.buffer.length > RBUF_INITIAL_SIZE) {
      rbuf.buffer = new byte[RBUF_INITIAL_SIZE];
    }
  }

  private byte[] processMessage(Buffer request, Session session) throws IOException {
    int typ = request.getByte();

    IdentityRepository irepo = session.getIdentityRepository();
    UserInfo userinfo = session.getUserInfo();

    mbuf.reset();

    if (typ == SSH2_AGENTC_REQUEST_IDENTITIES) {
      mbuf.putByte(SSH2_AGENT_IDENTITIES_ANSWER);
      Vector<Identity> identities = irepo.getIdentities();
      synchronized (identities) {
        int count = 0;
        for (int i = 0; i < identities.size(); i++) {
          Identity identity = identities.elementAt(i);
          if (identity.getPublicKeyBlob() != null)
            count++;
        }
        mbuf.putInt(count);
        for (int i = 0; i < identities.size(); i++) {
          Identity identity = identities.elementAt(i);
          byte[] pubkeyblob = identity.getPublicKeyBlob();
          if (pubkeyblob == null)
            continue;
          mbuf.putString(pubkeyblob);
          mbuf.putString(Util.empty);
        }
      }
    } else if (typ == SSH_AGENTC_REQUEST_RSA_IDENTITIES) {
      mbuf.putByte(SSH_AGENT_RSA_IDENTITIES_ANSWER);
      mbuf.putInt(0);
    } else if (typ == SSH2_AGENTC_SIGN_REQUEST) {
      byte[] blob = request.getString();
      byte[] data = request.getString();
      int flags = request.getInt();

      // if((flags & SSH_AGENT_OLD_SIGNATURE)!=0){ // old OpenSSH 2.0, 2.1
      // datafellows = SSH_BUG_SIGBLOB;
      // }

      Vector<Identity> identities = irepo.getIdentities();
      Identity identity = null;
      synchronized (identities) {
        for (int i = 0; i < identities.size(); i++) {
          Identity _identity = identities.elementAt(i);
          if (_identity.getPublicKeyBlob() == null)
            continue;
          if (!Util.array_equals(blob, _identity.getPublicKeyBlob())) {
            continue;
          }
          if (_identity.isEncrypted()) {
            if (userinfo == null)
              continue;
            while (_identity.isEncrypted()) {
              if (!userinfo.promptPassphrase("Passphrase for " + _identity.getName())) {
                break;
              }

              String _passphrase = userinfo.getPassphrase();
              if (_passphrase == null) {
                break;
              }

              byte[] passphrase = Util.str2byte(_passphrase);
              try {
                if (_identity.setPassphrase(passphrase)) {
                  break;
                }
              } catch (JSchException e) {
                break;
              }
            }
          }

          if (!_identity.isEncrypted()) {
            identity = _identity;
            break;
          }
        }
      }

      byte[] signature = null;

      if (identity != null) {
        Buffer kbuf = new Buffer(blob);
        String keytype = Util.byte2str(kbuf.getString());
        if (keytype.equals("ssh-rsa")) {
          if ((flags & SSH_AGENT_RSA_SHA2_256) != 0) {
            signature = identity.getSignature(data, "rsa-sha2-256");
          } else if ((flags & SSH_AGENT_RSA_SHA2_512) != 0) {
            signature = identity.getSignature(data, "rsa-sha2-512");
          } else {
            signature = identity.getSignature(data, "ssh-rsa");
          }
        } else {
          signature = identity.getSignature(data);
        }
      }

      if (signature == null) {
        mbuf.putByte(SSH2_AGENT_FAILURE);
      } else {
        mbuf.putByte(SSH2_AGENT_SIGN_RESPONSE);
        mbuf.putString(signature);
      }
    } else if (typ == SSH2_AGENTC_REMOVE_IDENTITY) {
      byte[] blob = request.getString();
      irepo.remove(blob);
      mbuf.putByte(SSH_AGENT_SUCCESS);
    } else if (typ == SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES) {
      mbuf.putByte(SSH_AGENT_SUCCESS);
    } else if (typ == SSH2_AGENTC_REMOVE_ALL_IDENTITIES) {
      irepo.removeAll();
      mbuf.putByte(SSH_AGENT_SUCCESS);
    } else if (typ == SSH2_AGENTC_ADD_IDENTITY) {
      byte[] identity = new byte[request.getLength()];
      request.getByte(identity);
      boolean result = irepo.add(identity);
      mbuf.putByte(result ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);
    } else {
      mbuf.putByte(SSH_AGENT_FAILURE);
    }

    byte[] response = new byte[mbuf.getLength()];
    mbuf.getByte(response);
    return response;
  }

  private void send(byte[] message) throws IOException {
    if (packet == null) {
      wbuf = new Buffer(rmpsize);
      packet = new Packet(wbuf);
    }
    packet.reset();
    wbuf.putByte((byte) Session.SSH_MSG_CHANNEL_DATA);
    wbuf.putInt(recipient);
    wbuf.putInt(4 + message.length);
    wbuf.putString(message);

    try {
      getSession().write(packet, this, 4 + message.length);
    } catch (Exception e) {
      throw new IOException(e.toString(), e);
    }
  }

  @Override
  void eof_remote() {
    super.eof_remote();
    synchronized (requestQueue) {
      requestQueueClosed = true;
      requestQueue.notifyAll();
    }
  }

  @Override
  public void disconnect() {
    synchronized (requestQueue) {
      requestQueueClosed = true;
      requestQueue.clear();
      queuedMessageLength = 0;
      requestQueue.notifyAll();
    }
    super.disconnect();
  }
}
