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

  /** Initial and idle capacity of {@link #rbuf}; the historical size of {@code new Buffer()}. */
  static final int RBUF_INITIAL_SIZE = 1024 * 10 * 2;

  /**
   * Default upper bound on the length of a single inbound agent message, in bytes.
   *
   * <p>
   * The requests this channel serves have a small natural ceiling: the largest is an
   * {@code SSH2_AGENTC_ADD_IDENTITY} carrying a private key, and even a 16384 bit RSA key is only
   * about 6 KiB of blob, while an {@code SSH2_AGENTC_SIGN_REQUEST} carrying a certificate and the
   * data to sign is smaller still. 256 KiB therefore leaves a very large margin, and it is the same
   * ceiling the established agent implementations apply: OpenSSH's ssh-agent
   * ({@code AGENT_MAX_LEN}), OpenSSH's client side ({@code MAX_AGENT_REPLY_LEN}) and PuTTY's
   * Pageant ({@code AGENT_MAX_MSGLEN}) all use 256 KiB. It also matches the longest string
   * {@link Buffer#getString()} will hand back, so a longer message could not be parsed intact here
   * in any case.
   *
   * <p>
   * A bound is needed because nothing else in the stack provides one: {@code Session#run} reopens
   * the local window as soon as it falls below half, so the peer decides how much it sends, and
   * before this bound existed {@link #write(byte[], int, int)} reassembled all of it before the
   * {@link IdentityRepository} was consulted at all.
   *
   * <p>
   * Override per session with
   * {@code session.setConfig("max_agent_forwarding_message_length", "...")}.
   */
  static final int MAX_MESSAGE_LENGTH = 256 * 1024;

  /** Config key overriding {@link #MAX_MESSAGE_LENGTH}. */
  static final String MAX_MESSAGE_LENGTH_KEY = "max_agent_forwarding_message_length";

  Buffer rbuf = null;
  private Buffer wbuf = null;
  private Packet packet = null;
  private Buffer mbuf = null;

  /** Resolved lazily from the session config; {@code 0} until then. */
  private int max_message_length = 0;

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
    try {
      sendOpenConfirmation();
    } catch (Exception e) {
      close = true;
      disconnect();
    }
  }

  @Override
  void write(byte[] foo, int s, int l) throws IOException {

    if (packet == null) {
      wbuf = new Buffer(rmpsize);
      packet = new Packet(wbuf);
    }

    Session _session = null;
    try {
      _session = getSession();
    } catch (JSchException e) {
      throw new IOException(e.toString(), e);
    }

    int maxlen = getMaxMessageLength(_session);

    // Refuse before buffering rather than after: the peer chooses how much it sends and the
    // local window is reopened for it, so this is the only place the reassembly is bounded.
    if (rbuf.getLength() + l > 4 + maxlen) {
      refuse(_session, "agent forwarding: " + (rbuf.getLength() + l)
          + " bytes buffered without a complete message, maximum is " + (4 + maxlen));
      return;
    }

    if (rbuf.buffer.length < rbuf.index + l) {
      int size = rbuf.buffer.length * 2;
      if (size < rbuf.index + l) {
        size = rbuf.index + l;
      }
      byte[] newbuf = new byte[size];
      System.arraycopy(rbuf.buffer, 0, newbuf, 0, rbuf.index);
      rbuf.buffer = newbuf;
    }

    rbuf.putByte(foo, s, l);

    if (rbuf.getLength() < 4) {
      // The length prefix itself has not arrived yet.
      return;
    }

    int mlen = rbuf.getInt();
    if (mlen < 1 || mlen > maxlen) {
      refuse(_session,
          "agent forwarding: message length " + (mlen & 0xffffffffL) + " is outside 1.." + maxlen);
      return;
    }
    if (mlen > rbuf.getLength()) {
      rbuf.s -= 4;
      return;
    }

    int typ = rbuf.getByte();

    IdentityRepository irepo = _session.getIdentityRepository();
    UserInfo userinfo = _session.getUserInfo();

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
      byte[] blob = rbuf.getString();
      byte[] data = rbuf.getString();
      int flags = rbuf.getInt();

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
      byte[] blob = rbuf.getString();
      irepo.remove(blob);
      mbuf.putByte(SSH_AGENT_SUCCESS);
    } else if (typ == SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES) {
      mbuf.putByte(SSH_AGENT_SUCCESS);
    } else if (typ == SSH2_AGENTC_REMOVE_ALL_IDENTITIES) {
      irepo.removeAll();
      mbuf.putByte(SSH_AGENT_SUCCESS);
    } else if (typ == SSH2_AGENTC_ADD_IDENTITY) {
      int fooo = rbuf.getLength();
      byte[] tmp = new byte[fooo];
      rbuf.getByte(tmp);
      boolean result = irepo.add(tmp);
      mbuf.putByte(result ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);
    } else {
      rbuf.s += rbuf.getLength();
      mbuf.putByte(SSH_AGENT_FAILURE);
    }

    byte[] response = new byte[mbuf.getLength()];
    mbuf.getByte(response);
    send(response);

    compact();
  }

  /**
   * Drops the bytes already dispatched and gives back an oversized backing array, so that a
   * long-lived channel does not hold on to its high-water mark for the rest of the session.
   */
  private void compact() {
    rbuf.shift();
    if (rbuf.buffer.length > RBUF_INITIAL_SIZE && rbuf.index <= RBUF_INITIAL_SIZE) {
      byte[] newbuf = new byte[RBUF_INITIAL_SIZE];
      System.arraycopy(rbuf.buffer, 0, newbuf, 0, rbuf.index);
      rbuf.buffer = newbuf;
    }
  }

  /**
   * Answers a request that cannot be reassembled with the agent protocol's failure response, and
   * then closes the channel.
   *
   * <p>
   * A length prefix that is bogus or too large desynchronises the stream, so there is nothing left
   * to resynchronise on; OpenSSH's ssh-agent closes the connection in the same situation. The
   * failure response is still sent first, best effort, so a peer waiting for a reply is not left
   * hanging. Nothing is thrown: this runs on the session's read loop.
   */
  private void refuse(Session session, String reason) {
    if (session.getLogger().isEnabled(Logger.WARN)) {
      session.getLogger().log(Logger.WARN, reason + ", closing the channel");
    }

    mbuf.reset();
    mbuf.putByte(SSH_AGENT_FAILURE);
    byte[] response = new byte[mbuf.getLength()];
    mbuf.getByte(response);
    send(response);

    rbuf.reset();
    rbuf.buffer = new byte[RBUF_INITIAL_SIZE];

    close = true;
    disconnect();
  }

  private int getMaxMessageLength(Session session) {
    int maxlen = max_message_length;
    if (maxlen != 0) {
      return maxlen;
    }

    maxlen = MAX_MESSAGE_LENGTH;
    try {
      String value = session.getConfig(MAX_MESSAGE_LENGTH_KEY);
      if (value != null) {
        int configured = Integer.parseInt(value);
        if (configured > 0) {
          maxlen = configured;
        }
      }
    } catch (NumberFormatException e) {
      // keep the default
    }

    max_message_length = maxlen;
    return maxlen;
  }

  private void send(byte[] message) {
    packet.reset();
    wbuf.putByte((byte) Session.SSH_MSG_CHANNEL_DATA);
    wbuf.putInt(recipient);
    wbuf.putInt(4 + message.length);
    wbuf.putString(message);

    try {
      getSession().write(packet, this, 4 + message.length);
    } catch (Exception e) {
    }
  }

  @Override
  void eof_remote() {
    super.eof_remote();
    eof();
  }
}
