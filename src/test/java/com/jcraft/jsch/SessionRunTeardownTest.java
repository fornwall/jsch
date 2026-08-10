package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.lang.reflect.Field;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Session.run() is the session's only read loop, and the teardown that follows it is the only thing
 * that closes the transport once that loop ends. These tests inject a failure into the loop and
 * check that the teardown -- disconnect() plus clearing isConnected -- runs exactly once on each
 * way out, including the one where an Error is on its way up the stack.
 */
class SessionRunTeardownTest {

  /** A session whose read loop fails immediately with a Throwable chosen per instance. */
  private static class FailingSession extends Session {
    private final Throwable failure;
    int disconnectCount;

    FailingSession(Throwable failure) throws JSchException {
      super(new JSch(), null, null, 0);
      this.failure = failure;
    }

    @Override
    Buffer read(Buffer buf) throws Exception {
      if (failure instanceof Error) {
        throw (Error) failure;
      }
      throw (Exception) failure;
    }

    @Override
    public void disconnect() {
      disconnectCount++;
      super.disconnect();
    }
  }

  /** Puts the session into the state run()'s loop condition requires, without a real connection. */
  private static void markConnected(Session session) throws Exception {
    Field isConnected = Session.class.getDeclaredField("isConnected");
    isConnected.setAccessible(true);
    isConnected.setBoolean(session, true);
  }

  @Test
  @DisplayName("an Error out of the read loop still tears the session down, and still propagates")
  void errorFromReadLoop() throws Exception {
    FailingSession session = new FailingSession(new OutOfMemoryError("injected"));
    markConnected(session);

    OutOfMemoryError thrown = assertThrows(OutOfMemoryError.class, session::run);

    assertEquals("injected", thrown.getMessage(), "the Error must reach the caller unchanged");
    assertEquals(1, session.disconnectCount, "disconnect() must run exactly once");
    assertFalse(session.isConnected(), "a session with no read loop must not report itself alive");
  }

  @Test
  @DisplayName("an Exception out of the read loop is still swallowed, and still tears down")
  void exceptionFromReadLoop() throws Exception {
    FailingSession session = new FailingSession(new IOException("injected"));
    markConnected(session);

    session.run();

    assertEquals(1, session.disconnectCount, "disconnect() must run exactly once");
    assertFalse(session.isConnected());
  }

  @Test
  @DisplayName("a loop that is never entered tears down exactly once, as before")
  void loopNeverEntered() throws Exception {
    FailingSession session = new FailingSession(new IOException("never thrown"));

    session.run();

    assertEquals(1, session.disconnectCount, "disconnect() must run exactly once");
    assertFalse(session.isConnected());
  }
}
