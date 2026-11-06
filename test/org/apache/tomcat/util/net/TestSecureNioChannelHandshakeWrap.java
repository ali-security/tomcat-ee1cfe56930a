/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tomcat.util.net;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;

import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

/**
 * White-box regression test for CVE-2024-38286. A malicious TLS peer can drive
 * the server's {@link SSLEngine} into a state where {@code unwrap()} repeatedly
 * reports {@link HandshakeStatus#NEED_WRAP} while there is still un-flushed
 * outbound handshake data, causing unbounded buffering of handshake wrap data.
 * The fix throttles this: {@link SecureNioChannel} refuses to buffer a second
 * pending handshake wrap and {@link SecureNio2Channel} caps the number of
 * queued handshake wraps.
 *
 * The SSL/APR integration tests (TestSsl, TestClientCert, ...) are excluded in
 * the Docker build (they need keystores/native libs), and upstream shipped no
 * test for this CVE, so these focused white-box tests provide the regression
 * coverage.
 */
public class TestSecureNioChannelHandshakeWrap {

    private ServerSocketChannel server;
    private SocketChannel client;
    private SocketChannel accepted;

    @After
    public void tearDown() {
        close(client);
        close(accepted);
        close(server);
    }

    private static void close(java.io.Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (IOException ignore) {
                // ignore
            }
        }
    }

    /**
     * The blocking read side of a loopback pair, primed with some bytes so that
     * {@code sc.read(netInBuffer)} in {@link SecureNioChannel#read(ByteBuffer)}
     * returns a positive value and the unwrap loop is entered.
     */
    private SocketChannel loopbackWithData() throws IOException {
        server = ServerSocketChannel.open();
        server.socket().bind(new InetSocketAddress(InetAddress.getByName("localhost"), 0));
        client = SocketChannel.open(new InetSocketAddress(InetAddress.getByName("localhost"),
                server.socket().getLocalPort()));
        accepted = server.accept();
        accepted.configureBlocking(true);
        // Feed some (encrypted-looking) bytes so the read side has data.
        client.write(ByteBuffer.wrap(new byte[] {1, 2, 3, 4, 5, 6, 7, 8}));
        return accepted;
    }

    /**
     * A minimal SSLEngine whose unwrap() always consumes the network input and
     * reports NEED_WRAP with an OK status — the loop condition CVE-2024-38286
     * exploits.
     */
    private static SSLEngine needWrapEngine() {
        return new NeedWrapSSLEngine();
    }

    private static SecureNioChannel newChannel() {
        SocketBufferHandler bufHandler = new SocketBufferHandler(8192, 8192, false);
        NioEndpoint endpoint = new NioEndpoint();
        return new SecureNioChannel(bufHandler, new NioSelectorPool(), endpoint);
    }

    private static void setProtected(Object target, Class<?> declaring, String name, Object value)
            throws Exception {
        Field f = declaring.getDeclaredField(name);
        f.setAccessible(true);
        f.set(target, value);
    }

    // ---- SecureNioChannel (blocking NIO) ------------------------------------

    /**
     * When a second consecutive NEED_WRAP is reported while outbound data is
     * still pending, {@link SecureNioChannel#read(ByteBuffer)} must fail fast
     * rather than buffer more handshake wrap data.
     */
    @Test
    public void testNioReadRejectsPendingHandshakeWrap() throws Exception {
        SecureNioChannel channel = new SecureNioChannel(
                new SocketBufferHandler(8192, 8192, false), new NioSelectorPool(), new NioEndpoint()) {
            @Override
            public int getOutboundRemaining() {
                // Pretend there is always un-flushed outbound handshake data so
                // the NEED_WRAP branch takes the "pending" path instead of
                // performing another handshakeWrap().
                return 1;
            }
        };
        SocketChannel sc = loopbackWithData();
        setProtected(channel, NioChannel.class, "sc", sc);
        setProtected(channel, SecureNioChannel.class, "sslEngine", needWrapEngine());
        setProtected(channel, SecureNioChannel.class, "handshakeComplete", Boolean.TRUE);

        ByteBuffer dst = ByteBuffer.allocate(8192);
        // First read: a single NEED_WRAP with outbound pending sets the flag.
        channel.read(dst);
        // Prime more data so the second read enters the unwrap loop again.
        client.write(ByteBuffer.wrap(new byte[] {9, 10, 11, 12}));
        // Second read: NEED_WRAP is reported again while a wrap is still
        // pending, so the throttle must fail fast rather than keep buffering.
        try {
            channel.read(dst);
            Assert.fail("Expected IOException for pending handshake wrap");
        } catch (IOException e) {
            Assert.assertTrue("Unexpected message: " + e.getMessage(),
                    e.getMessage() != null && e.getMessage().contains("handshake"));
        }
    }

    /**
     * The pending flag must be cleared by a successful wrap so that a single
     * NEED_WRAP does not, on its own, trip the guard.
     */
    @Test
    public void testNioSingleNeedWrapDoesNotThrow() throws Exception {
        SecureNioChannel channel = new SecureNioChannel(
                new SocketBufferHandler(8192, 8192, false), new NioSelectorPool(), new NioEndpoint()) {
            private int calls = 0;

            @Override
            public int getOutboundRemaining() {
                return 1;
            }

            @Override
            public int read(ByteBuffer dst) throws IOException {
                calls++;
                return super.read(dst);
            }
        };
        setProtected(channel, NioChannel.class, "sc", loopbackWithData());
        // Engine reports NEED_WRAP once then OK/FINISHED afterwards.
        setProtected(channel, SecureNioChannel.class, "sslEngine", new NeedWrapSSLEngine(1));
        setProtected(channel, SecureNioChannel.class, "handshakeComplete", Boolean.TRUE);

        ByteBuffer dst = ByteBuffer.allocate(8192);
        // First NEED_WRAP should set the pending flag but not throw.
        channel.read(dst);
    }

    // ---- SecureNio2Channel (async NIO2) constants ---------------------------

    /**
     * The wrap-queue limit must exist and be a sane, bounded value.
     */
    @Test
    public void testNio2HasBoundedWrapQueueLimit() throws Exception {
        Field limit = SecureNio2Channel.class.getDeclaredField("HANDSHAKE_WRAP_QUEUE_LENGTH_LIMIT");
        limit.setAccessible(true);
        Assert.assertTrue(Modifier.isStatic(limit.getModifiers()));
        int value = limit.getInt(null);
        Assert.assertTrue("Limit must be positive", value > 0);
        Assert.assertTrue("Limit must be bounded", value <= 1000);

        Field counter = SecureNio2Channel.class.getDeclaredField("handshakeWrapQueueLength");
        Assert.assertEquals(int.class, counter.getType());
        Assert.assertTrue("Counter must be volatile", Modifier.isVolatile(counter.getModifiers()));
    }

    /**
     * {@link SecureNioChannel} must carry the pending-wrap guard field.
     */
    @Test
    public void testNioHasPendingWrapField() throws Exception {
        Field f = SecureNioChannel.class.getDeclaredField("needHandshakeWrap");
        Assert.assertEquals(boolean.class, f.getType());
    }

    /**
     * The new resource strings for the throttle must resolve.
     */
    @Test
    public void testMessagesResolve() {
        org.apache.tomcat.util.res.StringManager sm =
                org.apache.tomcat.util.res.StringManager.getManager(
                        SecureNioChannel.class.getPackage().getName());
        Assert.assertNotNull(sm.getString("channel.nio.ssl.handshakeWrapPending"));
        Assert.assertNotNull(sm.getString("channel.nio.ssl.handshakeWrapQueueTooLong"));
        Assert.assertFalse(sm.getString("channel.nio.ssl.handshakeWrapPending").isEmpty());
        Assert.assertFalse(sm.getString("channel.nio.ssl.handshakeWrapQueueTooLong").isEmpty());
    }

    /**
     * Sanity check that the loopback harness works so a real read is exercised.
     */
    @Test
    public void testHarnessProducesData() throws Exception {
        SocketChannel sc = loopbackWithData();
        ByteBuffer b = ByteBuffer.allocate(16);
        int n = sc.read(b);
        Assert.assertTrue(n > 0);
    }

    /**
     * An SSLEngine stub whose unwrap() drains the source buffer and reports
     * NEED_WRAP for the first {@code needWrapCount} calls (default: always).
     */
    private static class NeedWrapSSLEngine extends SSLEngine {

        private final int needWrapCount;
        private int calls = 0;

        NeedWrapSSLEngine() {
            this(Integer.MAX_VALUE);
        }

        NeedWrapSSLEngine(int needWrapCount) {
            this.needWrapCount = needWrapCount;
        }

        @Override
        public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length) {
            // Consume all available network input so the do/while loop keeps
            // iterating without a BUFFER_UNDERFLOW break on the first pass.
            int consumed = src.remaining();
            src.position(src.limit());
            HandshakeStatus hs = (++calls <= needWrapCount)
                    ? HandshakeStatus.NEED_WRAP
                    : HandshakeStatus.FINISHED;
            return new SSLEngineResult(Status.OK, hs, consumed, 0);
        }

        @Override
        public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) {
            return new SSLEngineResult(Status.OK, HandshakeStatus.NOT_HANDSHAKING, 0, 0);
        }

        @Override
        public javax.net.ssl.SSLSession getSession() {
            return null;
        }

        // ---- unused abstract methods ----
        @Override
        public void beginHandshake() {
        }

        @Override
        public void closeInbound() {
        }

        @Override
        public boolean isInboundDone() {
            return false;
        }

        @Override
        public void closeOutbound() {
        }

        @Override
        public boolean isOutboundDone() {
            return false;
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return new String[0];
        }

        @Override
        public String[] getEnabledCipherSuites() {
            return new String[0];
        }

        @Override
        public void setEnabledCipherSuites(String[] suites) {
        }

        @Override
        public String[] getSupportedProtocols() {
            return new String[0];
        }

        @Override
        public String[] getEnabledProtocols() {
            return new String[0];
        }

        @Override
        public void setEnabledProtocols(String[] protocols) {
        }

        @Override
        public Runnable getDelegatedTask() {
            return null;
        }

        @Override
        public HandshakeStatus getHandshakeStatus() {
            return HandshakeStatus.NEED_WRAP;
        }

        @Override
        public void setUseClientMode(boolean mode) {
        }

        @Override
        public boolean getUseClientMode() {
            return false;
        }

        @Override
        public void setNeedClientAuth(boolean need) {
        }

        @Override
        public boolean getNeedClientAuth() {
            return false;
        }

        @Override
        public void setWantClientAuth(boolean want) {
        }

        @Override
        public boolean getWantClientAuth() {
            return false;
        }

        @Override
        public void setEnableSessionCreation(boolean flag) {
        }

        @Override
        public boolean getEnableSessionCreation() {
            return false;
        }
    }
}
