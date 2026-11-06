/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.coyote;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.CompletionHandler;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpUpgradeHandler;
import javax.servlet.http.WebConnection;

import org.junit.Assert;
import org.junit.Test;

import org.apache.coyote.http11.upgrade.InternalHttpUpgradeHandler;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.net.AbstractEndpoint.Handler.SocketState;
import org.apache.tomcat.util.net.ApplicationBufferHandler;
import org.apache.tomcat.util.net.NioChannel;
import org.apache.tomcat.util.net.NioEndpoint;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLSupport;
import org.apache.tomcat.util.net.SendfileDataBase;
import org.apache.tomcat.util.net.SendfileState;
import org.apache.tomcat.util.net.SocketBufferHandler;
import org.apache.tomcat.util.net.SocketEvent;
import org.apache.tomcat.util.net.SocketWrapperBase;

/**
 * Tests for {@link AbstractProtocol.ConnectionHandler}.
 * <p>
 * The tests in this class target CVE-2021-25122 (h2c request mix-up). When an
 * HTTP/1.1 connection is upgraded, any bytes the client has already pipelined
 * behind the upgrade request have to be handed over to the new protocol. Those
 * leftover bytes are exposed by {@link Processor#getLeftoverInput()} which, for
 * {@code Http11Processor}, returns a {@link ByteBuffer} that <em>wraps</em> (it
 * does not copy) the {@code Http11InputBuffer}'s internal {@code byte[]}.
 * <p>
 * {@code SocketWrapperBase.unRead()} is what copies those bytes out of that
 * shared array and into the connection's own read buffer. If the
 * {@code Http11Processor} is released back into the (connection handler wide)
 * pool of recycled processors <em>before</em> that copy is taken, another
 * connection's thread can take the very same processor out of the pool and
 * parse an unrelated request into the same array. The pending copy then hands
 * that other request's bytes to this connection - which is exactly the request
 * mix-up reported as CVE-2021-25122.
 * <p>
 * The tests that follow those target CVE-2021-43980 (a processor is recycled
 * while it is still being used). The connection handler has to take complete
 * ownership of the processor while it is processing so that a concurrent
 * {@link AbstractProtocol.ConnectionHandler#release(SocketWrapperBase)} - the
 * endpoint closing the connection from another thread - cannot recycle it.
 */
public class TestAbstractProtocol {

    /**
     * The bytes this client pipelined behind its upgrade request. These are the
     * bytes that must survive the upgrade.
     */
    private static final byte[] PIPELINED_BY_THIS_CLIENT =
            "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);

    /**
     * The bytes another connection parses into the recycled processor's input
     * buffer while it sits in the shared pool. Deliberately the same length as
     * {@link #PIPELINED_BY_THIS_CLIENT} so that it completely overwrites the
     * region the leftover {@link ByteBuffer} points at.
     */
    private static final byte[] PARSED_BY_ANOTHER_CONNECTION =
            "GET /victim HTTP/1.1\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);

    /**
     * Offset of the leftover bytes within the processor's input buffer. Non-zero
     * because {@code Http11InputBuffer.getLeftover()} wraps the array from the
     * buffer's current position, which is past the request that was just read.
     */
    private static final int LEFTOVER_OFFSET = 8;


    /**
     * Direct HTTP/2 connection ({@code upgradeToken == null}): the leftover
     * input must be copied out of the HTTP/1.1 processor before that processor
     * is released into the shared pool.
     */
    @Test
    public void testLeftoverInputNotMixedUpOnDirectHttp2Upgrade() throws Exception {
        doTestLeftoverInputNotMixedUp(false);
    }


    /**
     * HTTP upgrade token present ({@code upgradeToken != null}, e.g. an
     * {@code Upgrade: h2c} request or a Servlet API upgrade): the leftover input
     * must be copied out of the HTTP/1.1 processor before that processor is
     * released into the shared pool.
     */
    @Test
    public void testLeftoverInputNotMixedUpOnTokenUpgrade() throws Exception {
        doTestLeftoverInputNotMixedUp(true);
    }


    private void doTestLeftoverInputNotMixedUp(boolean useUpgradeToken) throws Exception {
        // Both payloads must be the same length for the overwrite performed by
        // the 'other connection' to fully cover the leftover bytes.
        Assert.assertEquals("Test payloads must be the same length",
                PIPELINED_BY_THIS_CLIENT.length, PARSED_BY_ANOTHER_CONNECTION.length);

        TesterProtocol protocol = new TesterProtocol(useUpgradeToken);
        AbstractProtocol.ConnectionHandler<NioChannel> handler =
                new AbstractProtocol.ConnectionHandler<>(protocol);

        // The connection that is being upgraded.
        TesterSocketWrapper wrapper = new TesterSocketWrapper(protocol.getTesterEndpoint());
        // A second, unrelated connection that will be served by the recycled
        // HTTP/1.1 processor once it has been returned to the shared pool.
        TesterSocketWrapper otherWrapper = new TesterSocketWrapper(protocol.getTesterEndpoint());

        TesterHttp11Processor http11Processor = new TesterHttp11Processor(useUpgradeToken);
        wrapper.setCurrentProcessor(http11Processor);

        // Once the HTTP/1.1 processor has been released, hand it to the second
        // connection via the handler (i.e. out of the shared pool of recycled
        // processors) and let that connection parse a request into it. In the
        // real server this happens on another thread; here it is driven from the
        // factory method the connection handler calls between release() and the
        // (pre-fix) unRead(), so the race is reproduced deterministically.
        protocol.setConcurrentConnection(handler, otherWrapper);

        SocketState state = handler.process(wrapper, SocketEvent.OPEN_READ);

        Assert.assertEquals(SocketState.UPGRADED, state);

        // The exploit primitive: the released HTTP/1.1 processor really is
        // handed out again from the shared pool, so its input buffer is not
        // this connection's to rely on any more.
        Assert.assertSame("The released HTTP/1.1 processor should have been taken" +
                " from the shared pool to serve the second connection",
                otherWrapper, http11Processor.getLastWrapper());
        Assert.assertArrayEquals("The second connection should have overwritten the" +
                " recycled processor's input buffer",
                PARSED_BY_ANOTHER_CONNECTION, http11Processor.getLeftoverRegion());

        // The upgraded connection must see the bytes *this* client pipelined,
        // not the request the other connection parsed into the recycled buffer.
        Assert.assertArrayEquals("Leftover input was read out of the HTTP/1.1" +
                " processor after it had been released to the shared pool, so this" +
                " connection was handed another connection's request bytes" +
                " (CVE-2021-25122)",
                PIPELINED_BY_THIS_CLIENT, readAllBufferedInput(wrapper));
    }


    /**
     * {@link SocketWrapperBase#takeCurrentProcessor()} returns the current
     * processor and clears it.
     */
    @Test
    public void testTakeCurrentProcessor() throws Exception {
        TesterSocketWrapper wrapper = new TesterSocketWrapper(new NioEndpoint());
        Object processor = new Object();

        Assert.assertNull(wrapper.takeCurrentProcessor());

        wrapper.setCurrentProcessor(processor);
        Assert.assertSame(processor, wrapper.getCurrentProcessor());
        Assert.assertSame(processor, wrapper.takeCurrentProcessor());
        Assert.assertNull(wrapper.getCurrentProcessor());
        Assert.assertNull(wrapper.takeCurrentProcessor());
    }


    /**
     * Only one of several threads racing to take the current processor may
     * obtain it. This is what stops two threads recycling the same processor.
     */
    @Test
    public void testTakeCurrentProcessorIsAtomic() throws Exception {
        int threadCount = 8;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        try {
            for (int round = 0; round < 50; round++) {
                TesterSocketWrapper wrapper = new TesterSocketWrapper(new NioEndpoint());
                Object processor = new Object();
                wrapper.setCurrentProcessor(processor);

                CyclicBarrier barrier = new CyclicBarrier(threadCount);
                List<Future<Object>> results = new ArrayList<>();
                for (int i = 0; i < threadCount; i++) {
                    results.add(executor.submit(() -> {
                        barrier.await(10, TimeUnit.SECONDS);
                        return wrapper.takeCurrentProcessor();
                    }));
                }
                int taken = 0;
                for (Future<Object> result : results) {
                    Object value = result.get(10, TimeUnit.SECONDS);
                    if (value != null) {
                        Assert.assertSame(processor, value);
                        taken++;
                    }
                }
                Assert.assertEquals("The processor must be taken by exactly one thread", 1, taken);
                Assert.assertNull(wrapper.getCurrentProcessor());
            }
        } finally {
            executor.shutdownNow();
        }
    }


    /**
     * While the handler is processing an event the processor belongs to the
     * handler: it is not associated with the wrapper. Afterwards it is either
     * associated with the wrapper again (the connection continues to need it)
     * or it has been released exactly once.
     */
    @Test
    public void testProcessorOwnershipDuringAndAfterProcessing() throws Exception {
        // LONG: processor stays associated with the wrapper
        TesterRecyclableProcessor longProcessor = new TesterRecyclableProcessor(SocketState.LONG);
        TesterSocketWrapper wrapper = doProcess(longProcessor);
        Assert.assertNull("The wrapper must not be associated with the processor while it is processing",
                longProcessor.getCurrentProcessorSeenWhileProcessing());
        Assert.assertSame(longProcessor, wrapper.getCurrentProcessor());
        Assert.assertEquals(0, longProcessor.getRecycleCount());

        // OPEN: processor released and no longer associated with the wrapper
        TesterRecyclableProcessor openProcessor = new TesterRecyclableProcessor(SocketState.OPEN);
        wrapper = doProcess(openProcessor);
        Assert.assertNull(openProcessor.getCurrentProcessorSeenWhileProcessing());
        Assert.assertNull(wrapper.getCurrentProcessor());
        Assert.assertEquals(1, openProcessor.getRecycleCount());

        // CLOSED: processor released and no longer associated with the wrapper
        TesterRecyclableProcessor closedProcessor = new TesterRecyclableProcessor(SocketState.CLOSED);
        wrapper = doProcess(closedProcessor);
        Assert.assertNull(closedProcessor.getCurrentProcessorSeenWhileProcessing());
        Assert.assertNull(wrapper.getCurrentProcessor());
        Assert.assertEquals(1, closedProcessor.getRecycleCount());
    }


    private static TesterSocketWrapper doProcess(TesterRecyclableProcessor processor)
            throws Exception {
        TesterProtocol protocol = new TesterProtocol(false);
        AbstractProtocol.ConnectionHandler<NioChannel> handler =
                new AbstractProtocol.ConnectionHandler<>(protocol);
        Deque<Processor> processors = new ArrayDeque<>();
        processors.add(processor);
        protocol.setProcessorFactory(processors::remove);

        TesterSocketWrapper wrapper = new TesterSocketWrapper(protocol.getTesterEndpoint());
        Assert.assertEquals(processor.getResult(), handler.process(wrapper, SocketEvent.OPEN_READ));
        return wrapper;
    }


    /**
     * The endpoint releasing a connection (e.g. because it was closed by the
     * client) from another thread while the connection is being processed must
     * not recycle the processor that is in use. If it did, the processor could
     * be handed to a second connection while the first is still using it, with
     * responses (or part responses) going to the wrong client (CVE-2021-43980).
     */
    @Test
    public void testConcurrentReleaseDoesNotRecycleProcessorInUse() throws Exception {
        TesterProtocol protocol = new TesterProtocol(false);
        AbstractProtocol.ConnectionHandler<NioChannel> handler =
                new AbstractProtocol.ConnectionHandler<>(protocol);

        TesterSocketWrapper wrapper = new TesterSocketWrapper(protocol.getTesterEndpoint());
        TesterSocketWrapper otherWrapper = new TesterSocketWrapper(protocol.getTesterEndpoint());

        TesterRecyclableProcessor inUse = new TesterRecyclableProcessor(SocketState.LONG);
        TesterRecyclableProcessor spare = new TesterRecyclableProcessor(SocketState.LONG);
        Deque<Processor> processors = new ArrayDeque<>();
        processors.add(inUse);
        processors.add(spare);
        protocol.setProcessorFactory(processors::remove);

        // While 'inUse' is processing, another thread (e.g. the poller handling
        // a closed connection) releases the wrapper.
        inUse.setWhileProcessing(() -> {
            Thread other = new Thread(() -> handler.release(wrapper));
            other.start();
            try {
                other.join(10000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            inUse.recycleCountAfterConcurrentRelease = inUse.getRecycleCount();
        });

        Assert.assertEquals(SocketState.LONG, handler.process(wrapper, SocketEvent.OPEN_READ));

        Assert.assertEquals("The processor was recycled while it was still in use",
                0, inUse.recycleCountAfterConcurrentRelease);
        Assert.assertEquals(0, inUse.getRecycleCount());
        Assert.assertSame(inUse, wrapper.getCurrentProcessor());

        // A second connection must not be given the processor that is in use
        Assert.assertEquals(SocketState.LONG, handler.process(otherWrapper, SocketEvent.OPEN_READ));
        Assert.assertEquals(1, inUse.getProcessCount());
        Assert.assertSame(wrapper, inUse.getLastWrapper());
        Assert.assertEquals(1, spare.getProcessCount());
        Assert.assertSame(otherWrapper, spare.getLastWrapper());
    }


    /**
     * Releasing a connection recycles the processor associated with it exactly
     * once however many times the endpoint calls release.
     */
    @Test
    public void testReleaseWrapperRecyclesProcessorOnce() throws Exception {
        TesterProtocol protocol = new TesterProtocol(false);
        AbstractProtocol.ConnectionHandler<NioChannel> handler =
                new AbstractProtocol.ConnectionHandler<>(protocol);
        TesterSocketWrapper wrapper = new TesterSocketWrapper(protocol.getTesterEndpoint());

        TesterRecyclableProcessor processor = new TesterRecyclableProcessor(SocketState.LONG);
        wrapper.setCurrentProcessor(processor);

        handler.release(wrapper);
        handler.release(wrapper);

        Assert.assertEquals(1, processor.getRecycleCount());
        Assert.assertNull(wrapper.getCurrentProcessor());
    }


    /**
     * A timeout event that turns out not to be required is a NO-OP. It must
     * leave the processor associated with the connection so that the next
     * event for the connection is processed by the same processor.
     */
    @Test
    public void testNoOpTimeoutKeepsProcessorAssociatedWithWrapper() throws Exception {
        TesterProtocol protocol = new TesterProtocol(false);
        AbstractProtocol.ConnectionHandler<NioChannel> handler =
                new AbstractProtocol.ConnectionHandler<>(protocol);
        TesterSocketWrapper wrapper = new TesterSocketWrapper(protocol.getTesterEndpoint());

        // Neither async nor an upgrade so a timeout is not required
        TesterRecyclableProcessor processor = new TesterRecyclableProcessor(SocketState.LONG);
        wrapper.setCurrentProcessor(processor);

        Assert.assertEquals(SocketState.OPEN, handler.process(wrapper, SocketEvent.TIMEOUT));

        Assert.assertEquals(0, processor.getProcessCount());
        Assert.assertEquals(0, processor.getRecycleCount());
        Assert.assertSame(processor, wrapper.getCurrentProcessor());
    }


    /**
     * Direct HTTP/2 connection ({@code upgradeToken == null}) when no h2c
     * upgrade protocol is available: the connection is closed and the HTTP/1.1
     * processor, which the handler owns, must be released (recycled) rather
     * than being dropped.
     */
    @Test
    public void testDirectHttp2WithoutH2cReleasesProcessor() throws Exception {
        TesterProtocol protocol = new TesterProtocol(false);
        protocol.setH2cAvailable(false);
        AbstractProtocol.ConnectionHandler<NioChannel> handler =
                new AbstractProtocol.ConnectionHandler<>(protocol);
        TesterSocketWrapper wrapper = new TesterSocketWrapper(protocol.getTesterEndpoint());
        TesterSocketWrapper otherWrapper = new TesterSocketWrapper(protocol.getTesterEndpoint());

        TesterRecyclableProcessor processor = new TesterRecyclableProcessor(SocketState.UPGRADING);
        processor.setResultForSubsequentCalls(SocketState.CLOSED);
        Deque<Processor> processors = new ArrayDeque<>();
        processors.add(processor);
        protocol.setProcessorFactory(processors::remove);

        Assert.assertEquals(SocketState.CLOSED, handler.process(wrapper, SocketEvent.OPEN_READ));

        Assert.assertEquals("The HTTP/1.1 processor was not released", 1, processor.getRecycleCount());
        Assert.assertNull(wrapper.getCurrentProcessor());

        // The released processor is available to serve another connection (no
        // new processor is created: the factory is empty)
        Assert.assertEquals(SocketState.CLOSED, handler.process(otherWrapper, SocketEvent.OPEN_READ));
        Assert.assertSame(otherWrapper, processor.getLastWrapper());
        Assert.assertEquals(2, processor.getRecycleCount());
    }


    /**
     * An HTTP/1.1 processor that reports what it sees of its wrapper while it
     * is processing and counts how often it is recycled.
     */
    private static class TesterRecyclableProcessor implements Processor {

        private final SocketState result;
        private SocketState resultForSubsequentCalls;
        private Runnable whileProcessing = null;
        private int processCount = 0;
        private int recycleCount = 0;
        private SocketWrapperBase<?> lastWrapper = null;
        private Object currentProcessorSeenWhileProcessing = null;
        volatile int recycleCountAfterConcurrentRelease = -1;

        TesterRecyclableProcessor(SocketState result) {
            this.result = result;
            this.resultForSubsequentCalls = result;
        }

        SocketState getResult() {
            return result;
        }

        void setResultForSubsequentCalls(SocketState resultForSubsequentCalls) {
            this.resultForSubsequentCalls = resultForSubsequentCalls;
        }

        void setWhileProcessing(Runnable whileProcessing) {
            this.whileProcessing = whileProcessing;
        }

        int getProcessCount() {
            return processCount;
        }

        int getRecycleCount() {
            return recycleCount;
        }

        SocketWrapperBase<?> getLastWrapper() {
            return lastWrapper;
        }

        Object getCurrentProcessorSeenWhileProcessing() {
            return currentProcessorSeenWhileProcessing;
        }

        @Override
        public SocketState process(SocketWrapperBase<?> socketWrapper, SocketEvent status) {
            processCount++;
            lastWrapper = socketWrapper;
            currentProcessorSeenWhileProcessing = socketWrapper.getCurrentProcessor();
            if (whileProcessing != null) {
                whileProcessing.run();
            }
            return processCount == 1 ? result : resultForSubsequentCalls;
        }

        @Override
        public UpgradeToken getUpgradeToken() {
            // Direct HTTP/2 connection
            return null;
        }

        @Override
        public ByteBuffer getLeftoverInput() {
            return ByteBuffer.allocate(0);
        }

        @Override
        public void recycle() {
            recycleCount++;
        }

        @Override
        public boolean isUpgrade() {
            // Must be false so that release() returns this processor to the
            // pool of recycled processors, as it does for Http11Processor.
            return false;
        }

        @Override
        public boolean isAsync() {
            return false;
        }

        @Override
        public void timeoutAsync(long now) {
            // NO-OP
        }

        @Override
        public Request getRequest() {
            return null;
        }

        @Override
        public void setSslSupport(SSLSupport sslSupport) {
            // NO-OP
        }

        @Override
        public void pause() {
            // NO-OP
        }

        @Override
        public boolean checkAsyncTimeoutGeneration() {
            return false;
        }
    }


    private static byte[] readAllBufferedInput(SocketWrapperBase<?> wrapper) {
        SocketBufferHandler bufferHandler = wrapper.getSocketBufferHandler();
        bufferHandler.configureReadBufferForRead();
        ByteBuffer readBuffer = bufferHandler.getReadBuffer();
        byte[] result = new byte[readBuffer.remaining()];
        readBuffer.get(result);
        return result;
    }


    /**
     * Stands in for {@code Http11Processor}. The key behaviour it reproduces is
     * that {@link #getLeftoverInput()} returns a view of - rather than a copy of
     * - its own internal buffer, and that {@link #recycle()} does not clear that
     * buffer.
     */
    private static class TesterHttp11Processor implements Processor {

        private final boolean useUpgradeToken;
        private final byte[] inputBuffer =
                new byte[LEFTOVER_OFFSET + PIPELINED_BY_THIS_CLIENT.length];
        private boolean upgradeRequested = true;
        private SocketWrapperBase<?> lastWrapper = null;

        TesterHttp11Processor(boolean useUpgradeToken) {
            this.useUpgradeToken = useUpgradeToken;
            System.arraycopy(PIPELINED_BY_THIS_CLIENT, 0, inputBuffer, LEFTOVER_OFFSET,
                    PIPELINED_BY_THIS_CLIENT.length);
        }

        /**
         * Simulates this recycled processor being used to parse a request that
         * arrived on a different connection, re-using the same input buffer.
         */
        void parseRequestFromAnotherConnection() {
            System.arraycopy(PARSED_BY_ANOTHER_CONNECTION, 0, inputBuffer, LEFTOVER_OFFSET,
                    PARSED_BY_ANOTHER_CONNECTION.length);
        }

        /**
         * @return the connection this processor was last used to serve
         */
        SocketWrapperBase<?> getLastWrapper() {
            return lastWrapper;
        }

        byte[] getLeftoverRegion() {
            byte[] result = new byte[PIPELINED_BY_THIS_CLIENT.length];
            System.arraycopy(inputBuffer, LEFTOVER_OFFSET, result, 0, result.length);
            return result;
        }

        @Override
        public SocketState process(SocketWrapperBase<?> socketWrapper, SocketEvent status) {
            lastWrapper = socketWrapper;
            if (upgradeRequested) {
                upgradeRequested = false;
                return SocketState.UPGRADING;
            }
            // Serving the second connection out of the shared pool.
            parseRequestFromAnotherConnection();
            return SocketState.CLOSED;
        }

        @Override
        public UpgradeToken getUpgradeToken() {
            if (useUpgradeToken) {
                return new UpgradeToken(new TesterUpgradeHandler(), null, null);
            }
            return null;
        }

        @Override
        public ByteBuffer getLeftoverInput() {
            // As per Http11InputBuffer.getLeftover() this wraps, and does not
            // copy, the internal buffer.
            return ByteBuffer.wrap(inputBuffer, LEFTOVER_OFFSET, PIPELINED_BY_THIS_CLIENT.length);
        }

        @Override
        public void recycle() {
            // As per Http11Processor, recycling does not clear the input buffer.
        }

        @Override
        public boolean isUpgrade() {
            // Must be false so that release() returns this processor to the
            // pool of recycled processors, as it does for Http11Processor.
            return false;
        }

        @Override
        public boolean isAsync() {
            return false;
        }

        @Override
        public void timeoutAsync(long now) {
            // NO-OP
        }

        @Override
        public Request getRequest() {
            return null;
        }

        @Override
        public void setSslSupport(SSLSupport sslSupport) {
            // NO-OP
        }

        @Override
        public void pause() {
            // NO-OP
        }

        @Override
        public boolean checkAsyncTimeoutGeneration() {
            return false;
        }
    }


    /**
     * Stands in for the processor created for the new protocol once the upgrade
     * has taken place. Implements {@link WebConnection} because the upgrade
     * token code path casts the new processor to it.
     */
    private static class TesterUpgradedProcessor implements Processor, WebConnection {

        @Override
        public SocketState process(SocketWrapperBase<?> socketWrapper, SocketEvent status) {
            return SocketState.UPGRADED;
        }

        @Override
        public UpgradeToken getUpgradeToken() {
            throw new IllegalStateException();
        }

        @Override
        public ByteBuffer getLeftoverInput() {
            throw new IllegalStateException();
        }

        @Override
        public boolean isUpgrade() {
            return true;
        }

        @Override
        public boolean isAsync() {
            return false;
        }

        @Override
        public void timeoutAsync(long now) {
            // NO-OP
        }

        @Override
        public Request getRequest() {
            return null;
        }

        @Override
        public void recycle() {
            // NO-OP
        }

        @Override
        public void setSslSupport(SSLSupport sslSupport) {
            // NO-OP
        }

        @Override
        public void pause() {
            // NO-OP
        }

        @Override
        public boolean checkAsyncTimeoutGeneration() {
            return false;
        }

        @Override
        public ServletInputStream getInputStream() {
            return null;
        }

        @Override
        public ServletOutputStream getOutputStream() {
            return null;
        }

        @Override
        public void close() {
            // NO-OP
        }
    }


    private static class TesterUpgradeHandler implements HttpUpgradeHandler {

        @Override
        public void init(WebConnection connection) {
            // NO-OP
        }

        @Override
        public void destroy() {
            // NO-OP
        }
    }


    /**
     * Minimal {@link AbstractProtocol} that lets the test control the upgrade
     * processor factory methods. Both of those factory methods are called by the
     * connection handler after the HTTP/1.1 processor has been released, which
     * is where the second connection is driven from.
     */
    private static class TesterProtocol extends AbstractProtocol<NioChannel> {

        private static final Log log = LogFactory.getLog(TesterProtocol.class);

        private final boolean useUpgradeToken;
        private final NioEndpoint testerEndpoint;
        private AbstractProtocol.ConnectionHandler<NioChannel> handler;
        private SocketWrapperBase<NioChannel> otherWrapper;
        private boolean concurrentConnectionServed = false;
        private Supplier<Processor> processorFactory = null;
        private boolean h2cAvailable = true;

        TesterProtocol(boolean useUpgradeToken) {
            this(useUpgradeToken, new NioEndpoint());
        }

        private TesterProtocol(boolean useUpgradeToken, NioEndpoint endpoint) {
            super(endpoint);
            this.useUpgradeToken = useUpgradeToken;
            this.testerEndpoint = endpoint;
        }

        NioEndpoint getTesterEndpoint() {
            return testerEndpoint;
        }

        void setConcurrentConnection(AbstractProtocol.ConnectionHandler<NioChannel> handler,
                SocketWrapperBase<NioChannel> otherWrapper) {
            this.handler = handler;
            this.otherWrapper = otherWrapper;
        }

        /**
         * Supplies the processors returned by {@link #createProcessor()}. If
         * not set, creating a processor is a test failure.
         */
        void setProcessorFactory(Supplier<Processor> processorFactory) {
            this.processorFactory = processorFactory;
        }

        /**
         * Controls whether the h2c upgrade protocol is available for a direct
         * HTTP/2 connection ({@code upgradeToken == null}).
         */
        void setH2cAvailable(boolean h2cAvailable) {
            this.h2cAvailable = h2cAvailable;
        }

        /**
         * Serves an unrelated connection through the connection handler. The
         * handler will take the just released HTTP/1.1 processor from the shared
         * pool of recycled processors and parse a request into its input buffer.
         */
        private void serveConcurrentConnection() {
            if (handler == null || concurrentConnectionServed) {
                return;
            }
            concurrentConnectionServed = true;
            handler.process(otherWrapper, SocketEvent.OPEN_READ);
        }

        @Override
        protected UpgradeProtocol getUpgradeProtocol(String name) {
            if (useUpgradeToken || !h2cAvailable || !"h2c".equals(name)) {
                return null;
            }
            return new TesterUpgradeProtocol();
        }

        @Override
        protected Processor createUpgradeProcessor(SocketWrapperBase<?> socket,
                UpgradeToken upgradeToken) {
            serveConcurrentConnection();
            return new TesterUpgradedProcessor();
        }

        @Override
        protected Processor createProcessor() {
            if (processorFactory == null) {
                throw new IllegalStateException("A new processor should not be required");
            }
            return processorFactory.get();
        }

        @Override
        protected UpgradeProtocol getNegotiatedProtocol(String name) {
            return null;
        }

        @Override
        protected Log getLog() {
            return log;
        }

        @Override
        protected String getNamePrefix() {
            return "tester";
        }

        @Override
        protected String getProtocolName() {
            return "Tester";
        }

        @Override
        public void addSslHostConfig(SSLHostConfig sslHostConfig) {
            // NO-OP
        }

        @Override
        public SSLHostConfig[] findSslHostConfigs() {
            return new SSLHostConfig[0];
        }

        @Override
        public void addUpgradeProtocol(UpgradeProtocol upgradeProtocol) {
            // NO-OP
        }

        @Override
        public UpgradeProtocol[] findUpgradeProtocols() {
            return new UpgradeProtocol[0];
        }


        private class TesterUpgradeProtocol implements UpgradeProtocol {

            @Override
            public String getHttpUpgradeName(boolean isSSLEnabled) {
                return "h2c";
            }

            @Override
            public byte[] getAlpnIdentifier() {
                return null;
            }

            @Override
            public String getAlpnName() {
                return null;
            }

            @Override
            public Processor getProcessor(SocketWrapperBase<?> socketWrapper, Adapter adapter) {
                serveConcurrentConnection();
                return new TesterUpgradedProcessor();
            }

            @Override
            public InternalHttpUpgradeHandler getInternalUpgradeHandler(
                    SocketWrapperBase<?> socketWrapper, Adapter adapter, Request request) {
                return null;
            }

            @Override
            public boolean accept(Request request) {
                return false;
            }
        }
    }


    /**
     * Minimal {@link SocketWrapperBase} that provides a real
     * {@link SocketBufferHandler} so that {@code unRead()} behaves as it does on
     * a live connection.
     */
    private static class TesterSocketWrapper extends SocketWrapperBase<NioChannel> {

        TesterSocketWrapper(NioEndpoint endpoint) {
            super(null, endpoint);
            socketBufferHandler = new SocketBufferHandler(1024, 1024, false);
        }

        @Override
        protected void populateRemoteHost() {
            // NO-OP
        }

        @Override
        protected void populateRemoteAddr() {
            // NO-OP
        }

        @Override
        protected void populateRemotePort() {
            // NO-OP
        }

        @Override
        protected void populateLocalName() {
            // NO-OP
        }

        @Override
        protected void populateLocalAddr() {
            // NO-OP
        }

        @Override
        protected void populateLocalPort() {
            // NO-OP
        }

        @Override
        public int read(boolean block, byte[] b, int off, int len) throws IOException {
            return populateReadBuffer(b, off, len);
        }

        @Override
        public int read(boolean block, ByteBuffer to) throws IOException {
            return populateReadBuffer(to);
        }

        @Override
        public boolean isReadyForRead() throws IOException {
            return !socketBufferHandler.isReadBufferEmpty();
        }

        @Override
        public void setAppReadBufHandler(ApplicationBufferHandler handler) {
            // NO-OP
        }

        @Override
        protected void doClose() {
            // NO-OP
        }

        @Override
        protected void doWrite(boolean block, ByteBuffer from) throws IOException {
            // Discard
            from.position(from.limit());
        }

        @Override
        public void registerReadInterest() {
            // NO-OP
        }

        @Override
        public void registerWriteInterest() {
            // NO-OP
        }

        @Override
        public SendfileDataBase createSendfileData(String filename, long pos, long length) {
            return null;
        }

        @Override
        public SendfileState processSendfile(SendfileDataBase sendfileData) {
            return SendfileState.DONE;
        }

        @Override
        public void doClientAuth(SSLSupport sslSupport) throws IOException {
            // NO-OP
        }

        @Override
        public SSLSupport getSslSupport(String clientCertProvider) {
            return null;
        }

        @Override
        protected <A> OperationState<A> newOperationState(boolean read, ByteBuffer[] buffers,
                int offset, int length, BlockingMode block, long timeout, TimeUnit unit,
                A attachment, CompletionCheck check, CompletionHandler<Long, ? super A> handler,
                Semaphore semaphore, VectoredIOCompletionHandler<A> completion) {
            throw new UnsupportedOperationException();
        }
    }
}
