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

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.junit.Assert;
import org.junit.Test;

/**
 * White-box regression test for CVE-2025-52434.
 *
 * The APR/native connector could crash the JVM when a socket was closed while
 * another thread was populating remote/local address information via native
 * calls. The fix guards each {@code populate*()} method and {@code close()}
 * with a per-socket {@link Lock} so that a close can never race an in-progress
 * native access on the same socket.
 *
 * This test exercises the locking contract without ever reaching JNI: it uses a
 * fresh {@link AprEndpoint} (no SSL) so the wrapper's buffers are heap-backed,
 * and it forces the wrapper into the closed state so every {@code populate*()}
 * returns at the {@code isClosed()} guard and {@code close()}'s CAS is a no-op.
 * The native APR layer is therefore never invoked.
 */
public class TestAprEndpointCloseRace {

    private AprEndpoint.AprSocketWrapper newClosedWrapper() {
        AprEndpoint endpoint = new AprEndpoint();
        // Fresh endpoint => isSSLEnabled() is false => heap SocketBufferHandler,
        // no direct buffer, so constructing the wrapper touches no native code.
        AprEndpoint.AprSocketWrapper wrapper =
                new AprEndpoint.AprSocketWrapper(Long.valueOf(1), endpoint);
        // Same-package access to the protected AtomicBoolean. Marking the
        // wrapper closed makes every populate*() bail at isClosed() and makes
        // close()'s state CAS a no-op, so JNI is never reached.
        wrapper.closed.set(true);
        return wrapper;
    }

    @Test
    public void testGetLockPresent() {
        AprEndpoint.AprSocketWrapper wrapper = newClosedWrapper();
        Lock lock = wrapper.getLock();
        Assert.assertNotNull("AprSocketWrapper must expose a dedicated socket lock", lock);
        Assert.assertTrue("Socket lock must be a ReentrantLock", lock instanceof ReentrantLock);
    }

    /**
     * Prove close() acquires the socket lock: while the main thread holds the
     * lock, a worker calling close() must block, and the lock must show a
     * queued waiter. Once the main thread releases, the worker proceeds.
     */
    @Test
    public void testCloseBlocksOnLock() throws Exception {
        assertCloseContends();
    }

    @Test
    public void testPopulateRemoteAddrBlocksOnLock() throws Exception {
        assertPopulateContends(Op.REMOTE_ADDR);
    }

    @Test
    public void testPopulateRemoteHostBlocksOnLock() throws Exception {
        assertPopulateContends(Op.REMOTE_HOST);
    }

    @Test
    public void testPopulateRemotePortBlocksOnLock() throws Exception {
        assertPopulateContends(Op.REMOTE_PORT);
    }

    @Test
    public void testPopulateLocalNameBlocksOnLock() throws Exception {
        assertPopulateContends(Op.LOCAL_NAME);
    }

    @Test
    public void testPopulateLocalAddrBlocksOnLock() throws Exception {
        assertPopulateContends(Op.LOCAL_ADDR);
    }

    @Test
    public void testPopulateLocalPortBlocksOnLock() throws Exception {
        assertPopulateContends(Op.LOCAL_PORT);
    }

    private enum Op {
        REMOTE_ADDR, REMOTE_HOST, REMOTE_PORT, LOCAL_NAME, LOCAL_ADDR, LOCAL_PORT
    }

    private void assertPopulateContends(final Op op) throws Exception {
        final AprEndpoint.AprSocketWrapper wrapper = newClosedWrapper();
        final Lock lock = wrapper.getLock();

        final CountDownLatch started = new CountDownLatch(1);
        final CountDownLatch finished = new CountDownLatch(1);

        lock.lock();
        try {
            Thread worker = new Thread(new Runnable() {
                @Override
                public void run() {
                    started.countDown();
                    invoke(wrapper, op);
                    finished.countDown();
                }
            });
            worker.setDaemon(true);
            worker.start();

            Assert.assertTrue("Worker did not start", started.await(5, TimeUnit.SECONDS));

            // The worker must block on the socket lock we hold.
            Assert.assertFalse("populate* completed while lock was held - not lock-guarded",
                    finished.await(500, TimeUnit.MILLISECONDS));
            Assert.assertTrue("No thread queued on the socket lock - populate* did not take the lock",
                    ((ReentrantLock) lock).hasQueuedThreads());
        } finally {
            lock.unlock();
        }

        // After releasing, the worker must be able to proceed.
        Assert.assertTrue("populate* did not complete after lock release",
                finished.await(5, TimeUnit.SECONDS));
    }

    /**
     * Same contention proof, specialised for close().
     */
    private void assertCloseContends() throws Exception {
        final AprEndpoint.AprSocketWrapper wrapper = newClosedWrapper();
        final Lock lock = wrapper.getLock();

        final CountDownLatch started = new CountDownLatch(1);
        final CountDownLatch finished = new CountDownLatch(1);

        lock.lock();
        try {
            Thread worker = new Thread(new Runnable() {
                @Override
                public void run() {
                    started.countDown();
                    wrapper.close();
                    finished.countDown();
                }
            });
            worker.setDaemon(true);
            worker.start();

            Assert.assertTrue("Worker did not start", started.await(5, TimeUnit.SECONDS));

            Assert.assertFalse("close() completed while lock was held - not lock-guarded",
                    finished.await(500, TimeUnit.MILLISECONDS));
            Assert.assertTrue("No thread queued on the socket lock - close() did not take the lock",
                    ((ReentrantLock) lock).hasQueuedThreads());
        } finally {
            lock.unlock();
        }

        Assert.assertTrue("close() did not complete after lock release",
                finished.await(5, TimeUnit.SECONDS));
    }

    private static void invoke(AprEndpoint.AprSocketWrapper wrapper, Op op) {
        switch (op) {
        case REMOTE_ADDR:
            wrapper.populateRemoteAddr();
            break;
        case REMOTE_HOST:
            wrapper.populateRemoteHost();
            break;
        case REMOTE_PORT:
            wrapper.populateRemotePort();
            break;
        case LOCAL_NAME:
            wrapper.populateLocalName();
            break;
        case LOCAL_ADDR:
            wrapper.populateLocalAddr();
            break;
        case LOCAL_PORT:
            wrapper.populateLocalPort();
            break;
        default:
            throw new IllegalArgumentException(String.valueOf(op));
        }
    }
}
