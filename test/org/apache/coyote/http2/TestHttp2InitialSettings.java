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
package org.apache.coyote.http2;

import java.nio.ByteBuffer;
import java.util.EnumMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;

/**
 * The local settings that reduce the limits a client is permitted to use (the
 * maximum number of concurrent streams and the initial flow control window
 * size) have to be effective as soon as the connection is created. If they only
 * take effect once the client has acknowledged the initial {@code SETTINGS}
 * frame, a client can simply never send that acknowledgement and continue to
 * use the (unlimited / larger) default limits for the life of the connection.
 */
public class TestHttp2InitialSettings {

    private static final long MAX_CONCURRENT_STREAMS = 5;
    private static final int INITIAL_WINDOW_SIZE = 8 * 1024;


    private static Http2UpgradeHandler buildHandler() {
        Http2Protocol protocol = new Http2Protocol();
        protocol.setMaxConcurrentStreams(MAX_CONCURRENT_STREAMS);
        protocol.setInitialWindowSize(INITIAL_WINDOW_SIZE);
        // No connection has been established so no SETTINGS frame has been
        // sent, never mind acknowledged.
        return new Http2UpgradeHandler(protocol, null, null);
    }


    /**
     * The limit on concurrent streams is read from the local settings by every
     * enforcement point in Http2UpgradeHandler. Before this was forced, it
     * reported UNLIMITED until the client acknowledged the SETTINGS frame.
     */
    @Test
    public void testMaxConcurrentStreamsAppliesBeforeAck() {
        Http2UpgradeHandler handler = buildHandler();

        Assert.assertNotEquals("Limit on concurrent streams is not enforced until the client sends an ACK",
                ConnectionSettingsBase.UNLIMITED, handler.getLocalSettings().getMaxConcurrentStreams());
        Assert.assertEquals(MAX_CONCURRENT_STREAMS, handler.getLocalSettings().getMaxConcurrentStreams());
    }


    /**
     * The initial flow control window is read from the local settings when the
     * per stream input buffer is sized. Before this was forced, it reported the
     * protocol default (65535) until the client acknowledged the SETTINGS
     * frame.
     */
    @Test
    public void testInitialWindowSizeAppliesBeforeAck() {
        Http2UpgradeHandler handler = buildHandler();

        Assert.assertNotEquals("Reduced flow control window is not applied until the client sends an ACK",
                ConnectionSettingsBase.DEFAULT_INITIAL_WINDOW_SIZE,
                handler.getLocalSettings().getInitialWindowSize());
        Assert.assertEquals(INITIAL_WINDOW_SIZE, handler.getLocalSettings().getInitialWindowSize());
    }


    /**
     * The resource consumption the reduced flow control window is meant to
     * limit. The buffer used to receive the request body is sized using the
     * local setting so, before the setting was forced, every stream on a
     * connection that had not been acknowledged allocated a buffer sized for
     * the default window rather than the configured one.
     */
    @Test
    public void testStreamInputBufferUsesConfiguredWindowBeforeAck() {
        Http2UpgradeHandler handler = buildHandler();

        Stream stream = new Stream(Integer.valueOf(3), handler);
        ByteBuffer inputByteBuffer = stream.getInputByteBuffer();

        Assert.assertNotNull(inputByteBuffer);
        Assert.assertEquals("Stream input buffer is sized for the default window, not the configured window",
                INITIAL_WINDOW_SIZE, inputByteBuffer.capacity());
    }


    /**
     * Forcing the settings must not stop them being advertised to the client.
     * The reduced limits still have to appear in the next SETTINGS frame and an
     * ACK is still expected for that frame.
     */
    @Test
    public void testForcedSettingsAreStillSentAndAcknowledged() {
        Http2UpgradeHandler handler = buildHandler();
        ConnectionSettingsLocal localSettings = handler.getLocalSettings();

        Map<Setting,Long> sent = parseSettingsFrame(localSettings.getSettingsFrameForPending());

        Assert.assertEquals(Long.valueOf(MAX_CONCURRENT_STREAMS), sent.get(Setting.MAX_CONCURRENT_STREAMS));
        Assert.assertEquals(Long.valueOf(INITIAL_WINDOW_SIZE), sent.get(Setting.INITIAL_WINDOW_SIZE));

        // An ACK is still expected for the frame that was just built
        Assert.assertTrue(localSettings.ack());
        // No second ACK is expected
        Assert.assertFalse(localSettings.ack());

        // The values must be unchanged by the ACK
        Assert.assertEquals(MAX_CONCURRENT_STREAMS, localSettings.getMaxConcurrentStreams());
        Assert.assertEquals(INITIAL_WINDOW_SIZE, localSettings.getInitialWindowSize());
    }


    /**
     * Settings that are not forced must keep the original behaviour of only
     * taking effect once the client has acknowledged them.
     */
    @Test
    public void testSettingsAreDeferredUnlessForced() {
        ConnectionSettingsLocal localSettings = new ConnectionSettingsLocal("0");

        Assert.assertEquals(ConnectionSettingsBase.UNLIMITED, localSettings.getMaxConcurrentStreams());

        localSettings.set(Setting.MAX_CONCURRENT_STREAMS, MAX_CONCURRENT_STREAMS);

        // Not forced so the most generous of the current and pending values is
        // used until the ACK is received
        Assert.assertEquals(ConnectionSettingsBase.UNLIMITED, localSettings.getMaxConcurrentStreams());

        localSettings.getSettingsFrameForPending();
        Assert.assertTrue(localSettings.ack());

        Assert.assertEquals(MAX_CONCURRENT_STREAMS, localSettings.getMaxConcurrentStreams());
    }


    private static Map<Setting,Long> parseSettingsFrame(byte[] frame) {
        Assert.assertEquals(FrameType.SETTINGS.getIdByte(), frame[3]);
        int payloadSize = ByteUtil.getThreeBytes(frame, 0);
        Assert.assertEquals(payloadSize, frame.length - 9);
        Assert.assertEquals(0, payloadSize % 6);

        Map<Setting,Long> result = new EnumMap<>(Setting.class);
        int pos = 9;
        while (pos < frame.length) {
            Setting setting = Setting.valueOf(ByteUtil.getTwoBytes(frame, pos));
            pos += 2;
            result.put(setting, Long.valueOf(ByteUtil.getFourBytes(frame, pos)));
            pos += 4;
        }
        return result;
    }
}
