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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import org.junit.Assert;
import org.junit.Test;

/**
 * Tests for the HTTP/2 overhead protection against the "MadeYouReset" denial
 * of service attack (CVE-2025-48989).
 * <p>
 * Rather than resetting streams itself, a client sends frames that are
 * malformed at the stream level so that the server resets the stream. As with
 * the "Rapid Reset" attack, this allows the client to trigger an unbounded
 * amount of request processing on the server while never exceeding the limit
 * on concurrent streams. Reset frames sent by the server must therefore add to
 * the overhead count in the same way as reset frames received from the client
 * so that such a connection is closed with an ENHANCE_YOUR_CALM error.
 */
public class TestHttp2MadeYouReset extends Http2TestBase {

    private static final int ATTACK_STREAM_COUNT = 50;

    private static final byte[] PING_PAYLOAD = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };


    /*
     * Each request is followed by a WINDOW_UPDATE frame with a zero increment
     * for the same stream. That is a stream error so the server resets every
     * stream. All the frames (and a trailing PING) are sent in a single write
     * so the server is likely to read them in a single read.
     */
    @Test
    public void testZeroWindowUpdateSingleWrite() throws Exception {
        http2Connect();

        ByteArrayOutputStream attack = new ByteArrayOutputStream();
        for (int i = 0; i < ATTACK_STREAM_COUNT; i++) {
            int streamId = 3 + (2 * i);
            appendSimpleGetRequest(attack, streamId);
            attack.write(buildWindowUpdateFrame(streamId, 0));
        }
        attack.write(buildPingFrame(PING_PAYLOAD));

        os.write(attack.toByteArray());
        os.flush();

        assertConnectionClosedForOverhead();
    }


    /*
     * As above but each frame is sent (and flushed) individually.
     */
    @Test
    public void testZeroWindowUpdateSeparateWrites() throws Exception {
        http2Connect();

        try {
            for (int i = 0; i < ATTACK_STREAM_COUNT; i++) {
                int streamId = 3 + (2 * i);
                sendSimpleGetRequest(streamId);
                sendWindowUpdate(streamId, 0);
            }
            os.write(buildPingFrame(PING_PAYLOAD));
            os.flush();
        } catch (IOException ioe) {
            // Expected once the server has closed the connection
        }

        assertConnectionClosedForOverhead();
    }


    /*
     * Each request is followed by a WINDOW_UPDATE frame that overflows the
     * flow control window for the stream. That is a stream error so the server
     * resets every stream.
     */
    @Test
    public void testWindowOverflowSingleWrite() throws Exception {
        http2Connect();

        ByteArrayOutputStream attack = new ByteArrayOutputStream();
        for (int i = 0; i < ATTACK_STREAM_COUNT; i++) {
            int streamId = 3 + (2 * i);
            appendSimpleGetRequest(attack, streamId);
            attack.write(buildWindowUpdateFrame(streamId, (1 << 31) - 1));
        }
        attack.write(buildPingFrame(PING_PAYLOAD));

        os.write(attack.toByteArray());
        os.flush();

        assertConnectionClosedForOverhead();
    }


    /*
     * PRIORITY frames for streams that depend on themselves are stream errors.
     * They are rejected before they are counted as overhead frames so the only
     * protection is the reset sent by the server.
     */
    @Test
    public void testSelfDependentPrioritySingleWrite() throws Exception {
        http2Connect();

        ByteArrayOutputStream attack = new ByteArrayOutputStream();
        for (int i = 0; i < ATTACK_STREAM_COUNT; i++) {
            int streamId = 3 + (2 * i);
            attack.write(buildPriorityFrame(streamId, streamId, 15));
        }
        attack.write(buildPingFrame(PING_PAYLOAD));

        os.write(attack.toByteArray());
        os.flush();

        assertConnectionClosedForOverhead();
    }


    /*
     * A client that triggers the occasional stream reset must not have the
     * connection closed.
     */
    @Test
    public void testOccasionalServerResetAllowed() throws Exception {
        http2Connect();

        sendSimpleGetRequest(3);
        sendWindowUpdate(3, 0);

        sendSimpleGetRequest(5);

        // Stream 3 may or may not have been (partly) written before the reset
        // was sent so skip any frames for stream 3.
        String trace;
        int frameCount = 0;
        do {
            parser.readFrame(true);
            trace = output.getTrace();
            frameCount++;
        } while (!(trace.contains("5-EndOfStream") && trace.contains("3-RST-")) &&
                !trace.contains("0-Goaway-") && frameCount < 100);

        Assert.assertFalse(trace, trace.contains("0-Goaway-"));
        Assert.assertTrue(trace, trace.contains("3-RST-[" + Http2Error.PROTOCOL_ERROR.getCode() + "]"));
        Assert.assertTrue(trace, trace.contains("5-EndOfStream"));
    }


    private void assertConnectionClosedForOverhead() throws Exception {
        boolean closed = false;
        String trace = output.getTrace();
        try {
            // Read until the server closes the connection or responds to the
            // PING sent after the frames that trigger the resets.
            while (!trace.contains("0-Goaway-") && !trace.contains("0-Ping-Ack-")) {
                parser.readFrame(true);
                trace = output.getTrace();
            }
        } catch (IOException ioe) {
            // The server closed the connection
            closed = true;
            trace = output.getTrace();
        }

        // If the PING was acknowledged the server continued to process frames
        // after the overhead limit should have been exceeded.
        Assert.assertFalse("Connection was not closed: " + trace, trace.contains("0-Ping-Ack-"));

        if (!closed || trace.contains("0-Goaway-")) {
            // The resets sent by the server precede the GOAWAY frame
            Assert.assertTrue(trace, trace.contains("-RST-["));
            String goaway = trace.substring(trace.indexOf("0-Goaway-"));
            Assert.assertTrue(goaway, goaway.matches(
                    "(?s)0-Goaway-\\[\\d+\\]-\\[" + Http2Error.ENHANCE_YOUR_CALM.getCode() + "\\]-\\[.*"));
        }
    }


    private void appendSimpleGetRequest(ByteArrayOutputStream target, int streamId) throws IOException {
        byte[] frameHeader = new byte[9];
        ByteBuffer headersPayload = ByteBuffer.allocate(128);
        buildSimpleGetRequest(frameHeader, headersPayload, null, streamId);
        target.write(frameHeader);
        target.write(headersPayload.array(), headersPayload.arrayOffset(), headersPayload.limit());
    }


    private static byte[] buildWindowUpdateFrame(int streamId, int increment) {
        byte[] updateFrame = new byte[13];
        // length is always 4
        updateFrame[2] = 0x04;
        updateFrame[3] = FrameType.WINDOW_UPDATE.getIdByte();
        // no flags
        // Stream ID
        ByteUtil.set31Bits(updateFrame, 5, streamId);
        // Payload
        ByteUtil.set31Bits(updateFrame, 9, increment);
        return updateFrame;
    }


    private static byte[] buildPriorityFrame(int streamId, int streamDependencyId, int weight) {
        byte[] priorityFrame = new byte[14];
        // length
        ByteUtil.setThreeBytes(priorityFrame, 0, 5);
        // type
        priorityFrame[3] = FrameType.PRIORITY.getIdByte();
        // No flags
        // Stream ID
        ByteUtil.set31Bits(priorityFrame, 5, streamId);
        // Payload
        ByteUtil.set31Bits(priorityFrame, 9, streamDependencyId);
        priorityFrame[13] = (byte) (weight & 0xFF);
        return priorityFrame;
    }


    private static byte[] buildPingFrame(byte[] payload) {
        byte[] pingFrame = new byte[9 + payload.length];
        // length
        ByteUtil.setThreeBytes(pingFrame, 0, payload.length);
        // Type
        pingFrame[3] = FrameType.PING.getIdByte();
        // No flags
        // Stream 0
        System.arraycopy(payload, 0, pingFrame, 9, payload.length);
        return pingFrame;
    }
}
