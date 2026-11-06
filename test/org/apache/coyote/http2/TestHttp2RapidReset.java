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
 * Tests for the HTTP/2 overhead protection against the "Rapid Reset" denial of
 * service attack (CVE-2023-44487).
 * <p>
 * A client that repeatedly opens a stream and then immediately resets it can
 * trigger an unbounded amount of request processing on the server while never
 * exceeding the limit on concurrent streams. Reset frames must therefore add to
 * the overhead count so that such a connection is closed with an
 * ENHANCE_YOUR_CALM error.
 */
public class TestHttp2RapidReset extends Http2TestBase {

    private static final int ATTACK_STREAM_COUNT = 50;

    private static final byte[] PING_PAYLOAD = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };


    /*
     * All the HEADERS / RST_STREAM pairs (and a trailing PING) are sent in a
     * single write so the server is likely to read them in a single read. The
     * frames after the one that exceeds the overhead limit must not be
     * processed.
     */
    @Test
    public void testRapidResetSingleWrite() throws Exception {
        http2Connect();

        ByteArrayOutputStream attack = new ByteArrayOutputStream();
        for (int i = 0; i < ATTACK_STREAM_COUNT; i++) {
            int streamId = 3 + (2 * i);
            appendSimpleGetRequest(attack, streamId);
            attack.write(buildRstFrame(streamId, Http2Error.CANCEL.getCode()));
        }
        attack.write(buildPingFrame(PING_PAYLOAD));

        os.write(attack.toByteArray());
        os.flush();

        assertConnectionClosedForOverhead();
    }


    /*
     * Each HEADERS and RST_STREAM frame is sent (and flushed) individually.
     */
    @Test
    public void testRapidResetSeparateWrites() throws Exception {
        http2Connect();

        try {
            for (int i = 0; i < ATTACK_STREAM_COUNT; i++) {
                int streamId = 3 + (2 * i);
                sendSimpleGetRequest(streamId);
                sendRst(streamId, Http2Error.CANCEL.getCode());
            }
            os.write(buildPingFrame(PING_PAYLOAD));
            os.flush();
        } catch (IOException ioe) {
            // Expected once the server has closed the connection
        }

        assertConnectionClosedForOverhead();
    }


    /*
     * A client cancelling the occasional stream (as browsers routinely do) must
     * not have the connection closed.
     */
    @Test
    public void testOccasionalResetAllowed() throws Exception {
        http2Connect();

        sendSimpleGetRequest(3);
        sendRst(3, Http2Error.CANCEL.getCode());

        sendSimpleGetRequest(5);

        // Stream 3 may or may not have been (partly) written before the reset
        // was processed so skip any frames for stream 3.
        String trace;
        int frameCount = 0;
        do {
            parser.readFrame(true);
            trace = output.getTrace();
            frameCount++;
        } while (!trace.contains("5-EndOfStream") && !trace.contains("0-Goaway-") &&
                frameCount < 100);

        Assert.assertFalse(trace, trace.contains("0-Goaway-"));
        Assert.assertTrue(trace, trace.contains("5-EndOfStream"));
    }


    private void assertConnectionClosedForOverhead() throws Exception {
        boolean closed = false;
        String trace = output.getTrace();
        try {
            // Read until the server closes the connection or responds to the
            // PING sent after the resets.
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


    private static byte[] buildRstFrame(int streamId, long errorCode) {
        byte[] rstFrame = new byte[13];
        // length is always 4
        rstFrame[2] = 0x04;
        rstFrame[3] = FrameType.RST.getIdByte();
        // no flags
        // Stream ID
        ByteUtil.set31Bits(rstFrame, 5, streamId);
        // Payload
        ByteUtil.setFourBytes(rstFrame, 9, errorCode);
        return rstFrame;
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
