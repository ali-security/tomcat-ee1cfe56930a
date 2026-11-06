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
package org.apache.tomcat.util.security;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

import org.apache.tomcat.util.buf.ByteChunk;

public class TestConstantTime {

    /*
     * The AJP secret is transferred as bytes on the wire and compared against
     * the configured secret which is a String. The bytes always sit at a
     * non-zero offset within the AJP packet buffer so the ByteChunk based
     * comparison must respect ByteChunk.getStart().
     */
    private static final String SECRET = "RIGHTSECRET";

    // 0xC9 is E-acute in ISO-8859-1 i.e. a byte that is negative when signed
    private static final String HIGH_BYTE_SECRET = "S\u00C9CRET";


    private static ByteChunk toByteChunk(String s) {
        return toByteChunk(s, 0);
    }


    /*
     * Builds a ByteChunk where the interesting bytes start at the requested
     * offset. The rest of the buffer is filled with a byte that does not appear
     * in any of the test values so that an implementation which ignores
     * getStart() will read the wrong data.
     */
    private static ByteChunk toByteChunk(String s, int offset) {
        byte[] data = s.getBytes(StandardCharsets.ISO_8859_1);
        byte[] buf = new byte[offset + data.length + 4];
        Arrays.fill(buf, (byte) '#');
        System.arraycopy(data, 0, buf, offset, data.length);
        ByteChunk bc = new ByteChunk();
        bc.setBytes(buf, offset, data.length);
        return bc;
    }


    // ------------------------------------------------- equals(String, String)

    @Test
    public void testStringEqual() {
        Assert.assertTrue(ConstantTime.equals(new String(SECRET.toCharArray()), SECRET, false));
    }


    @Test
    public void testStringSameReference() {
        Assert.assertTrue(ConstantTime.equals(SECRET, SECRET, false));
    }


    @Test
    public void testStringNotEqualSameLength() {
        Assert.assertFalse(ConstantTime.equals("RIGHTSECRE_", SECRET, false));
    }


    @Test
    public void testStringNotEqualFirstCharacter() {
        Assert.assertFalse(ConstantTime.equals("_IGHTSECRET", SECRET, false));
    }


    @Test
    public void testStringShorter() {
        Assert.assertFalse(ConstantTime.equals("RIGHTSECRE", SECRET, false));
    }


    @Test
    public void testStringLonger() {
        Assert.assertFalse(ConstantTime.equals("RIGHTSECRETS", SECRET, false));
    }


    @Test
    public void testStringCaseSensitive() {
        Assert.assertFalse(ConstantTime.equals("rightsecret", SECRET, false));
    }


    @Test
    public void testStringIgnoreCase() {
        Assert.assertTrue(ConstantTime.equals("rightsecret", SECRET, true));
    }


    @Test
    public void testStringIgnoreCaseNotEqual() {
        Assert.assertFalse(ConstantTime.equals("rightsecre_", SECRET, true));
    }


    @Test
    public void testStringBothNull() {
        Assert.assertTrue(ConstantTime.equals(null, null, false));
    }


    @Test
    public void testStringFirstNull() {
        Assert.assertFalse(ConstantTime.equals(null, SECRET, false));
    }


    @Test
    public void testStringSecondNull() {
        Assert.assertFalse(ConstantTime.equals(SECRET, null, false));
    }


    @Test
    public void testStringBothEmpty() {
        Assert.assertTrue(ConstantTime.equals(new String(new char[0]), "", false));
    }


    @Test
    public void testStringFirstEmpty() {
        Assert.assertFalse(ConstantTime.equals("", SECRET, false));
    }


    @Test
    public void testStringSecondEmpty() {
        Assert.assertFalse(ConstantTime.equals(SECRET, "", false));
    }


    // ---------------------------------------------- equals(ByteChunk, String)

    @Test
    public void testByteChunkEqual() {
        Assert.assertTrue(ConstantTime.equals(toByteChunk(SECRET), SECRET));
    }


    @Test
    public void testByteChunkNotEqualSameLength() {
        Assert.assertFalse(ConstantTime.equals(toByteChunk("RIGHTSECRE_"), SECRET));
    }


    @Test
    public void testByteChunkNotEqualFirstByte() {
        Assert.assertFalse(ConstantTime.equals(toByteChunk("_IGHTSECRET"), SECRET));
    }


    @Test
    public void testByteChunkShorter() {
        Assert.assertFalse(ConstantTime.equals(toByteChunk("RIGHTSECRE"), SECRET));
    }


    @Test
    public void testByteChunkLonger() {
        Assert.assertFalse(ConstantTime.equals(toByteChunk("RIGHTSECRETS"), SECRET));
    }


    @Test
    public void testByteChunkCaseSensitive() {
        Assert.assertFalse(ConstantTime.equals(toByteChunk("rightsecret"), SECRET));
    }


    /*
     * The AJP secret never starts at the beginning of the packet buffer so the
     * comparison has to start at ByteChunk.getStart(). An implementation that
     * reads from index zero rejects a valid secret.
     */
    @Test
    public void testByteChunkNonZeroStartEqual() {
        Assert.assertTrue(ConstantTime.equals(toByteChunk(SECRET, 13), SECRET));
    }


    @Test
    public void testByteChunkNonZeroStartNotEqual() {
        Assert.assertFalse(ConstantTime.equals(toByteChunk("RIGHTSECRE_", 13), SECRET));
    }


    @Test
    public void testByteChunkNonZeroStartShorter() {
        Assert.assertFalse(ConstantTime.equals(toByteChunk("RIGHTSECRE", 13), SECRET));
    }


    @Test
    public void testByteChunkNonZeroStartLonger() {
        Assert.assertFalse(ConstantTime.equals(toByteChunk("RIGHTSECRETS", 13), SECRET));
    }


    /*
     * Bytes have to be compared as unsigned values. If they are compared as
     * signed values any byte greater than 0x7F can never match the equivalent
     * character.
     */
    @Test
    public void testByteChunkHighByteEqual() {
        Assert.assertTrue(ConstantTime.equals(toByteChunk(HIGH_BYTE_SECRET), HIGH_BYTE_SECRET));
    }


    @Test
    public void testByteChunkHighByteEqualNonZeroStart() {
        Assert.assertTrue(ConstantTime.equals(toByteChunk(HIGH_BYTE_SECRET, 7), HIGH_BYTE_SECRET));
    }


    @Test
    public void testByteChunkHighByteNotEqual() {
        // Differs from HIGH_BYTE_SECRET in the high byte only
        Assert.assertFalse(ConstantTime.equals(toByteChunk("S\u00CACRET"), HIGH_BYTE_SECRET));
    }


    @Test
    public void testByteChunkBothNull() {
        Assert.assertTrue(ConstantTime.equals((ByteChunk) null, (String) null));
    }


    @Test
    public void testByteChunkNull() {
        Assert.assertFalse(ConstantTime.equals((ByteChunk) null, SECRET));
    }


    @Test
    public void testByteChunkStringNull() {
        Assert.assertFalse(ConstantTime.equals(toByteChunk(SECRET), null));
    }


    @Test
    public void testByteChunkBothEmpty() {
        Assert.assertTrue(ConstantTime.equals(toByteChunk(""), ""));
    }


    @Test
    public void testByteChunkEmpty() {
        Assert.assertFalse(ConstantTime.equals(toByteChunk(""), SECRET));
    }


    @Test
    public void testByteChunkStringEmpty() {
        Assert.assertFalse(ConstantTime.equals(toByteChunk(SECRET), ""));
    }


    // ---------------------------------------------- equals(byte[], byte[])

    @Test
    public void testByteArrayEqual() {
        Assert.assertTrue(ConstantTime.equals(SECRET.getBytes(StandardCharsets.ISO_8859_1),
                SECRET.getBytes(StandardCharsets.ISO_8859_1)));
    }


    @Test
    public void testByteArrayNotEqual() {
        Assert.assertFalse(ConstantTime.equals("RIGHTSECRE_".getBytes(StandardCharsets.ISO_8859_1),
                SECRET.getBytes(StandardCharsets.ISO_8859_1)));
    }


    @Test
    public void testByteArrayDifferentLength() {
        Assert.assertFalse(ConstantTime.equals("RIGHTSECRE".getBytes(StandardCharsets.ISO_8859_1),
                SECRET.getBytes(StandardCharsets.ISO_8859_1)));
    }


    @Test
    public void testByteArrayBothNull() {
        Assert.assertTrue(ConstantTime.equals((byte[]) null, (byte[]) null));
    }


    @Test
    public void testByteArrayFirstNull() {
        Assert.assertFalse(ConstantTime.equals(null, SECRET.getBytes(StandardCharsets.ISO_8859_1)));
    }


    @Test
    public void testByteArraySecondNull() {
        Assert.assertFalse(ConstantTime.equals(SECRET.getBytes(StandardCharsets.ISO_8859_1), null));
    }
}
