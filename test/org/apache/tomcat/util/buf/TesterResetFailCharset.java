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
package org.apache.tomcat.util.buf;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;

/**
 * A single byte character set whose decoders and encoders fail when they are
 * reset. Used to test that a failure to reset a decoder / encoder does not
 * prevent the remainder of the recycling process from completing.
 */
public class TesterResetFailCharset extends Charset {

    public TesterResetFailCharset() {
        super("x-tomcat-tester-reset-fail", null);
    }


    @Override
    public boolean contains(Charset cs) {
        return cs instanceof TesterResetFailCharset;
    }


    @Override
    public CharsetDecoder newDecoder() {
        return new ResetFailDecoder(this);
    }


    @Override
    public CharsetEncoder newEncoder() {
        return new ResetFailEncoder(this);
    }


    private static class ResetFailDecoder extends CharsetDecoder {

        ResetFailDecoder(Charset cs) {
            super(cs, 1, 1);
        }

        @Override
        protected CoderResult decodeLoop(ByteBuffer in, CharBuffer out) {
            while (in.hasRemaining()) {
                if (!out.hasRemaining()) {
                    return CoderResult.OVERFLOW;
                }
                out.put((char) (in.get() & 0xFF));
            }
            return CoderResult.UNDERFLOW;
        }

        @Override
        protected void implReset() {
            throw new IllegalStateException("Decoder reset failure");
        }
    }


    private static class ResetFailEncoder extends CharsetEncoder {

        ResetFailEncoder(Charset cs) {
            super(cs, 1, 1);
        }

        @Override
        protected CoderResult encodeLoop(CharBuffer in, ByteBuffer out) {
            while (in.hasRemaining()) {
                if (!out.hasRemaining()) {
                    return CoderResult.OVERFLOW;
                }
                out.put((byte) in.get());
            }
            return CoderResult.UNDERFLOW;
        }

        @Override
        protected void implReset() {
            throw new IllegalStateException("Encoder reset failure");
        }
    }
}
