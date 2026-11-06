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

import java.lang.reflect.Field;
import java.nio.CharBuffer;

import org.junit.Assert;
import org.junit.Test;

public class TestC2BConverter {

    @Test
    public void testRecycleWithFailingEncoderReset() throws Exception {
        C2BConverter conv = new C2BConverter(new TesterResetFailCharset());

        // Simulate an incomplete character left over from the previous use of
        // this converter
        Field f = C2BConverter.class.getDeclaredField("leftovers");
        f.setAccessible(true);
        CharBuffer leftovers = (CharBuffer) f.get(conv);
        leftovers.put('\ud83d');
        Assert.assertTrue(conv.isUndeflow());

        // A failure to reset the encoder must neither escape from recycle()
        // nor prevent the remainder of the converter from being recycled
        conv.recycle();

        Assert.assertFalse(conv.isUndeflow());
    }
}
