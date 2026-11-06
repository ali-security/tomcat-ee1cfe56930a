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
package org.apache.catalina.webresources;

import java.lang.reflect.Method;

import org.junit.Assert;
import org.junit.Test;

/**
 * White-box test for the fix for CVE-2021-24122. The private
 * {@code isInvalidWindowsFilename(String)} method must treat the ':' character
 * (used in NTFS Alternate Data Stream names) as an invalid Windows file name
 * character so that access to the ADS is blocked.
 */
public class TestAbstractFileResourceSet {

    private boolean isInvalidWindowsFilename(String name) throws Exception {
        // DirResourceSet is a concrete subclass of AbstractFileResourceSet.
        DirResourceSet resourceSet = new DirResourceSet();
        Method m = AbstractFileResourceSet.class.getDeclaredMethod(
                "isInvalidWindowsFilename", String.class);
        m.setAccessible(true);
        return ((Boolean) m.invoke(resourceSet, name)).booleanValue();
    }

    @Test
    public void testColonIsRejected() throws Exception {
        // ':' introduces an NTFS Alternate Data Stream - must be rejected
        Assert.assertTrue(isInvalidWindowsFilename("foo.txt:stream"));
    }

    @Test
    public void testColonAloneIsRejected() throws Exception {
        Assert.assertTrue(isInvalidWindowsFilename(":"));
    }

    @Test
    public void testPlainNameIsAccepted() throws Exception {
        Assert.assertFalse(isInvalidWindowsFilename("foo.txt"));
    }

    @Test
    public void testEmptyNameIsAccepted() throws Exception {
        Assert.assertFalse(isInvalidWindowsFilename(""));
    }

    @Test
    public void testOtherDisallowedCharsStillRejected() throws Exception {
        Assert.assertTrue(isInvalidWindowsFilename("foo\"bar"));
        Assert.assertTrue(isInvalidWindowsFilename("foo<bar"));
        Assert.assertTrue(isInvalidWindowsFilename("foo>bar"));
    }
}
