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
package org.apache.tomcat.util.compat;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import org.apache.tomcat.util.res.StringManager;

/**
 * Tests the canonical file name cache support added to fix CVE-2024-56337.
 */
public class TestJreCompat {

    private static final StringManager sm = StringManager.getManager(JreCompat.class);


    @Test
    public void testMessagesAreDefined() {
        Assert.assertNotNull(sm.getString("jreCompat.useCanonCaches.failed"));
        Assert.assertNotNull(sm.getString("jreCompat.useCanonCaches.init"));
        Assert.assertNotNull(sm.getString("jreCompat.useCanonCaches.java18"));
        Assert.assertNotNull(sm.getString("jreCompat.useCanonCaches.none"));
        Assert.assertNotNull(StringManager.getManager(Jre12Compat.class).getString("jre12Compat.javaPre12"));
    }


    /**
     * The Java 12 and later canonical file name cache logic only takes effect if {@code Jre12Compat} is selected for
     * every Java version from 12 onwards. If it is not, the Java 8 to 11 logic - which assumes the cache is enabled -
     * is silently used instead.
     */
    @Test
    public void testJre12CompatIsSelectedFromJava12() {
        Assume.assumeFalse("GraalCompat is selected on a native image", JreCompat.isGraalAvailable());

        boolean java12OrLater = TesterCanonCaches.javaMajorVersion() >= 12;
        Assert.assertEquals(java12OrLater, JreCompat.isJre12Available());
        Assert.assertEquals("JreCompat.getInstance() returned [" + JreCompat.getInstance().getClass().getName() + "]",
                java12OrLater, JreCompat.getInstance() instanceof Jre12Compat);
    }


    /**
     * Java 8 to 11 enable the cache by default. Unless the command line explicitly disables it, Tomcat has to assume
     * it is enabled - this is the case that makes a web application vulnerable to CVE-2024-56337. Java 12 and later
     * disable the cache by default.
     */
    @Test
    public void testNoCommandLineArgument() throws Exception {
        doTestCommandLine(Collections.<String> emptyList(), false, true);
    }


    /**
     * The mitigation applied by upstream's start-up scripts. Both implementations have to recognise it.
     */
    @Test
    public void testCommandLineDisablesCache() throws Exception {
        doTestCommandLine(Collections.singletonList(TesterCanonCaches.USE_CANON_CACHES_FALSE), true, true);
    }


    /**
     * A user explicitly enabling the cache re-introduces the exposure on every Java version that still has the cache.
     * Neither implementation may report the cache as disabled. The cache was removed in Java 21 so, from then on, it is
     * always disabled.
     */
    @Test
    public void testCommandLineEnablesCache() throws Exception {
        doTestCommandLine(Collections.singletonList(TesterCanonCaches.USE_CANON_CACHES_TRUE), false,
                TesterCanonCaches.isCanonCachesRemoved());
    }


    /**
     * The JVM parses the value with a case insensitive comparison with "true".
     */
    @Test
    public void testCommandLineEnablesCacheIgnoringCase() throws Exception {
        doTestCommandLine(Collections.singletonList("-Dsun.io.useCanonCaches=TRUE"), false,
                TesterCanonCaches.isCanonCachesRemoved());
    }


    /**
     * To consider the cache disabled on Java 8 to 11 there must be no command line argument that enables it, however
     * many others disable it.
     */
    @Test
    public void testCommandLineEnableWinsOverDisable() throws Exception {
        doTestCommandLine(Arrays.asList(TesterCanonCaches.USE_CANON_CACHES_FALSE,
                TesterCanonCaches.USE_CANON_CACHES_TRUE, TesterCanonCaches.USE_CANON_CACHES_FALSE), false,
                TesterCanonCaches.isCanonCachesRemoved());
    }


    private void doTestCommandLine(List<String> jvmArgs, boolean expectedBase, boolean expectedJre12)
            throws Exception {
        String output = TesterCanonCaches.fork(jvmArgs, TesterJreCompatCanonCaches.class);

        Assert.assertTrue("Forked JVM did not complete. Output:\n" + output, output.contains("DONE"));
        assertMarker(output, "BASE_DISABLED=" + expectedBase);
        assertMarker(output, "JRE12_DISABLED=" + expectedJre12);
    }


    /**
     * disableCanonCaches() has to change the way the JVM resolves file names, not just the state Tomcat keeps. A
     * symbolic link that is changed after it has been resolved once is how the stale cache entry shows up.
     */
    @Test
    public void testDisableCanonCaches() throws Exception {
        int java = TesterCanonCaches.javaMajorVersion();
        // The cache can't be disabled on Java 18 to 20 and doesn't exist on Java 21 and later.
        Assume.assumeTrue("Java " + java + " has no canonical file name cache that can be disabled",
                java <= 17);

        List<String> jvmArgs = new ArrayList<>();
        // Java 8 and 11 enable the cache by default but, from Java 12, it has to be enabled explicitly
        jvmArgs.add(TesterCanonCaches.USE_CANON_CACHES_TRUE);
        if (java >= 12) {
            // The cache can only be disabled if the JVM allows access to the (final) field
            jvmArgs.addAll(Arrays.asList(TesterCanonCaches.ADD_OPENS));
        }

        String output = TesterCanonCaches.fork(jvmArgs, TesterJreCompatCanonCaches.class, "disable");

        Assert.assertTrue("Forked JVM did not complete. Output:\n" + output, output.contains("DONE"));
        Assume.assumeFalse("Symbolic links are not available", output.contains("SYMLINK=unsupported"));

        // This is the exposure: without any action the cache returns a name for a file that has changed
        assertMarker(output, "DISABLED_AT_START=false");
        assertMarker(output, "FIRST=true");
        assertMarker(output, "STALE=true");

        assertMarker(output, "DISABLE_RESULT=true");
        assertMarker(output, "DISABLED_AT_END=true");
        assertMarker(output, "FRESH=true");
    }


    /**
     * The cache was removed in Java 21 so there is nothing to disable and the explicit request to enable it has no
     * effect. Without the Java 21 handling, disableCanonCaches() would fail to find the field.
     */
    @Test
    public void testCanonCachesAlwaysDisabledFromJava21() throws Exception {
        Assume.assumeTrue(TesterCanonCaches.isCanonCachesRemoved());
        Assert.assertTrue(JreCompat.getInstance().isCanonCachesDisabled());
        Assert.assertTrue(JreCompat.getInstance().disableCanonCaches());

        String output = TesterCanonCaches.fork(Collections.singletonList(TesterCanonCaches.USE_CANON_CACHES_TRUE),
                TesterJreCompatCanonCaches.class, "disable");
        Assert.assertTrue("Forked JVM did not complete. Output:\n" + output, output.contains("DONE"));
        assertMarker(output, "DISABLED_AT_START=true");
        assertMarker(output, "DISABLED_AT_END=true");
    }


    private void assertMarker(String output, String marker) {
        Assert.assertTrue("Expected [" + marker + "] in the output of the forked JVM:\n" + output,
                output.contains(marker + System.lineSeparator()) || output.contains(marker + "\n"));
    }
}
