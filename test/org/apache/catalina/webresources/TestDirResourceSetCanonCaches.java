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

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.compat.JreCompat;
import org.apache.tomcat.util.compat.TesterCanonCaches;
import org.apache.tomcat.util.res.StringManager;

/**
 * Tests the CVE-2024-56337 exposure check added to {@link DirResourceSet}.
 * <p>
 * The check depends on the Java version and on the command line the JVM was started with, neither of which can be
 * changed in the JVM running the tests, so most of the tests drive a forked JVM.
 */
public class TestDirResourceSetCanonCaches extends TomcatBaseTest {

    private static final StringManager sm = StringManager.getManager(DirResourceSet.class);

    /**
     * Fragment of {@code dirResourceSet.canonCaches.enabled}. Logged (as the message of the exception that stops the
     * WebResourceSet starting) when Tomcat cannot confirm that the canonical file name cache has been disabled.
     */
    private static final String EXPOSED_MESSAGE = "may be exposed to CVE-2024-56337";

    /**
     * Fragment of {@code dirResourceSet.canonCaches.disabled}. Logged when Tomcat disabled the cache.
     */
    private static final String DISABLED_WARNING = "Disabled the global canonical file name cache";

    /**
     * {@code jreCompat.useCanonCaches.none}. Only logged if the exposure check actually attempted to disable the
     * cache.
     */
    private static final String DISABLE_ATTEMPTED_WARNING =
            "No reference to the java.io.FileSystem.useCanonCaches static field available";

    /**
     * {@code jreCompat.useCanonCaches.failed}. Only logged if the exposure check found the field but could not set
     * it.
     */
    private static final String DISABLE_FAILED_WARNING =
            "Failed to set the java.io.FileSystem.useCanonCaches static field";


    @Test
    public void testMessagesAreDefined() {
        String disabled = sm.getString("dirResourceSet.canonCaches.disabled");
        Assert.assertNotNull(disabled);
        Assert.assertTrue(disabled.contains(DISABLED_WARNING));
        String exposed = sm.getString("dirResourceSet.canonCaches.enabled");
        Assert.assertNotNull(exposed);
        Assert.assertTrue(exposed.contains(EXPOSED_MESSAGE));
    }


    /**
     * A web application started with a writable resource set must leave the JVM with the canonical file name cache
     * disabled, whatever the JVM was doing before: enabled by default on Java 8 to 11, disabled by default from Java
     * 12 and absent from Java 21.
     */
    @Test
    public void testStartingAWebApplicationDisablesTheCache() throws Exception {
        Tomcat tomcat = getTomcatInstance();

        File appDir = new File("test/webapp");
        Context ctx = tomcat.addContext("", appDir.getAbsolutePath());
        tomcat.start();

        Assert.assertTrue("The web application is not running", ctx.getState().isAvailable());
        Assert.assertTrue("The canonical file name cache is still enabled",
                JreCompat.getInstance().isCanonCachesDisabled());
    }


    /**
     * The vulnerable scenario on the Java versions where the cache is enabled by default (and, on any version, when it
     * has been enabled explicitly): a writable resource set is started while the cache is enabled. Tomcat must disable
     * the cache, must say so and must still start the resource set.
     */
    @Test
    public void testCanonCachesAreDisabled() throws Exception {
        int java = TesterCanonCaches.javaMajorVersion();
        // See TestJreCompat.testDisableCanonCaches() for the Java versions where the cache can be disabled
        Assume.assumeTrue("Java " + java + " has no canonical file name cache that can be disabled", java <= 17);

        List<String> jvmArgs = new ArrayList<>();
        jvmArgs.add(TesterCanonCaches.USE_CANON_CACHES_TRUE);
        if (java >= 12) {
            jvmArgs.addAll(Arrays.asList(TesterCanonCaches.ADD_OPENS));
        }

        String output = fork(jvmArgs, false, "none");

        assertMarker(output, "CANON_CACHES_DISABLED_BEFORE=false");
        assertMarker(output, "START=OK");
        assertMarker(output, "CANON_CACHES_DISABLED_AFTER=true");
        Assert.assertTrue("No warning that the cache was disabled was logged:\n" + output,
                output.contains("WARN|org.apache.catalina.webresources.DirResourceSet|" + DISABLED_WARNING));
        if (java <= 11) {
            // Java 12 and later make the field final so the JVM may not allow it to be read
            assertMarker(output, "JDK_USE_CANON_CACHES_AFTER=false");
        }
    }


    /**
     * The mitigation the upstream start-up scripts apply. No warning, and the cache is never touched.
     */
    @Test
    public void testCanonCachesDisabledOnTheCommandLine() throws Exception {
        String output = fork(Collections.singletonList(TesterCanonCaches.USE_CANON_CACHES_FALSE), false, "none");

        assertMarker(output, "CANON_CACHES_DISABLED_BEFORE=true");
        assertMarker(output, "START=OK");
        assertMarker(output, "CANON_CACHES_DISABLED_AFTER=true");
        Assert.assertFalse("A warning was logged for a protected JVM:\n" + output, output.contains("WARN|"));
    }


    /**
     * Neither CVE-2024-56337 nor CVE-2024-50379 is exploitable against a read only resource set so the check must not
     * fire - and must not disable the cache - for one.
     */
    @Test
    public void testReadOnlyResourceSetIsNotChecked() throws Exception {
        // From Java 21 the cache is always reported as disabled
        Assume.assumeFalse(TesterCanonCaches.isCanonCachesRemoved());

        String output = fork(Collections.singletonList(TesterCanonCaches.USE_CANON_CACHES_TRUE), true, "none");

        assertMarker(output, "CANON_CACHES_DISABLED_BEFORE=false");
        assertMarker(output, "START=OK");
        assertMarker(output, "CANON_CACHES_DISABLED_AFTER=false");
        Assert.assertFalse("The cache was touched for a read only WebResourceSet:\n" + output,
                output.contains("WARN|"));
    }


    /**
     * The cache is enabled and Tomcat is unable to find the field it needs to disable it. The WebResourceSet may be
     * exposed to CVE-2024-56337 so it must not start.
     */
    @Test
    public void testCanonCachesCanNotBeDisabledFieldNotAvailable() throws Exception {
        Assume.assumeFalse(TesterCanonCaches.isCanonCachesRemoved());

        String output = fork(Collections.singletonList(TesterCanonCaches.USE_CANON_CACHES_TRUE), false,
                "fieldNotAvailable");

        assertMarker(output, "CANON_CACHES_DISABLED_BEFORE=false");
        assertMarker(output, "START=FAILED:java.lang.IllegalStateException");
        Assert.assertTrue("The exception does not explain the exposure:\n" + output,
                output.contains("START_FAILED_MESSAGE=") && output.contains(EXPOSED_MESSAGE));
        assertMarker(output, "CANON_CACHES_DISABLED_AFTER=false");
        Assert.assertTrue("Tomcat did not try to disable the cache:\n" + output,
                output.contains(DISABLE_ATTEMPTED_WARNING));
        Assert.assertFalse("The cache was reported as disabled:\n" + output, output.contains(DISABLED_WARNING));
    }


    /**
     * The cache is enabled and Tomcat found the field it needs to disable it but could not set it. The WebResourceSet
     * may be exposed to CVE-2024-56337 so it must not start.
     */
    @Test
    public void testCanonCachesCanNotBeDisabledFieldNotSettable() throws Exception {
        Assume.assumeFalse(TesterCanonCaches.isCanonCachesRemoved());

        String output = fork(Collections.singletonList(TesterCanonCaches.USE_CANON_CACHES_TRUE), false,
                "fieldNotSettable");

        assertMarker(output, "CANON_CACHES_DISABLED_BEFORE=false");
        assertMarker(output, "START=FAILED:java.lang.IllegalStateException");
        Assert.assertTrue("The exception does not explain the exposure:\n" + output,
                output.contains(EXPOSED_MESSAGE));
        assertMarker(output, "CANON_CACHES_DISABLED_AFTER=false");
        Assert.assertTrue("Tomcat did not try to set the field:\n" + output,
                output.contains(DISABLE_FAILED_WARNING));
    }


    /**
     * The same failure but for a read only resource set, which is not exposed so must start normally.
     */
    @Test
    public void testCanonCachesCanNotBeDisabledReadOnly() throws Exception {
        Assume.assumeFalse(TesterCanonCaches.isCanonCachesRemoved());

        String output = fork(Collections.singletonList(TesterCanonCaches.USE_CANON_CACHES_TRUE), true,
                "fieldNotAvailable");

        assertMarker(output, "START=OK");
    }


    private String fork(List<String> jvmArgs, boolean readOnly, String simulation) throws Exception {
        String output = TesterCanonCaches.fork(jvmArgs, TesterDirResourceSetCanonCaches.class,
                Boolean.toString(readOnly), simulation);
        Assert.assertTrue("Forked JVM did not complete. Output:\n" + output, output.contains("DONE"));
        return output;
    }


    private void assertMarker(String output, String marker) {
        Assert.assertTrue("Expected [" + marker + "] in the output of the forked JVM:\n" + output,
                output.contains(marker + System.lineSeparator()) || output.contains(marker + "\n"));
    }
}
