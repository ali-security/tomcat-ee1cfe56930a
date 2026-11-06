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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Helpers for testing the canonical file name cache handling added for CVE-2024-56337.
 * <p>
 * The behaviour under test depends on the Java version the JVM is running on and on the command line the JVM was
 * started with. Neither can be changed from within a running test JVM so the tests have to drive a forked JVM and
 * assert on the markers it writes to standard out.
 * <p>
 * Named {@code Tester*} so that the Ant build does not collect it as a test case. It is in this package so that it
 * can reach the protected state in {@link JreCompat}.
 */
public class TesterCanonCaches {

    public static final String USE_CANON_CACHES_TRUE = "-Dsun.io.useCanonCaches=true";
    public static final String USE_CANON_CACHES_FALSE = "-Dsun.io.useCanonCaches=false";

    /*
     * Allows the canonical file name cache to be disabled, via reflection, on Java 12 to 17 (the value is final on
     * those versions).
     */
    public static final String[] ADD_OPENS = { "--add-opens=java.base/java.io=ALL-UNNAMED",
            "--add-opens=java.base/java.lang.invoke=ALL-UNNAMED",
            "--add-opens=java.base/java.lang.reflect=ALL-UNNAMED" };

    // Used to simulate a java.io.FileSystem.useCanonCaches field that exists but that can't be set (it is final)
    @SuppressWarnings("unused")
    private static final Boolean NOT_SETTABLE = Boolean.TRUE;


    private TesterCanonCaches() {
        // Utility class. Hide default constructor.
    }


    /**
     * @return The major version of the JVM running the test (8, 9, 10, 11, ...)
     */
    public static int javaMajorVersion() {
        String version = System.getProperty("java.specification.version");
        if (version.startsWith("1.")) {
            version = version.substring(2);
        }
        return Integer.parseInt(version);
    }


    /**
     * @return {@code true} if the canonical file name cache has been removed from the JDK (Java 21 and later)
     */
    public static boolean isCanonCachesRemoved() {
        return javaMajorVersion() >= 21;
    }


    /**
     * Make {@link JreCompat#disableCanonCaches()} behave as if the {@code java.io.FileSystem.useCanonCaches} field
     * could not be found. Also forgets any previous determination of whether the cache is disabled.
     */
    public static void simulateUseCanonCachesFieldNotAvailable() {
        synchronized (JreCompat.canonCachesDisabledLock) {
            JreCompat.canonCachesDisabled = null;
        }
        JreCompat.useCanonCachesField = Optional.empty();
    }


    /**
     * Make {@link JreCompat#disableCanonCaches()} behave as if the {@code java.io.FileSystem.useCanonCaches} field
     * could be found but not set. Also forgets any previous determination of whether the cache is disabled.
     *
     * @throws ReflectiveOperationException If the field used for the simulation can not be found
     */
    public static void simulateUseCanonCachesFieldNotSettable() throws ReflectiveOperationException {
        Field f = TesterCanonCaches.class.getDeclaredField("NOT_SETTABLE");
        f.setAccessible(true);
        synchronized (JreCompat.canonCachesDisabledLock) {
            JreCompat.canonCachesDisabled = null;
        }
        JreCompat.useCanonCachesField = Optional.of(f);
    }


    /**
     * Runs the given class in a forked JVM and returns everything it wrote to standard out and standard error.
     *
     * @param jvmArgs Additional JVM arguments
     * @param main    The class to run
     * @param args    The arguments for the class to run
     *
     * @return The output of the forked JVM
     *
     * @throws IOException          If the JVM could not be started or its output could not be read
     * @throws InterruptedException If the current thread is interrupted while waiting for the JVM
     */
    public static String fork(List<String> jvmArgs, Class<?> main, String... args)
            throws IOException, InterruptedException {

        List<String> command = new ArrayList<>();
        command.add(new File(new File(System.getProperty("java.home"), "bin"), "java").getAbsolutePath());
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.addAll(jvmArgs);
        command.add(main.getName());
        for (String arg : args) {
            command.add(arg);
        }

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process p = pb.start();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (InputStream is = p.getInputStream()) {
            byte[] buf = new byte[4096];
            int read = is.read(buf);
            while (read > 0) {
                baos.write(buf, 0, read);
                read = is.read(buf);
            }
        }
        if (!p.waitFor(120, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new IOException("Forked JVM did not complete within 120s. Output:\n" +
                    baos.toString(StandardCharsets.UTF_8.name()));
        }

        return baos.toString(StandardCharsets.UTF_8.name());
    }
}
