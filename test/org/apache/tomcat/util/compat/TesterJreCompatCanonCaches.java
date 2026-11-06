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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Driven by {@code TestJreCompat} which starts this class in a forked JVM.
 * <p>
 * With no arguments it reports how the Java 8 to 11 ({@link JreCompat}) and Java 12 and later ({@link Jre12Compat})
 * implementations of {@code isCanonCachesDisabled()} interpret the command line this JVM was started with.
 * <p>
 * With the argument {@code disable} it reports what {@code disableCanonCaches()} does to the way this JVM resolves a
 * symbolic link that is changed after it has been resolved once.
 * <p>
 * Named {@code Tester*} so that the Ant build does not collect it as a test case.
 */
public class TesterJreCompatCanonCaches {

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "disable".equals(args[0])) {
            disable();
            return;
        }

        /*
         * The answer is cached in a static field shared by every implementation so it has to be reset between the
         * implementations under test.
         */
        JreCompat.canonCachesDisabled = null;
        System.out.println("BASE_DISABLED=" + new JreCompat().isCanonCachesDisabled());

        JreCompat.canonCachesDisabled = null;
        System.out.println("JRE12_DISABLED=" + new Jre12Compat().isCanonCachesDisabled());

        JreCompat.canonCachesDisabled = null;
        System.out.println("INSTANCE=" + JreCompat.getInstance().getClass().getName());
        System.out.println("DONE");
    }


    private static void disable() throws Exception {
        Path dir = Files.createTempDirectory("canon-caches");
        try {
            Path target1 = Files.createDirectory(dir.resolve("target1"));
            Path target2 = Files.createDirectory(dir.resolve("target2"));
            Path link = dir.resolve("link");
            try {
                Files.createSymbolicLink(link, target1);
            } catch (IOException | UnsupportedOperationException | SecurityException e) {
                System.out.println("SYMLINK=unsupported");
                System.out.println("DONE");
                return;
            }

            File file = link.toFile();
            String real1 = target1.toRealPath().toString();
            String real2 = target2.toRealPath().toString();

            boolean disabledAtStart = JreCompat.getInstance().isCanonCachesDisabled();
            System.out.println("DISABLED_AT_START=" + disabledAtStart);

            // If the cache is enabled this puts the canonical name of the link in the cache
            System.out.println("FIRST=" + real1.equals(file.getCanonicalPath()));

            // The link now refers to a different file...
            Files.delete(link);
            Files.createSymbolicLink(link, target2);

            // ...but the cache, if it is enabled, still returns the old name
            System.out.println("STALE=" + real1.equals(file.getCanonicalPath()));

            if (!disabledAtStart) {
                System.out.println("DISABLE_RESULT=" + JreCompat.getInstance().disableCanonCaches());
            }
            System.out.println("DISABLED_AT_END=" + JreCompat.getInstance().isCanonCachesDisabled());
            System.out.println("FRESH=" + real2.equals(file.getCanonicalPath()));
            System.out.println("DONE");
        } finally {
            // Best effort clean up. The JVM is about to exit.
            File[] files = dir.toFile().listFiles();
            if (files != null) {
                for (File f : files) {
                    f.delete();
                }
            }
            dir.toFile().delete();
        }
    }
}
