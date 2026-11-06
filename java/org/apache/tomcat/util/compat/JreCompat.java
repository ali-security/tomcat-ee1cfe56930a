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
import java.lang.management.ManagementFactory;
import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Field;
import java.net.URL;
import java.net.URLConnection;
import java.util.Deque;
import java.util.List;
import java.util.Optional;
import java.util.jar.JarFile;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.res.StringManager;

/**
 * This is the base implementation class for JRE compatibility and provides an
 * implementation based on Java 8. Sub-classes may extend this class and provide
 * alternative implementations for later JRE versions
 */
public class JreCompat {

    private static final int RUNTIME_MAJOR_VERSION = 8;

    private static final JreCompat instance;
    private static final boolean graalAvailable;
    private static final boolean jre9Available;
    private static final boolean jre12Available;
    private static final Log log = LogFactory.getLog(JreCompat.class);
    private static final StringManager sm = StringManager.getManager(JreCompat.class);

    protected static final String USE_CANON_CACHES_CMD_ARG = "-Dsun.io.useCanonCaches=";
    protected static volatile Boolean canonCachesDisabled;
    protected static final Object canonCachesDisabledLock = new Object();
    protected static volatile Optional<Field> useCanonCachesField;
    protected static final Object useCanonCachesFieldLock = new Object();

    static {
        // This is Tomcat 9 with a minimum Java version of Java 8.
        // Look for the highest supported JVM first
        if (GraalCompat.isSupported()) {
            instance = new GraalCompat();
            graalAvailable = true;
            jre9Available = Jre9Compat.isSupported();
            jre12Available = Jre12Compat.isSupported();
        } else if (Jre12Compat.isSupported()) {
            instance = new Jre12Compat();
            graalAvailable = false;
            jre9Available = true;
            jre12Available = true;
        } else if (Jre9Compat.isSupported()) {
            instance = new Jre9Compat();
            graalAvailable = false;
            jre9Available = true;
            jre12Available = false;
        } else {
            instance = new JreCompat();
            graalAvailable = false;
            jre9Available = false;
            jre12Available = false;
        }
    }


    public static JreCompat getInstance() {
        return instance;
    }


    public static boolean isGraalAvailable() {
        return graalAvailable;
    }


    public static boolean isJre9Available() {
        return jre9Available;
    }


    public static boolean isJre12Available() {
        return jre12Available;
    }


    // Java 8 implementation of Java 9 methods

    /**
     * Test if the provided exception is an instance of
     * java.lang.reflect.InaccessibleObjectException.
     *
     * @param t The exception to test
     *
     * @return {@code true} if the exception is an instance of
     *         InaccessibleObjectException, otherwise {@code false}
     */
    public boolean isInstanceOfInaccessibleObjectException(Throwable t) {
        // Exception does not exist prior to Java 9
        return false;
    }


    /**
     * Set the application protocols the server will accept for ALPN
     *
     * @param sslParameters The SSL parameters for a connection
     * @param protocols     The application protocols to be allowed for that
     *                      connection
     */
    public void setApplicationProtocols(SSLParameters sslParameters, String[] protocols) {
        throw new UnsupportedOperationException(sm.getString("jreCompat.noApplicationProtocols"));
    }


    /**
     * Get the application protocol that has been negotiated for connection
     * associated with the given SSLEngine.
     *
     * @param sslEngine The SSLEngine for which to obtain the negotiated
     *                  protocol
     *
     * @return The name of the negotiated protocol
     */
    public String getApplicationProtocol(SSLEngine sslEngine) {
        throw new UnsupportedOperationException(sm.getString("jreCompat.noApplicationProtocol"));
    }


    /**
     * Disables caching for JAR URL connections. For Java 8 and earlier, this also disables
     * caching for ALL URL connections.
     *
     * @throws IOException If a dummy JAR URLConnection can not be created
     */
    public void disableCachingForJarUrlConnections() throws IOException {
        // Doesn't matter that this JAR doesn't exist - just as
        // long as the URL is well-formed
        URL url = new URL("jar:file://dummy.jar!/");
        URLConnection uConn = url.openConnection();
        uConn.setDefaultUseCaches(false);
    }


    /**
     * Obtains the URLs for all the JARs on the module path when the JVM starts
     * and adds them to the provided Deque.
     *
     * @param classPathUrlsToProcess    The Deque to which the modules should be
     *                                  added
     */
    public void addBootModulePath(Deque<URL> classPathUrlsToProcess) {
        // NO-OP for Java 8. There is no module path.
    }


    /**
     * Creates a new JarFile instance. When running on Java 9 and later, the
     * JarFile will be multi-release JAR aware. While this isn't strictly
     * required to be in this package, it is provided as a convenience method.
     *
     * @param s The JAR file to open
     *
     * @return A JarFile instance based on the provided path
     *
     * @throws IOException  If an I/O error occurs creating the JarFile instance
     */
    public final JarFile jarFileNewInstance(String s) throws IOException {
        return jarFileNewInstance(new File(s));
    }


    /**
     * Creates a new JarFile instance. When running on Java 9 and later, the
     * JarFile will be multi-release JAR aware.
     *
     * @param f The JAR file to open
     *
     * @return A JarFile instance based on the provided file
     *
     * @throws IOException  If an I/O error occurs creating the JarFile instance
     */
    public JarFile jarFileNewInstance(File f) throws IOException {
        return new JarFile(f);
    }


    /**
     * Is this JarFile a multi-release JAR file.
     *
     * @param jarFile   The JarFile to test
     *
     * @return {@code true} If it is a multi-release JAR file and is configured
     *         to behave as such.
     */
    public boolean jarFileIsMultiRelease(JarFile jarFile) {
        // Java 8 doesn't support multi-release so default to false
        return false;
    }


    public int jarFileRuntimeMajorVersion() {
        return RUNTIME_MAJOR_VERSION;
    }


    /**
     * Is the accessibleObject accessible (as a result of appropriate module
     * exports) on the provided instance?
     *
     * @param base  The specific instance to be tested.
     * @param accessibleObject  The method/field/constructor to be tested.
     *
     * @return {code true} if the AccessibleObject can be accessed otherwise
     *         {code false}
     */
    public boolean canAcccess(Object base, AccessibleObject accessibleObject) {
        // Java 8 doesn't support modules so default to true
        return true;
    }


    /**
     * Is the given class in an exported package?
     *
     * @param type  The class to test
     *
     * @return Always {@code true} for Java 8. {@code true} if the enclosing
     *         package is exported for Java 9+
     */
    public boolean isExported(Class<?> type) {
        return true;
    }


    /*
     * The behaviour of the canonical file name cache varies by Java version.
     *
     * The cache was removed in Java 21 so these methods and the associated code can be removed once the minimum Java
     * version is 21.
     *
     * For 12 <= Java <= 20, the cache was present but disabled by default.
     *
     * For Java < 12, the cache was enabled by default. Tomcat assumes the cache is enabled unless proven otherwise.
     *
     * The static field in java.io.FileSystem will be set before any application code gets a chance to run. Therefore,
     * the value of that field can be determined by looking at the command line arguments. This enables us to determine
     * the status without having using reflection.
     *
     * This is Java 8 to 11 (Tomcat 9.0.x has a minimum Java version of 8).
     */
    public boolean isCanonCachesDisabled() {
        if (canonCachesDisabled != null) {
            return canonCachesDisabled.booleanValue();
        }
        synchronized (canonCachesDisabledLock) {
            if (canonCachesDisabled != null) {
                return canonCachesDisabled.booleanValue();
            }

            boolean cacheEnabled = true;
            List<String> args = ManagementFactory.getRuntimeMXBean().getInputArguments();
            for (String arg : args) {
                // To consider the cache disabled
                // - there must be at least one command line argument that disables it
                // - there must be no command line arguments that enable it
                if (arg.startsWith(USE_CANON_CACHES_CMD_ARG)) {
                    String valueAsString = arg.substring(USE_CANON_CACHES_CMD_ARG.length());
                    boolean valueAsBoolean = Boolean.valueOf(valueAsString).booleanValue();
                    if (valueAsBoolean) {
                        canonCachesDisabled = Boolean.FALSE;
                        return false;
                    } else {
                        cacheEnabled = false;
                    }
                }
            }
            if (cacheEnabled) {
                canonCachesDisabled = Boolean.FALSE;
            } else {
                canonCachesDisabled = Boolean.TRUE;
            }
            return canonCachesDisabled.booleanValue();
        }
    }


    /**
     * Disable the global canonical file cache.
     *
     * @return {@code true} if the global canonical file cache was already disabled prior to this call or was disabled
     *             as a result of this call, otherwise {@code false}
     */
    public boolean disableCanonCaches() {
        ensureUseCanonCachesFieldIsPopulated();
        if (!useCanonCachesField.isPresent()) {
            log.warn(sm.getString("jreCompat.useCanonCaches.none"));
            return false;
        }
        try {
            useCanonCachesField.get().set(null, Boolean.FALSE);
        } catch (ReflectiveOperationException | IllegalArgumentException e) {
            log.warn(sm.getString("jreCompat.useCanonCaches.failed"), e);
            return false;
        }
        synchronized (canonCachesDisabledLock) {
            canonCachesDisabled = Boolean.TRUE;
        }
        return true;
    }


    protected void ensureUseCanonCachesFieldIsPopulated() {
        if (useCanonCachesField != null) {
            return;
        }
        synchronized (useCanonCachesFieldLock) {
            if (useCanonCachesField != null) {
                return;
            }

            Field f = null;
            try {
                Class<?> clazz = Class.forName("java.io.FileSystem");
                f = clazz.getDeclaredField("useCanonCaches");
                // Need this because the 'useCanonCaches' field is not public (it is not final in Java 8 to 11)
                f.setAccessible(true);
            } catch (ReflectiveOperationException | RuntimeException e) {
                /*
                 * Upstream catches IllegalArgumentException here. RuntimeException is used instead (as in upstream
                 * 5d3585d2, BZ 69576) because this code has to compile for Java 8 so it cannot name
                 * InaccessibleObjectException (Java 9+), which is what setAccessible() throws on Java 9 to 11 when
                 * java.io is not open to the unnamed module (--illegal-access=deny).
                 */
                // Make sure field is not set.
                f = null;
                log.warn(sm.getString("jreCompat.useCanonCaches.init"), e);
            }

            if (f == null) {
                useCanonCachesField = Optional.empty();
            } else {
                useCanonCachesField = Optional.of(f);
            }
        }
    }
}
