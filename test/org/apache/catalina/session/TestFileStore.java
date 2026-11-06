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
package org.apache.catalina.session;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.apache.catalina.Manager;
import org.apache.catalina.Session;
import org.apache.tomcat.unittest.TesterContext;
import org.apache.tomcat.unittest.TesterServletContext;
import org.apache.tomcat.util.http.fileupload.FileUtils;

/**
 * Confirms that {@link FileStore} only ever operates on session files that are
 * genuinely located inside its storage directory.
 * <p>
 * The original containment check compared the canonical path of the candidate
 * session file with the canonical path of the storage directory using
 * {@link String#startsWith(String)}. Because the storage directory path has no
 * trailing separator, any <em>sibling</em> directory whose name simply starts
 * with the name of the storage directory satisfied that check, so a session ID
 * containing <code>../</code> could still escape the storage directory. That is
 * the incomplete fix for CVE-2020-9484 which was tracked as CVE-2021-25329;
 * {@link java.nio.file.Path#startsWith(java.nio.file.Path)} compares whole path
 * elements and is therefore not fooled by a shared name prefix.
 */
public class TestFileStore {

    /*
     * The sibling directory name deliberately starts with the storage directory
     * name so that a String based prefix comparison of the two canonical paths
     * matches, while an element based (Path) comparison does not.
     */
    private static final String STORAGE_DIR_NAME = "SESS_TEMP_TFS";
    private static final String SIBLING_DIR_NAME = STORAGE_DIR_NAME + "evil";

    private static final String SIBLING_SESSION_ID = "evil";
    private static final String OUTSIDE_SESSION_ID = "outside";
    private static final String VALID_SESSION_ID = "tmp1";

    /* Session ID that escapes the storage directory into the sibling directory */
    private static final String TRAVERSAL_INTO_SIBLING_DIR =
            ".." + File.separator + SIBLING_DIR_NAME + File.separator + SIBLING_SESSION_ID;

    /* Session ID that escapes the storage directory into its parent */
    private static final String TRAVERSAL_INTO_PARENT_DIR = ".." + File.separator + OUTSIDE_SESSION_ID;

    private final Manager manager = new StandardManager();

    private File base;
    private File storageDir;
    private File siblingSessionFile;
    private File outsideSessionFile;
    private File validSessionFile;
    private FileStore fileStore;


    @Before
    public void setUp() throws Exception {
        base = Files.createTempDirectory("TestFileStore").toFile();

        storageDir = new File(base, STORAGE_DIR_NAME);
        Assert.assertTrue(storageDir.mkdir());

        File siblingDir = new File(base, SIBLING_DIR_NAME);
        Assert.assertTrue(siblingDir.mkdir());

        TesterContext testerContext = new TesterContext();
        testerContext.setServletContext(new TesterServletContext());
        manager.setContext(testerContext);

        // A store rooted at the sibling directory is used to plant a session
        // file there that is genuinely loadable, so that a successful escape
        // from the storage directory is unambiguous.
        FileStore siblingStore = new FileStore();
        siblingStore.setManager(manager);
        siblingStore.setDirectory(siblingDir.getAbsolutePath());
        siblingStore.save(createSession(SIBLING_SESSION_ID));
        siblingSessionFile = new File(siblingDir, SIBLING_SESSION_ID + ".session");
        Assert.assertTrue(siblingSessionFile.isFile());

        outsideSessionFile = new File(base, OUTSIDE_SESSION_ID + ".session");
        Assert.assertTrue(outsideSessionFile.createNewFile());

        fileStore = new FileStore();
        fileStore.setManager(manager);
        fileStore.setDirectory(storageDir.getAbsolutePath());
        fileStore.save(createSession(VALID_SESSION_ID));
        validSessionFile = new File(storageDir, VALID_SESSION_ID + ".session");
        Assert.assertTrue(validSessionFile.isFile());
    }


    @After
    public void tearDown() throws IOException {
        if (base != null && base.exists()) {
            FileUtils.deleteDirectory(base);
        }
    }


    private Session createSession(String id) {
        StandardSession session = new StandardSession(manager);
        session.setValid(true);
        session.setCreationTime(System.currentTimeMillis());
        session.setMaxInactiveInterval(60);
        session.setId(id, false);
        return session;
    }


    /**
     * Demonstrates that the exploited session ID does defeat a String based
     * prefix check, i.e. that the tests below really do exercise the
     * CVE-2021-25329 attack vector rather than a path that was already blocked.
     */
    @Test
    public void testSiblingDirectoryDefeatsStringPrefixCheck() throws Exception {
        File escaped = new File(storageDir, TRAVERSAL_INTO_SIBLING_DIR + ".session");

        Assert.assertTrue("Sibling directory no longer defeats a String prefix check so the"
                + " CVE-2021-25329 tests would not be discriminating",
                escaped.getCanonicalPath().startsWith(storageDir.getCanonicalPath()));

        Assert.assertFalse("Sibling directory must not be treated as being inside the storage"
                + " directory", escaped.getCanonicalFile().toPath().startsWith(
                        storageDir.getCanonicalFile().toPath()));
    }


    /**
     * CVE-2021-25329: a session ID that traverses into a sibling directory
     * whose name starts with the name of the storage directory must not allow
     * an arbitrary file to be deserialized.
     */
    @Test
    public void testLoadFromSiblingDirectory() throws Exception {
        Assert.assertNull(fileStore.load(TRAVERSAL_INTO_SIBLING_DIR));
    }


    /**
     * CVE-2021-25329: the same traversal must not allow an arbitrary file to be
     * deleted.
     */
    @Test
    public void testRemoveFromSiblingDirectory() throws Exception {
        fileStore.remove(TRAVERSAL_INTO_SIBLING_DIR);

        Assert.assertTrue("Session file outside the storage directory was removed",
                siblingSessionFile.isFile());
    }


    /**
     * CVE-2021-25329: the same traversal must not allow an arbitrary file to be
     * overwritten.
     */
    @Test
    public void testSaveToSiblingDirectory() throws Exception {
        byte[] original = Files.readAllBytes(siblingSessionFile.toPath());

        fileStore.save(createSession(TRAVERSAL_INTO_SIBLING_DIR));

        Assert.assertArrayEquals("Session file outside the storage directory was overwritten",
                original, Files.readAllBytes(siblingSessionFile.toPath()));
    }


    /**
     * CVE-2020-9484: a plain traversal out of the storage directory must
     * continue to be rejected.
     */
    @Test
    public void testTraversalIntoParentDirectory() throws Exception {
        Assert.assertNull(fileStore.load(TRAVERSAL_INTO_PARENT_DIR));

        fileStore.remove(TRAVERSAL_INTO_PARENT_DIR);
        Assert.assertTrue("Session file outside the storage directory was removed",
                outsideSessionFile.isFile());
    }


    /**
     * Sessions that really are inside the storage directory must still be
     * loaded and removed.
     */
    @Test
    public void testSessionInsideStorageDirectory() throws Exception {
        Assert.assertNotNull(fileStore.load(VALID_SESSION_ID));

        fileStore.remove(VALID_SESSION_ID);
        Assert.assertFalse("Session file inside the storage directory was not removed",
                validSessionFile.exists());
    }
}
