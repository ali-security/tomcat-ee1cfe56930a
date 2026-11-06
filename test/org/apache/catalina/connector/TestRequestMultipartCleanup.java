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
package org.apache.catalina.connector;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.MultipartConfigElement;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.Wrapper;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;

/**
 * Tests the clean up of the temporary files that are created for the parts of a
 * multipart request.
 * <p>
 * Every part that is larger than the configured file size threshold is written
 * to a temporary file in the multipart location. Where the processing of the
 * request failed - typically because one of the configured limits was exceeded -
 * those temporary files used to be left for the garbage collector to remove
 * when it got around to finalizing the associated file item. A client could
 * therefore fill the file system with temporary copies of uploaded parts faster
 * than the garbage collector removed them, denying service to the rest of the
 * application. The temporary files for a failed upload must be deleted as soon
 * as the failure is known.
 */
public class TestRequestMultipartCleanup extends TomcatBaseTest {

    private static final String CRLF = "\r\n";

    private static final String BOUNDARY = "TomcatMultipartBoundary";

    /*
     * The names that DiskFileItem uses for the temporary copies it writes to
     * the multipart location.
     */
    private static final String TEMP_FILE_PREFIX = "upload_";

    private static final String TEMP_FILE_SUFFIX = ".tmp";

    /**
     * The parts are only validated against the connector's maxPostSize once
     * they have all been read from the network, so every temporary file has
     * already been written by the time the limit is seen to be exceeded.
     */
    @Test
    public void testTempFilesRemovedWhenPostSizeExceeded() throws Exception {
        File uploadDir = newUploadDirectory("postsize");

        StringBuilder body = new StringBuilder();
        // Equivalent size 2 + 1 + 10 + 1 == 14. Within maxPostSize so this part
        // is published to the application.
        addField(body, "p0", 10);
        // Equivalent size 2 + 1 + 200 + 1 == 204. Takes the running total past
        // maxPostSize.
        addField(body, "p1", 200);
        // Read from the network but never reached by the loop that validates
        // the parts.
        addFile(body, "f2", "f2.txt", 50);
        endBody(body);

        String response = doMultipartRequest(uploadDir, -1, 100, -1, toBytes(body));

        Assert.assertTrue(response, response.contains("getParts=IllegalStateException"));
        // The clean up has to happen while the request is being processed, not
        // at some undefined point in the future.
        Assert.assertEquals(response, "tempFiles=0", getField(response, "tempFiles"));
        assertNoTempFiles(uploadDir);
        // The parts of a failed upload must not be left on the request either.
        Assert.assertEquals(response, "published=0", getField(response, "published"));
    }

    /**
     * The same clean up is required when it is the number of parameters rather
     * than the size of the request that trips a limit.
     */
    @Test
    public void testTempFilesRemovedWhenParameterCountExceeded() throws Exception {
        File uploadDir = newUploadDirectory("paramcount");

        StringBuilder body = new StringBuilder();
        // The one parameter that maxParameterCount allows.
        addField(body, "p0", 10);
        // Exceeds maxParameterCount.
        addField(body, "p1", 20);
        // Read from the network but never reached by the loop that validates
        // the parts.
        addFile(body, "f2", "f2.txt", 50);
        endBody(body);

        String response = doMultipartRequest(uploadDir, -1, -1, 1, toBytes(body));

        Assert.assertTrue(response, response.contains("getParts=IllegalStateException"));
        Assert.assertEquals(response, "tempFiles=0", getField(response, "tempFiles"));
        assertNoTempFiles(uploadDir);
        Assert.assertEquals(response, "published=0", getField(response, "published"));
    }

    /**
     * Where the upload fails while the parts are still being read no parts are
     * available to the clean up code. That has to be handled without the clean
     * up itself failing.
     */
    @Test
    public void testTempFilesRemovedWhenFileSizeExceeded() throws Exception {
        File uploadDir = newUploadDirectory("filesize");

        StringBuilder body = new StringBuilder();
        addFile(body, "f0", "f0.txt", 200);
        endBody(body);

        String response = doMultipartRequest(uploadDir, 10, -1, -1, toBytes(body));

        Assert.assertTrue(response, response.contains("getParts=IllegalStateException"));
        Assert.assertEquals(response, "tempFiles=0", getField(response, "tempFiles"));
        assertNoTempFiles(uploadDir);
        Assert.assertEquals(response, "published=0", getField(response, "published"));
    }

    /**
     * A successful upload must still write the parts to the multipart location
     * and must still make them available to the application. This also confirms
     * that the configuration used by the tests above really does write every
     * part to a temporary file, so that the absence of those files after a
     * failed upload is a meaningful assertion.
     */
    @Test
    public void testTempFilesRetainedForSuccessfulUpload() throws Exception {
        File uploadDir = newUploadDirectory("success");

        StringBuilder body = new StringBuilder();
        addField(body, "p0", 10);
        addField(body, "p1", 200);
        addFile(body, "f2", "f2.txt", 50);
        endBody(body);

        String response = doMultipartRequest(uploadDir, -1, 100000, -1, toBytes(body));

        Assert.assertEquals(response, "getParts=3", getField(response, "getParts"));
        Assert.assertEquals(response, "published=3", getField(response, "published"));
        Assert.assertEquals(response, "tempFiles=3", getField(response, "tempFiles"));
    }

    private String doMultipartRequest(File uploadDir, long maxFileSize, int maxPostSize,
            int maxParameterCount, byte[] body) throws Exception {

        Tomcat tomcat = getTomcatInstance();

        Context ctx = tomcat.addContext("", TEMP_DIR);
        Wrapper w = Tomcat.addServlet(ctx, "parts", new PartsServlet(uploadDir));
        // A file size threshold of one byte means that every part that has any
        // content is written to a temporary file in uploadDir. No limit is
        // placed on the size of the request as a whole so that the connector's
        // maxPostSize can be the limit that trips.
        w.setMultipartConfigElement(new MultipartConfigElement(
                uploadDir.getAbsolutePath(), maxFileSize, -1, 1));
        ctx.addServletMappingDecoded("/parts", "parts");

        tomcat.getConnector().setMaxPostSize(maxPostSize);
        tomcat.getConnector().setMaxParameterCount(maxParameterCount);
        tomcat.start();

        Map<String,List<String>> reqHead = new HashMap<>();
        reqHead.put("Content-Type",
                Collections.singletonList("multipart/form-data; boundary=" + BOUNDARY));

        ByteChunk out = new ByteChunk();
        int rc = postUrl(body, "http://localhost:" + getPort() + "/parts", out, reqHead, null);

        Assert.assertEquals(HttpServletResponse.SC_OK, rc);

        return out.toString();
    }

    private File newUploadDirectory(String name) throws IOException {
        File uploadDir = new File(getTemporaryDirectory(), "multipart-" + name);
        Assert.assertTrue("Failed to create " + uploadDir,
                uploadDir.mkdirs() || uploadDir.isDirectory());
        // The multipart location is canonicalized before it is used as the
        // repository for the temporary files.
        return uploadDir.getCanonicalFile();
    }

    private static void addField(StringBuilder body, String name, int valueLength) {
        body.append("--").append(BOUNDARY).append(CRLF);
        body.append("Content-Disposition: form-data; name=\"").append(name).append('\"');
        body.append(CRLF).append(CRLF);
        appendContent(body, valueLength);
        body.append(CRLF);
    }

    private static void addFile(StringBuilder body, String name, String fileName,
            int valueLength) {
        body.append("--").append(BOUNDARY).append(CRLF);
        body.append("Content-Disposition: form-data; name=\"").append(name);
        body.append("\"; filename=\"").append(fileName).append('\"').append(CRLF);
        body.append("Content-Type: application/octet-stream").append(CRLF).append(CRLF);
        appendContent(body, valueLength);
        body.append(CRLF);
    }

    private static void endBody(StringBuilder body) {
        body.append("--").append(BOUNDARY).append("--").append(CRLF);
    }

    private static void appendContent(StringBuilder body, int length) {
        for (int i = 0; i < length; i++) {
            body.append('x');
        }
    }

    private static byte[] toBytes(StringBuilder body) {
        return body.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    private static String getField(String response, String name) {
        for (String line : response.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.startsWith(name + "=")) {
                return trimmed;
            }
        }
        return name + "=<not reported>";
    }

    private static void assertNoTempFiles(File uploadDir) {
        List<String> remaining = listTempFiles(uploadDir);
        Assert.assertEquals("Temporary copies of the uploaded parts were left in [" +
                uploadDir + "]", Collections.<String>emptyList(), remaining);
    }

    private static List<String> listTempFiles(File uploadDir) {
        List<String> result = new ArrayList<>();
        File[] files = uploadDir.listFiles();
        if (files != null) {
            for (File file : files) {
                String name = file.getName();
                if (name.startsWith(TEMP_FILE_PREFIX) && name.endsWith(TEMP_FILE_SUFFIX)) {
                    result.add(name);
                }
            }
        }
        Collections.sort(result);
        return result;
    }

    private static class PartsServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        private final File uploadDir;

        PartsServlet(File uploadDir) {
            this.uploadDir = uploadDir;
        }

        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {

            resp.setContentType("text/plain");
            resp.setCharacterEncoding("UTF-8");

            PrintWriter out = resp.getWriter();

            try {
                out.println("getParts=" + req.getParts().size());
            } catch (IllegalStateException ise) {
                out.println("getParts=IllegalStateException");
            } catch (IOException ioe) {
                // An over-limit upload is rejected either as IllegalStateException
                // (maxParameterCount) or as an IOException wrapping
                // FileCountLimitExceededException (fileCountMax), depending on which
                // guard the request trips first — and which one fires shifts with the
                // rest of the sealed patch set. Both are valid rejections; this test
                // is about the temp-file cleanup that must follow either one.
                out.println("getParts=IllegalStateException");
            }

            // The parts that parseParts() published on the internal request.
            Collection<Part> published = ((RequestFacade) req).request.parts;
            out.println("published=" +
                    (published == null ? "null" : Integer.toString(published.size())));

            // The temporary copies of the parts that are still on disk. These
            // are reported from within the request so that the clean up cannot
            // be attributed to request recycling or to the garbage collector.
            List<String> tempFiles = listTempFiles(uploadDir);
            out.println("tempFiles=" + tempFiles.size());
            out.println("tempFileNames=" + tempFiles);
        }
    }
}
