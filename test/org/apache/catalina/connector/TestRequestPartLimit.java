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

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.MultipartConfigElement;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.Wrapper;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;

/**
 * Tests the two limits added for CVE-2025-48988 to protect against multipart
 * denial of service: {@code maxPartCount} bounds the total number of parts in a
 * multipart request and {@code maxPartHeaderSize} bounds the number of header
 * bytes permitted per part.
 */
public class TestRequestPartLimit extends TomcatBaseTest {

    private static final String CRLF = "\r\n";

    private static final String BOUNDARY = "TomcatMultipartBoundary";

    /**
     * A multipart request with more parts than {@code maxPartCount} must be
     * rejected even though it is within {@code maxParameterCount}.
     */
    @Test
    public void testMaxPartCountExceeded() throws Exception {
        StringBuilder body = new StringBuilder();
        // Five parts. maxPartCount is set to 2 below, so this is over the limit.
        addField(body, "p0", 5);
        addField(body, "p1", 5);
        addField(body, "p2", 5);
        addField(body, "p3", 5);
        addField(body, "p4", 5);
        endBody(body);

        // maxParameterCount left generous (large) so the part count is the
        // limit that trips. maxPartCount = 2, maxPartHeaderSize left generous.
        String response = doMultipartRequest(1000, 2, 8192, toBytes(body));

        Assert.assertFalse("Request with too many parts must be rejected: " + response,
                response.contains("getParts=OK"));
        Assert.assertTrue(response, response.contains("getParts=rejected"));
    }

    /**
     * A multipart request within {@code maxPartCount} must be accepted.
     */
    @Test
    public void testMaxPartCountNotExceeded() throws Exception {
        StringBuilder body = new StringBuilder();
        addField(body, "p0", 5);
        addField(body, "p1", 5);
        endBody(body);

        String response = doMultipartRequest(1000, 5, 8192, toBytes(body));

        Assert.assertTrue("Request within the part-count limit must be accepted: " + response,
                response.contains("getParts=OK"));
        Assert.assertTrue(response, response.contains("partCount=2"));
    }

    /**
     * A multipart request with a part whose headers exceed
     * {@code maxPartHeaderSize} must be rejected.
     */
    @Test
    public void testMaxPartHeaderSizeExceeded() throws Exception {
        StringBuilder body = new StringBuilder();
        // A single part whose header section is padded well beyond the small
        // maxPartHeaderSize configured below.
        addFieldWithLongHeader(body, "p0", 5, 400);
        endBody(body);

        // maxPartHeaderSize = 128; the padded header above is larger than that.
        String response = doMultipartRequest(1000, 100, 128, toBytes(body));

        Assert.assertFalse("Request with oversized part headers must be rejected: " + response,
                response.contains("getParts=OK"));
        Assert.assertTrue(response, response.contains("getParts=rejected"));
    }

    /**
     * A multipart request whose part headers are within
     * {@code maxPartHeaderSize} must be accepted.
     */
    @Test
    public void testMaxPartHeaderSizeNotExceeded() throws Exception {
        StringBuilder body = new StringBuilder();
        addField(body, "p0", 5);
        endBody(body);

        String response = doMultipartRequest(1000, 100, 512, toBytes(body));

        Assert.assertTrue("Request within the part-header-size limit must be accepted: " + response,
                response.contains("getParts=OK"));
        Assert.assertTrue(response, response.contains("partCount=1"));
    }

    /**
     * {@code maxPartCount} must still bound the number of parts when
     * {@code maxParameterCount} is unlimited.
     */
    @Test
    public void testMaxPartCountExceededParameterCountUnlimited() throws Exception {
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < 5; i++) {
            addField(body, "p" + i, 5);
        }
        endBody(body);

        String response = doMultipartRequest(-1, 2, 8192, toBytes(body));

        Assert.assertFalse("Request with too many parts must be rejected: " + response,
                response.contains("getParts=OK"));
        Assert.assertTrue(response, response.contains("getParts=rejected"));
    }

    /**
     * With the default connector configuration a request with more than 50
     * parts must be rejected.
     */
    @Test
    public void testDefaultMaxPartCountExceeded() throws Exception {
        Assert.assertEquals(50, getTomcatInstance().getConnector().getMaxPartCount());

        StringBuilder body = new StringBuilder();
        for (int i = 0; i < 51; i++) {
            addField(body, "p" + i, 5);
        }
        endBody(body);

        String response = doMultipartRequest(toBytes(body));

        Assert.assertFalse("Request with too many parts must be rejected: " + response,
                response.contains("getParts=OK"));
        Assert.assertTrue(response, response.contains("getParts=rejected"));
    }

    /**
     * With the default connector configuration a request with exactly 50 parts
     * must be accepted.
     */
    @Test
    public void testDefaultMaxPartCountNotExceeded() throws Exception {
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < 50; i++) {
            addField(body, "p" + i, 5);
        }
        endBody(body);

        String response = doMultipartRequest(toBytes(body));

        Assert.assertTrue("Request within the default part-count limit must be accepted: " +
                response, response.contains("getParts=OK"));
        Assert.assertTrue(response, response.contains("partCount=50"));
    }

    /**
     * With the default connector configuration a part whose headers exceed 512
     * bytes must be rejected.
     */
    @Test
    public void testDefaultMaxPartHeaderSizeExceeded() throws Exception {
        Assert.assertEquals(512, getTomcatInstance().getConnector().getMaxPartHeaderSize());

        StringBuilder body = new StringBuilder();
        addFieldWithLongHeader(body, "p0", 5, 1024);
        endBody(body);

        String response = doMultipartRequest(toBytes(body));

        Assert.assertFalse("Request with oversized part headers must be rejected: " + response,
                response.contains("getParts=OK"));
        Assert.assertTrue(response, response.contains("getParts=rejected"));
    }

    private String doMultipartRequest(int maxParameterCount, int maxPartCount,
            int maxPartHeaderSize, byte[] body) throws Exception {

        Tomcat tomcat = getTomcatInstance();

        tomcat.getConnector().setMaxParameterCount(maxParameterCount);
        tomcat.getConnector().setMaxPartCount(maxPartCount);
        tomcat.getConnector().setMaxPartHeaderSize(maxPartHeaderSize);

        return doMultipartRequest(body);
    }

    private String doMultipartRequest(byte[] body) throws Exception {

        Tomcat tomcat = getTomcatInstance();

        Context ctx = tomcat.addContext("", TEMP_DIR);
        Wrapper w = Tomcat.addServlet(ctx, "parts", new PartsServlet());
        // No file-size, request-size or per-servlet parameter limits so that the
        // connector limits under test are the ones that trip.
        w.setMultipartConfigElement(new MultipartConfigElement(
                TEMP_DIR, -1, -1, -1));
        ctx.addServletMappingDecoded("/parts", "parts");

        tomcat.start();

        Map<String,List<String>> reqHead = new HashMap<>();
        reqHead.put("Content-Type",
                Collections.singletonList("multipart/form-data; boundary=" + BOUNDARY));

        ByteChunk out = new ByteChunk();
        postUrl(body, "http://localhost:" + getPort() + "/parts", out, reqHead, null);

        return out.toString();
    }

    private static void addField(StringBuilder body, String name, int valueLength) {
        body.append("--").append(BOUNDARY).append(CRLF);
        body.append("Content-Disposition: form-data; name=\"").append(name).append('\"');
        body.append(CRLF).append(CRLF);
        appendContent(body, valueLength);
        body.append(CRLF);
    }

    private static void addFieldWithLongHeader(StringBuilder body, String name,
            int valueLength, int headerPadding) {
        body.append("--").append(BOUNDARY).append(CRLF);
        body.append("Content-Disposition: form-data; name=\"").append(name).append('\"');
        body.append(CRLF);
        // A custom, oversized header to push the header section past the limit.
        body.append("X-Padding: ");
        appendContent(body, headerPadding);
        body.append(CRLF).append(CRLF);
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

    private static class PartsServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {

            resp.setContentType("text/plain");
            resp.setCharacterEncoding("UTF-8");

            PrintWriter out = resp.getWriter();

            try {
                int count = req.getParts().size();
                out.println("getParts=OK");
                out.println("partCount=" + count);
            } catch (IllegalStateException ise) {
                // maxPartHeaderSize exceeded surfaces as a SizeException wrapped
                // in an IllegalStateException.
                out.println("getParts=rejected");
                out.println("reason=IllegalStateException");
            } catch (IOException ioe) {
                // maxPartCount exceeded surfaces as a FileUploadException wrapped
                // in an IOException.
                out.println("getParts=rejected");
                out.println("reason=IOException");
            }
        }
    }
}
