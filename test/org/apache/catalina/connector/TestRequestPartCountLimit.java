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
 * Tests that the number of parts in a multipart request is limited by the
 * connector's maxParameterCount (CVE-2023-24998). Previously only the parts
 * without a file name were counted (as parameters) and that count was only
 * checked once every part had been read, so a request made up of a very large
 * number of file parts was parsed in full regardless of maxParameterCount.
 */
public class TestRequestPartCountLimit extends TomcatBaseTest {

    private static final String CRLF = "\r\n";

    private static final String BOUNDARY = "TomcatPartCountBoundary";

    @Test
    public void testFilePartsOverLimitRejected() throws Exception {
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < 3; i++) {
            addFile(body, "f" + i);
        }
        endBody(body);

        String response = doMultipartRequest(2, null, toBytes(body));

        assertRejected(response);
    }

    @Test
    public void testManyFilePartsRejected() throws Exception {
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            addFile(body, "f" + i);
        }
        endBody(body);

        String response = doMultipartRequest(10, null, toBytes(body));

        assertRejected(response);
    }

    @Test
    public void testFilePartsAtLimitAccepted() throws Exception {
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < 3; i++) {
            addFile(body, "f" + i);
        }
        endBody(body);

        String response = doMultipartRequest(3, null, toBytes(body));

        Assert.assertEquals(response, "getParts=3", getField(response, "getParts"));
    }

    @Test
    public void testFilePartsNoLimit() throws Exception {
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < 20; i++) {
            addFile(body, "f" + i);
        }
        endBody(body);

        String response = doMultipartRequest(-1, null, toBytes(body));

        Assert.assertEquals(response, "getParts=20", getField(response, "getParts"));
    }

    @Test
    public void testFieldsAndFilePartsOverLimitRejected() throws Exception {
        StringBuilder body = new StringBuilder();
        addField(body, "p0");
        addFile(body, "f1");
        addFile(body, "f2");
        endBody(body);

        String response = doMultipartRequest(2, null, toBytes(body));

        assertRejected(response);
    }

    @Test
    public void testFieldsAtLimitAccepted() throws Exception {
        StringBuilder body = new StringBuilder();
        addField(body, "p0");
        addField(body, "p1");
        endBody(body);

        String response = doMultipartRequest(2, null, toBytes(body));

        Assert.assertEquals(response, "getParts=2", getField(response, "getParts"));
    }

    @Test
    public void testQueryParametersReducePartLimit() throws Exception {
        StringBuilder body = new StringBuilder();
        addFile(body, "f0");
        addFile(body, "f1");
        endBody(body);

        // Two query parameters plus two parts exceeds the limit of three
        String response = doMultipartRequest(3, "q0=a&q1=b", toBytes(body));

        assertRejected(response);
    }

    @Test
    public void testQueryParametersAndPartsAtLimitAccepted() throws Exception {
        StringBuilder body = new StringBuilder();
        addFile(body, "f0");
        endBody(body);

        String response = doMultipartRequest(3, "q0=a&q1=b", toBytes(body));

        Assert.assertEquals(response, "getParts=1", getField(response, "getParts"));
    }

    private static void assertRejected(String response) {
        Assert.assertEquals(response, "getParts=IOException", getField(response, "getParts"));
        Assert.assertEquals(response, "cause=FileCountLimitExceededException",
                getField(response, "cause"));
    }

    private String doMultipartRequest(int maxParameterCount, String query, byte[] body)
            throws Exception {

        Tomcat tomcat = getTomcatInstance();

        Context ctx = tomcat.addContext("", TEMP_DIR);
        Wrapper w = Tomcat.addServlet(ctx, "parts", new PartsServlet());
        w.setMultipartConfigElement(new MultipartConfigElement(
                getTemporaryDirectory().getAbsolutePath(), -1, -1, 1024));
        ctx.addServletMappingDecoded("/parts", "parts");

        tomcat.getConnector().setMaxParameterCount(maxParameterCount);
        tomcat.start();

        Map<String,List<String>> reqHead = new HashMap<>();
        reqHead.put("Content-Type",
                Collections.singletonList("multipart/form-data; boundary=" + BOUNDARY));

        String path = "http://localhost:" + getPort() + "/parts";
        if (query != null) {
            path = path + "?" + query;
        }

        ByteChunk out = new ByteChunk();
        int rc = postUrl(body, path, out, reqHead, null);

        Assert.assertEquals(HttpServletResponse.SC_OK, rc);

        return out.toString();
    }

    private static void addField(StringBuilder body, String name) {
        body.append("--").append(BOUNDARY).append(CRLF);
        body.append("Content-Disposition: form-data; name=\"").append(name).append('\"');
        body.append(CRLF).append(CRLF);
        body.append("value-").append(name);
        body.append(CRLF);
    }

    private static void addFile(StringBuilder body, String name) {
        body.append("--").append(BOUNDARY).append(CRLF);
        body.append("Content-Disposition: form-data; name=\"").append(name);
        body.append("\"; filename=\"").append(name).append(".txt\"").append(CRLF);
        body.append("Content-Type: application/octet-stream").append(CRLF).append(CRLF);
        body.append("content-").append(name);
        body.append(CRLF);
    }

    private static void endBody(StringBuilder body) {
        body.append("--").append(BOUNDARY).append("--").append(CRLF);
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

    private static class PartsServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {

            resp.setContentType("text/plain");
            resp.setCharacterEncoding("UTF-8");

            PrintWriter out = resp.getWriter();

            try {
                // Trigger the normal parameter parsing first so the query
                // string parameters are counted before the parts are parsed.
                req.getParameter("q0");
                out.println("getParts=" + req.getParts().size());
            } catch (IOException | IllegalStateException e) {
                out.println("getParts=" + e.getClass().getSimpleName());
                Throwable cause = e.getCause();
                out.println("cause=" +
                        (cause == null ? "null" : cause.getClass().getSimpleName()));
            }
        }
    }
}
