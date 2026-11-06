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
package org.apache.catalina.servlets;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import static org.apache.catalina.startup.SimpleHttpClient.CRLF;
import org.apache.catalina.Context;
import org.apache.catalina.Wrapper;
import org.apache.catalina.startup.SimpleHttpClient;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.websocket.server.WsContextListener;

public class TestWebdavServlet extends TomcatBaseTest {

    // @formatter:off
    private static final String LOCK_BODY =
            "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n" +
            "<D:lockinfo xmlns:D='DAV:'>\n" +
            "  <D:lockscope><D:exclusive/></D:lockscope>\n" +
            "  <D:locktype><D:write/></D:locktype>\n" +
            "  <D:owner>someone</D:owner>\n" +
            "</D:lockinfo>";

    private static final String PROPFIND_PROP =
            "<?xml version=\"1.0\" encoding=\"utf-8\" ?> \n" +
            "<D:propfind xmlns:D=\"DAV:\">\n" +
            "  <D:prop>\n" +
            "    <D:getcontenttype/>\n" +
            "    <T:customprop xmlns:T=\"http://tomcat.apache.org/testsuite\"/>\n" +
            "    <T:othercustomprop xmlns:T=\"http://tomcat.apache.org/testsuite\"/>\n" +
            "    <D:getcontentlength/>\n" +
            "  </D:prop>\n" +
            "</D:propfind>";
    // @formatter:on

    /*
     * Test attempting to access special paths (WEB-INF/META-INF) using WebdavServlet
     */
    @Test
    public void testGetSpecials() throws Exception {
        Tomcat tomcat = getTomcatInstance();

        String contextPath = "/examples";

        File appDir = new File(getBuildDirectory(), "webapps" + contextPath);
        // app dir is relative to server home
        org.apache.catalina.Context ctx =
            tomcat.addWebapp(null, "/examples", appDir.getAbsolutePath());

        Tomcat.addServlet(ctx, "webdav", new WebdavServlet());
        ctx.addServletMappingDecoded("/*", "webdav");

        tomcat.start();

        final ByteChunk res = new ByteChunk();

        int rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/WEB-INF/web.xml", res, null);
        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);

        rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/WEB-INF/doesntexistanywhere", res, null);
        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);

        rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/WEB-INF/", res, null);
        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);

        rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/META-INF/MANIFEST.MF", res, null);
        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);

        rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/META-INF/doesntexistanywhere", res, null);
        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);

    }

    /*
     * Test https://bz.apache.org/bugzilla/show_bug.cgi?id=50026
     * Verify protection of special paths with re-mount of web app resource root.
     */
    @Test
    public void testGetWithSubpathmount() throws Exception {
        Tomcat tomcat = getTomcatInstance();

        String contextPath = "/examples";

        File appDir = new File(getBuildDirectory(), "webapps" + contextPath);
        // app dir is relative to server home
        org.apache.catalina.Context ctx =
            tomcat.addWebapp(null, "/examples", appDir.getAbsolutePath());

        Tomcat.addServlet(ctx, "webdav", new WebdavServlet());
        ctx.addServletMappingDecoded("/webdav/*", "webdav");
        ctx.addApplicationListener(WsContextListener.class.getName());

        tomcat.start();

        final ByteChunk res = new ByteChunk();

        // Make sure WebdavServlet isn't exposing special directories
        // by remounting the webapp under a sub-path

        int rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/webdav/WEB-INF/web.xml", res, null);

        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);
        rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/webdav/WEB-INF/doesntexistanywhere", res, null);
        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);

        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);
        rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/webdav/WEB-INF/", res, null);
        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);

        rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/webdav/META-INF/MANIFEST.MF", res, null);
        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);

        rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/webdav/META-INF/doesntexistanywhere", res, null);
        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);

        // Make sure WebdavServlet is serving resources
        // relative to the map/mount point
        final ByteChunk rootResource = new ByteChunk();
        rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/index.html", rootResource, null);
        Assert.assertEquals(HttpServletResponse.SC_OK, rc);

        final ByteChunk subpathResource = new ByteChunk();
        rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/webdav/index.html", subpathResource, null);
        Assert.assertEquals(HttpServletResponse.SC_OK, rc);

        Assert.assertEquals(rootResource.toString(), subpathResource.toString());

        rc =getUrl("http://localhost:" + getPort() + contextPath +
                "/webdav/static/index.html", res, null);
        Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);

    }

    public static int getUrl(String path, ByteChunk out,
            Map<String, List<String>> resHead) throws IOException {
        out.recycle();
        return TomcatBaseTest.getUrl(path, out, resHead);
    }


    /*
     * Only tests LOCK bodies exceeding limit. Other tests cover valid LOCK bodies.
     */
    @Test
    public void testLockBodyLimit() throws Exception {
        doTestLimit("LOCK", LOCK_BODY);
    }


    /*
     * Only tests PROPFIND bodies exceeding limit. Other tests cover valid PROPFIND bodies.
     */
    @Test
    public void testPropFindBodyLimit() throws Exception {
        doTestLimit("PROPFIND", PROPFIND_PROP);
    }


    private void doTestLimit(String method, String requestBody) throws Exception {

        Tomcat tomcat = getTomcatInstance();

        File appDir = new File("test/webapp");
        Context ctxt = tomcat.addContext("", appDir.getAbsolutePath());

        Wrapper webdavServlet = Tomcat.addServlet(ctxt, "webdav", new WebdavServlet());
        webdavServlet.addInitParameter("listings", "true");
        webdavServlet.addInitParameter("secret", "foo");
        webdavServlet.addInitParameter("readonly", "false");
        webdavServlet.addInitParameter("maxRequestBodySize", "10");

        ctxt.addServletMappingDecoded("/*", "webdav");
        tomcat.start();

        // With content length
        Client client = new Client();
        client.setPort(getPort());

        // @formatter:off
        client.setRequest(new String[] {
                method + " / HTTP/1.1" + CRLF +
                    "Host: localhost:" + getPort() + CRLF +
                    "Content-Length: " + requestBody.length() + CRLF +
                    "Connection: Close" + CRLF +
                    CRLF +
                    requestBody
                });
        // @formatter:on
        client.connect();
        client.processRequest(true);
        Assert.assertEquals(WebdavStatus.SC_REQUEST_TOO_LONG, client.getStatusCode());

        // Without content length
        client.reset();

        // @formatter:off
        client.setRequest(new String[] {
                method + " / HTTP/1.1" + CRLF +
                    "Host: localhost:" + getPort() + CRLF +
                    "Transfer-Encoding: chunked" + CRLF +
                    "Connection: Close" + CRLF +
                    CRLF +
                    Integer.toHexString(requestBody.length()) + CRLF +
                    requestBody + CRLF +
                    "0" + CRLF +
                    CRLF
                });
        // @formatter:on
        client.connect();
        client.processRequest(true);
        Assert.assertEquals(WebdavStatus.SC_REQUEST_TOO_LONG, client.getStatusCode());
    }


    private static final class Client extends SimpleHttpClient {

        @Override
        public boolean isResponseBodyOK() {
            return true;
        }
    }

}
