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
package org.apache.tomcat.util.net;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import static org.apache.catalina.startup.SimpleHttpClient.CRLF;
import org.apache.catalina.Context;
import org.apache.catalina.Wrapper;
import org.apache.catalina.startup.SimpleHttpClient;
import org.apache.catalina.startup.TesterServlet;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.net.SSLHostConfigCertificate.Type;
import org.apache.tomcat.util.net.TesterSupport.ClientSSLSocketFactory;
import org.apache.tomcat.websocket.server.WsContextListener;

/**
 * The keys and certificates used in this file are all available in svn and were
 * generated using a test CA the files for which are in the Tomcat PMC private
 * repository since not all of them are AL2 licensed.
 */
public class TestSsl extends TomcatBaseTest {

    @Test
    public void testSimpleSsl() throws Exception {
        TesterSupport.configureClientSsl();

        Tomcat tomcat = getTomcatInstance();

        File appDir = new File(getBuildDirectory(), "webapps/examples");
        org.apache.catalina.Context ctxt  = tomcat.addWebapp(
                null, "/examples", appDir.getAbsolutePath());
        ctxt.addApplicationListener(WsContextListener.class.getName());

        TesterSupport.initSsl(tomcat);

        tomcat.start();
        ByteChunk res = getUrl("https://localhost:" + getPort() +
            "/examples/servlets/servlet/HelloWorldExample");
        Assert.assertTrue(res.toString().indexOf("<a href=\"../helloworld.html\">") > 0);
        Assert.assertTrue("Checking no client issuer has been requested",
                TesterSupport.getLastClientAuthRequestedIssuerCount() == 0);
    }

    @Test
    public void testKeyPass() throws Exception {
        TesterSupport.configureClientSsl();

        Tomcat tomcat = getTomcatInstance();

        File appDir = new File(getBuildDirectory(), "webapps/examples");
        org.apache.catalina.Context ctxt  = tomcat.addWebapp(
                null, "/examples", appDir.getAbsolutePath());
        ctxt.addApplicationListener(WsContextListener.class.getName());

        TesterSupport.initSsl(tomcat, TesterSupport.LOCALHOST_KEYPASS_JKS,
                TesterSupport.JKS_PASS, TesterSupport.JKS_KEY_PASS);

        tomcat.start();
        ByteChunk res = getUrl("https://localhost:" + getPort() +
            "/examples/servlets/servlet/HelloWorldExample");
        Assert.assertTrue(res.toString().indexOf("<a href=\"../helloworld.html\">") > 0);
        Assert.assertTrue("Checking no client issuer has been requested",
                TesterSupport.getLastClientAuthRequestedIssuerCount() == 0);
    }


    @Test
    public void testSni() throws Exception {
        System.setProperty("jsse.enableSNIExtension", "true");
        ClientSSLSocketFactory clientSSLSocketFactory = TesterSupport.configureClientSsl();
        Tomcat tomcat = getTomcatInstance();
        tomcat.getConnector().setProperty("strictSni", "true");

        File appDir = new File(getBuildDirectory(), "webapps/examples");
        Context ctxt  = tomcat.addWebapp(null, "/examples", appDir.getAbsolutePath());
        ctxt.addApplicationListener(WsContextListener.class.getName());

        TesterSupport.initSsl(tomcat);

        // Add another config for localhost
        SSLHostConfig sslHostConfig = new SSLHostConfig();
        SSLHostConfigCertificate certificate = new SSLHostConfigCertificate(sslHostConfig, Type.UNDEFINED);
        sslHostConfig.addCertificate(certificate);
        certificate.setCertificateKeystoreFile(new File(TesterSupport.LOCALHOST_RSA_JKS).getAbsolutePath());
        certificate.setCertificateKeystorePassword(TesterSupport.JKS_PASS);
        sslHostConfig.setHostName("localhost");
        tomcat.getConnector().addSslHostConfig(sslHostConfig);

        // Add another config for foobar
        sslHostConfig = new SSLHostConfig();
        certificate = new SSLHostConfigCertificate(sslHostConfig, Type.UNDEFINED);
        sslHostConfig.addCertificate(certificate);
        certificate.setCertificateKeystoreFile(new File(TesterSupport.LOCALHOST_RSA_JKS).getAbsolutePath());
        certificate.setCertificateKeystorePassword(TesterSupport.JKS_PASS);
        sslHostConfig.setHostName("foobar");
        tomcat.getConnector().addSslHostConfig(sslHostConfig);

        tomcat.start();

        // Send SNI and it matches
        SSLSocket sslSocket = (SSLSocket) clientSSLSocketFactory.createSocket("localhost", getPort());
        SNIHostName serverName = new SNIHostName("localhost");
        List<SNIServerName> serverNames = new ArrayList<>(1);
        serverNames.add(serverName);
        SSLParameters params = sslSocket.getSSLParameters();
        params.setServerNames(serverNames);
        sslSocket.setSSLParameters(params);

        Client client = new Client();
        client.setPort(getPort());

        // @formatter:off
        client.setRequest(new String[] {
                "GET /examples/servlets/servlet/HelloWorldExample HTTP/1.1" + CRLF +
                    "Host: localhost" + CRLF +
                    "Connection: Close" + CRLF +
                    CRLF
                });
        // @formatter:on
        client.connect(sslSocket);
        client.processRequest(true);

        Assert.assertEquals(HttpServletResponse.SC_OK, client.getStatusCode());
        Assert.assertTrue(client.getResponseBody().contains("<a href=\"../helloworld.html\">"));
        client.disconnect();
        client.reset();

        // Send SNI and it does not match
        sslSocket = (SSLSocket) clientSSLSocketFactory.createSocket("localhost", getPort());
        params = sslSocket.getSSLParameters();
        params.setServerNames(serverNames);
        sslSocket.setSSLParameters(params);

        // @formatter:off
        client.setRequest(new String[] {
                "GET /examples/servlets/servlet/HelloWorldExample HTTP/1.1" + CRLF +
                    "Host: foobar" + CRLF +
                    "Connection: Close" + CRLF +
                    CRLF
                });
        // @formatter:on
        client.connect(sslSocket);
        client.processRequest(true);

        Assert.assertEquals(HttpServletResponse.SC_BAD_REQUEST, client.getStatusCode());
        client.disconnect();
        client.reset();

        // Send SNI and it does not match, but this goes to the default host which is the same one
        tomcat.getConnector().setProperty("defaultSSLHostConfigName", "localhost");
        sslSocket = (SSLSocket) clientSSLSocketFactory.createSocket("localhost", getPort());
        params = sslSocket.getSSLParameters();
        params.setServerNames(serverNames);
        sslSocket.setSSLParameters(params);

        // @formatter:off
        client.setRequest(new String[] {
                "GET /examples/servlets/servlet/HelloWorldExample HTTP/1.1" + CRLF +
                    "Host: something" + CRLF +
                    "Connection: Close" + CRLF +
                    CRLF
                });
        // @formatter:on
        client.connect(sslSocket);
        client.processRequest(true);

        Assert.assertEquals(HttpServletResponse.SC_OK, client.getStatusCode());
        client.disconnect();
        client.reset();
        tomcat.getConnector().setProperty("defaultSSLHostConfigName", "_default_");

        tomcat.getConnector().setProperty("strictSni", "false");

        // SNI is not verified
        sslSocket = (SSLSocket) clientSSLSocketFactory.createSocket("localhost", getPort());
        params = sslSocket.getSSLParameters();
        params.setServerNames(serverNames);
        sslSocket.setSSLParameters(params);

        // @formatter:off
        client.setRequest(new String[] {
                "GET /examples/servlets/servlet/HelloWorldExample HTTP/1.1" + CRLF +
                    "Host: foobar" + CRLF +
                    "Connection: Close" + CRLF +
                    CRLF
                });
        // @formatter:on
        client.connect(sslSocket);
        client.processRequest(true);

        Assert.assertEquals(HttpServletResponse.SC_OK, client.getStatusCode());
        client.disconnect();
        client.reset();

        tomcat.getConnector().setProperty("strictSni", "true");

        // No SNI but this is the default config
        tomcat.getConnector().setProperty("defaultSSLHostConfigName", "localhost");
        Assert.assertEquals(HttpServletResponse.SC_OK,
                getUrl("https://localhost:" + getPort() + "/examples/servlets/servlet/HelloWorldExample",
                        new ByteChunk(), null));

        // No SNI and this is not the default config
        tomcat.getConnector().setProperty("defaultSSLHostConfigName", "_default_");
        Assert.assertEquals(HttpServletResponse.SC_BAD_REQUEST,
                getUrl("https://localhost:" + getPort() + "/examples/servlets/servlet/HelloWorldExample",
                        new ByteChunk(), null));

    }

    private static final class Client extends SimpleHttpClient {

        @Override
        public boolean isResponseBodyOK() {
            return true;
        }

    }


    @Test
    public void testRenegotiateWorks() throws Exception {
        Tomcat tomcat = getTomcatInstance();

        Assume.assumeTrue("SSL renegotiation has to be supported for this test",
                TesterSupport.isClientRenegotiationSupported(getTomcatInstance()));

        Context root = tomcat.addContext("", TEMP_DIR);
        Wrapper w =
            Tomcat.addServlet(root, "tester", new TesterServlet());
        w.setAsyncSupported(true);
        root.addServletMappingDecoded("/", "tester");

        TesterSupport.initSsl(tomcat);

        tomcat.start();

        SSLContext sslCtx;
        if (TesterSupport.isDefaultTLSProtocolForTesting13(tomcat.getConnector())) {
            // Force TLS 1.2 if TLS 1.3 is available as JSSE's TLS 1.3
            // implementation doesn't support Post Handshake Authentication
            // which is required for this test to pass.
            sslCtx = SSLContext.getInstance(Constants.SSL_PROTO_TLSv1_2);
        } else {
            sslCtx = SSLContext.getInstance(Constants.SSL_PROTO_TLS);
        }
        sslCtx.init(null, TesterSupport.getTrustManagers(), null);
        SSLSocketFactory socketFactory = sslCtx.getSocketFactory();
        SSLSocket socket = (SSLSocket) socketFactory.createSocket("localhost",
                getPort());

        OutputStream os = socket.getOutputStream();
        InputStream is = socket.getInputStream();
        Reader r = new InputStreamReader(is);

        doRequest(os, r);
        Assert.assertTrue("Checking no client issuer has been requested",
                TesterSupport.getLastClientAuthRequestedIssuerCount() == 0);

        TesterHandshakeListener listener = new TesterHandshakeListener();
        socket.addHandshakeCompletedListener(listener);

        socket.startHandshake();

        doRequest(os, r);
        // Handshake complete appears to be called asynchronously
        int wait = 0;
        while (wait < 5000 && !listener.isComplete()) {
            wait += 50;
            Thread.sleep(50);
        }
        Assert.assertTrue("Checking no client issuer has been requested",
                TesterSupport.getLastClientAuthRequestedIssuerCount() == 0);
        Assert.assertTrue(listener.isComplete());
        System.out.println("Renegotiation completed after " + wait + " ms");
    }

    private void doRequest(OutputStream os, Reader r) throws IOException {
        char[] expectedResponseLine = "HTTP/1.1 200 \r\n".toCharArray();

        os.write("GET /tester HTTP/1.1\r\n".getBytes());
        os.write("Host: localhost\r\n".getBytes());
        os.write("Connection: Keep-Alive\r\n\r\n".getBytes());
        os.flush();

        // First check we get the expected response line
        for (char c : expectedResponseLine) {
            int read = r.read();
            Assert.assertEquals(c, read);
        }

        // Skip to the end of the headers
        char[] endOfHeaders ="\r\n\r\n".toCharArray();
        int found = 0;
        while (found != endOfHeaders.length) {
            if (r.read() == endOfHeaders[found]) {
                found++;
            } else {
                found = 0;
            }
        }

        // Read the body
        char[] expectedBody = "OK".toCharArray();
        for (char c : expectedBody) {
            int read = r.read();
            Assert.assertEquals(c, read);
        }
    }

    private static class TesterHandshakeListener implements HandshakeCompletedListener {

        private volatile boolean complete = false;

        @Override
        public void handshakeCompleted(HandshakeCompletedEvent event) {
            complete = true;
        }

        public boolean isComplete() {
            return complete;
        }
    }
}
