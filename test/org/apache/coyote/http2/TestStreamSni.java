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
package org.apache.coyote.http2;

import org.junit.Assert;
import org.junit.Test;

import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.tomcat.util.net.SSLHostConfig;

/**
 * Tests that the HTTP/2 <code>:authority</code> pseudo header is matched with
 * the SNI host name used for the TLS handshake.
 *
 * <p>
 * Without that matching a client can complete the TLS handshake against the
 * <code>SSLHostConfig</code> of one virtual host - for example one that does
 * not request a client certificate - and then send HTTP/2 requests for a
 * different virtual host that is protected by a <code>SSLHostConfig</code>
 * that does require one.
 */
public class TestStreamSni {

    private static Http2UpgradeHandler createHandler(final String sniHostName, boolean sslEnabled,
            boolean strictSni) {
        Http11NioProtocol http11Protocol = new Http11NioProtocol();
        http11Protocol.setSSLEnabled(sslEnabled);
        // A default configuration is always present when SSL is in use
        addSslHostConfig(http11Protocol, http11Protocol.getDefaultSSLHostConfigName());
        addSslHostConfig(http11Protocol, "localhost");
        addSslHostConfig(http11Protocol, "foobar");
        if (!strictSni) {
            Assert.assertTrue(http11Protocol.setProperty("strictSni", "false"));
        }

        Http2Protocol http2Protocol = new Http2Protocol();
        http2Protocol.setHttp11Protocol(http11Protocol);

        return new Http2UpgradeHandler(http2Protocol, null, null) {
            @Override
            String getSniHostName() {
                // The SNI host name the client sent in the TLS handshake
                return sniHostName;
            }
        };
    }


    private static void addSslHostConfig(Http11NioProtocol protocol, String hostName) {
        SSLHostConfig sslHostConfig = new SSLHostConfig();
        sslHostConfig.setHostName(hostName);
        protocol.addSslHostConfig(sslHostConfig);
    }


    private static Stream startRequest(Http2UpgradeHandler handler) throws Exception {
        Stream stream = new Stream(Integer.valueOf(1), handler);
        stream.receivedStartOfHeaders(true);
        stream.emitHeader(":method", "GET");
        stream.emitHeader(":scheme", "https");
        stream.emitHeader(":path", "/");
        return stream;
    }


    @Test
    public void testHttp2ProtocolIsNestedUnderHttp11Protocol() {
        Http11NioProtocol http11Protocol = new Http11NioProtocol();
        Http2Protocol http2Protocol = new Http2Protocol();
        http2Protocol.setHttp11Protocol(http11Protocol);
        Assert.assertSame(http11Protocol, http2Protocol.getHttp11Protocol());
    }


    /**
     * The vulnerability. The TLS handshake selects the SSLHostConfig for
     * [localhost] but the request then claims to be for the virtual host
     * [foobar] which has a different - potentially more strictly protected -
     * SSLHostConfig. This has to be rejected.
     */
    @Test
    public void testAuthorityDoesNotMatchSniIsRejected() throws Exception {
        Stream stream = startRequest(createHandler("localhost", true, true));
        try {
            stream.emitHeader(":authority", "foobar");
            Assert.fail("The :authority [foobar] must not be accepted with the SNI host name [localhost]");
        } catch (HpackException expected) {
            // Expected
        }
    }


    @Test
    public void testAuthorityWithPortDoesNotMatchSniIsRejected() throws Exception {
        Stream stream = startRequest(createHandler("localhost", true, true));
        try {
            stream.emitHeader(":authority", "foobar:8443");
            Assert.fail("The :authority [foobar:8443] must not be accepted with the SNI host name [localhost]");
        } catch (HpackException expected) {
            // Expected
        }
    }


    /**
     * The same bypass, but attempted without sending SNI at all so that the
     * connection uses the default SSLHostConfig.
     */
    @Test
    public void testNoSniAndAuthorityIsNotTheDefaultConfigIsRejected() throws Exception {
        Stream stream = startRequest(createHandler(null, true, true));
        try {
            stream.emitHeader(":authority", "foobar");
            Assert.fail("The :authority [foobar] must not be accepted without SNI");
        } catch (HpackException expected) {
            // Expected
        }
    }


    @Test
    public void testAuthorityMatchesSniIsAllowed() throws Exception {
        Stream stream = startRequest(createHandler("localhost", true, true));
        stream.emitHeader(":authority", "localhost:8443");
        Assert.assertEquals("localhost", stream.getCoyoteRequest().serverName().toString());
        Assert.assertEquals(8443, stream.getCoyoteRequest().getServerPort());

        // Host names are not case sensitive
        stream = startRequest(createHandler("LocalHost", true, true));
        stream.emitHeader(":authority", "localhost");
        Assert.assertEquals("localhost", stream.getCoyoteRequest().serverName().toString());
    }


    @Test
    public void testHostHeaderDoesNotMatchSniIsRejected() throws Exception {
        // No :authority so the Host header is the authority
        Stream stream = startRequest(createHandler("localhost", true, true));
        try {
            stream.emitHeader("host", "foobar");
            Assert.fail("The Host [foobar] must not be accepted with the SNI host name [localhost]");
        } catch (HpackException expected) {
            // Expected
        }
    }

    @Test
    public void testHostHeaderMatchesSniIsAllowed() throws Exception {
        Stream stream = startRequest(createHandler("localhost", true, true));
        stream.emitHeader("host", "localhost:8443");
        Assert.assertEquals("localhost", stream.getCoyoteRequest().serverName().toString());
        Assert.assertEquals(8443, stream.getCoyoteRequest().getServerPort());
        // The Host header is still a request header
        Assert.assertEquals("localhost:8443", stream.getCoyoteRequest().getMimeHeaders().getHeader("host"));
    }

    @Test
    public void testAuthorityIsUsedWhenHostIsAlsoPresent() throws Exception {
        Stream stream = startRequest(createHandler("localhost", true, true));
        stream.emitHeader(":authority", "localhost");
        // Not used as the authority and so not matched with the SNI host name
        stream.emitHeader("host", "foobar");
        Assert.assertEquals("localhost", stream.getCoyoteRequest().serverName().toString());
    }

    @Test
    public void testSameSslHostConfigIsAllowed() throws Exception {
        // Neither name has a dedicated configuration so both use the default
        Stream stream = startRequest(createHandler("unknown1", true, true));
        stream.emitHeader(":authority", "unknown2");
        Assert.assertEquals("unknown2", stream.getCoyoteRequest().serverName().toString());
    }


    @Test
    public void testStrictSniDisabled() throws Exception {
        // The check is opt-out for users that relied on the old behaviour
        Stream stream = startRequest(createHandler("localhost", true, false));
        stream.emitHeader(":authority", "foobar");
        Assert.assertEquals("foobar", stream.getCoyoteRequest().serverName().toString());
    }


    @Test
    public void testNotSslEnabled() throws Exception {
        // Nothing to check on a plain text (h2c) connection
        Stream stream = startRequest(createHandler(null, false, true));
        stream.emitHeader(":authority", "foobar");
        Assert.assertEquals("foobar", stream.getCoyoteRequest().serverName().toString());
    }
}
