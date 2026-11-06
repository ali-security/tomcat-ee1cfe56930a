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

import org.junit.Assert;
import org.junit.Test;

/**
 * Unit tests for {@link AbstractEndpoint#checkSni(String, String)}, the SNI
 * host name to protocol (HTTP <code>Host</code> header / HTTP/2
 * <code>:authority</code>) host name matching.
 *
 * <p>
 * Without that matching a client can complete the TLS handshake against the
 * <code>SSLHostConfig</code> of one virtual host - for example one that does
 * not request a client certificate - and then send an HTTP request for a
 * different virtual host that is protected by a <code>SSLHostConfig</code>
 * that does require one. These tests run without any TLS handshake so they are
 * independent of the (expired) test key stores.
 */
public class TestAbstractEndpointSni {

    private static AbstractEndpoint<?,?> createEndpoint(boolean sslEnabled) {
        NioEndpoint endpoint = new NioEndpoint();
        endpoint.setSSLEnabled(sslEnabled);
        // A default configuration is always present when SSL is in use
        addSslHostConfig(endpoint, SSLHostConfig.DEFAULT_SSL_HOST_NAME);
        return endpoint;
    }


    private static void addSslHostConfig(AbstractEndpoint<?,?> endpoint, String hostName) {
        SSLHostConfig sslHostConfig = new SSLHostConfig();
        sslHostConfig.setHostName(hostName);
        endpoint.addSslHostConfig(sslHostConfig);
    }


    @Test
    public void testStrictSniEnabledByDefault() {
        // The protection has to be on unless it is explicitly disabled
        Assert.assertTrue(createEndpoint(true).getStrictSni());
    }


    /**
     * The vulnerability. The TLS handshake selects the SSLHostConfig for
     * [localhost] but the request then claims to be for the virtual host
     * [foobar] which has a different - potentially more strictly protected -
     * SSLHostConfig. This has to be rejected.
     */
    @Test
    public void testSniDoesNotMatchHostIsRejected() {
        AbstractEndpoint<?,?> endpoint = createEndpoint(true);
        addSslHostConfig(endpoint, "localhost");
        addSslHostConfig(endpoint, "foobar");

        Assert.assertFalse(endpoint.checkSni("localhost", "foobar"));
        Assert.assertFalse(endpoint.checkSni("foobar", "localhost"));
    }


    /**
     * The same bypass, but attempted without sending SNI at all so that the
     * connection uses the default SSLHostConfig.
     */
    @Test
    public void testNoSniAndHostIsNotTheDefaultConfigIsRejected() {
        AbstractEndpoint<?,?> endpoint = createEndpoint(true);
        addSslHostConfig(endpoint, "localhost");
        addSslHostConfig(endpoint, "foobar");

        Assert.assertFalse(endpoint.checkSni(null, "foobar"));

        // Unless that non default configuration is made the default one
        endpoint.setDefaultSSLHostConfigName("foobar");
        Assert.assertTrue(endpoint.checkSni(null, "foobar"));
    }


    @Test
    public void testSniMatchesHostIsAllowed() {
        AbstractEndpoint<?,?> endpoint = createEndpoint(true);
        addSslHostConfig(endpoint, "localhost");
        addSslHostConfig(endpoint, "foobar");

        Assert.assertTrue(endpoint.checkSni("localhost", "localhost"));
        // Host names are not case sensitive
        Assert.assertTrue(endpoint.checkSni("LOCALHOST", "localhost"));
        Assert.assertTrue(endpoint.checkSni("localhost", "LocalHost"));
    }


    @Test
    public void testSameSslHostConfigIsAllowed() {
        AbstractEndpoint<?,?> endpoint = createEndpoint(true);
        addSslHostConfig(endpoint, "localhost");

        // Neither name has a dedicated configuration so both use the default
        Assert.assertTrue(endpoint.checkSni("unknown1", "unknown2"));
        // No SNI and the host uses the default configuration
        Assert.assertTrue(endpoint.checkSni(null, "unknown"));

        // Both names match the same wildcard configuration
        addSslHostConfig(endpoint, "*.example.com");
        Assert.assertTrue(endpoint.checkSni("a.example.com", "b.example.com"));
        // But the wildcard configuration is not the one used for [localhost]
        Assert.assertFalse(endpoint.checkSni("a.example.com", "localhost"));
    }


    /**
     * The third scenario of the connector configuration: SNI and host do not
     * match but both are served by the same (default) configuration.
     */
    @Test
    public void testNonDefaultDefaultSslHostConfigName() {
        AbstractEndpoint<?,?> endpoint = createEndpoint(true);
        addSslHostConfig(endpoint, "localhost");
        addSslHostConfig(endpoint, "foobar");
        endpoint.setDefaultSSLHostConfigName("localhost");

        // [something] has no configuration of its own so it falls back to the
        // default which is the same configuration the SNI host name selected
        Assert.assertTrue(endpoint.checkSni("localhost", "something"));
        // [foobar] still has its own configuration
        Assert.assertFalse(endpoint.checkSni("localhost", "foobar"));
    }


    @Test
    public void testStrictSniDisabled() {
        AbstractEndpoint<?,?> endpoint = createEndpoint(true);
        addSslHostConfig(endpoint, "localhost");
        addSslHostConfig(endpoint, "foobar");
        endpoint.setStrictSni(false);

        // The check is opt-out for users that relied on the old behaviour
        Assert.assertTrue(endpoint.checkSni("localhost", "foobar"));
        Assert.assertTrue(endpoint.checkSni(null, "foobar"));
    }


    @Test
    public void testNotSslEnabled() {
        AbstractEndpoint<?,?> endpoint = createEndpoint(false);

        // Nothing to check on a plain text connector
        Assert.assertTrue(endpoint.checkSni(null, "foobar"));
        Assert.assertTrue(endpoint.checkSni("localhost", "foobar"));
    }
}
