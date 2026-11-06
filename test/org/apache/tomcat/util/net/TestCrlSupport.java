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
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.SSLException;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;

@RunWith(Parameterized.class)
public class TestCrlSupport extends TomcatBaseTest {

    @Parameters(name = "{0} with OpenSSL trust {2}, revoked cert {4}, CRL {5}")
    public static Collection<Object[]> parameters() {
        List<Object[]> parameterSets = new ArrayList<>();
        for (Boolean clientCertificateIsRevoked : booleans) {
            for (Boolean crlIsPopulated : booleans) {
                parameterSets.add(new Object[] { "JSSE", Boolean.FALSE, Boolean.FALSE,
                        "org.apache.tomcat.util.net.jsse.JSSEImplementation", clientCertificateIsRevoked, crlIsPopulated});
                parameterSets.add(new Object[] { "OpenSSL", Boolean.TRUE, Boolean.TRUE,
                        "org.apache.tomcat.util.net.openssl.OpenSSLImplementation", clientCertificateIsRevoked, crlIsPopulated });
                parameterSets.add(new Object[] { "OpenSSL", Boolean.TRUE, Boolean.FALSE,
                        "org.apache.tomcat.util.net.openssl.OpenSSLImplementation", clientCertificateIsRevoked, crlIsPopulated });
            }
        }

        return parameterSets;
    }

    @Parameter(0)
    public String connectorName;

    @Parameter(1)
    public boolean useOpenSSL;

    @Parameter(2)
    public boolean useOpenSSLTrust;

    @Parameter(3)
    public String sslImplementationName;

    @Parameter(4)
    public boolean clientCertificateIsRevoked;

    @Parameter(5)
    public boolean crlIsPopulated;


    @Override
    public void setUp() throws Exception {
        super.setUp();
        Tomcat tomcat = getTomcatInstance();
        TesterSupport.configureSSLImplementation(tomcat, sslImplementationName, useOpenSSL);
        TesterSupport.configureClientCertContext(tomcat, useOpenSSLTrust, TesterSupport.CLIENT_JKS, TesterSupport.CLIENT_CRL_JKS);
        if (tomcat.getConnector().getProtocolHandlerClassName().contains("Apr")) {
            /*
             * The APR connector only verifies a client certificate obtained via
             * renegotiation (CLIENT-CERT authentication) if client certificate
             * verification is enabled for the connector. Request the client
             * certificate during the initial handshake so it is always verified
             * against the trusted CA and the CRL.
             */
            tomcat.getConnector().findSslHostConfigs()[0].setCertificateVerification("optional");
        }
        // Configure the CRL
        if (crlIsPopulated) {
            tomcat.getConnector().findSslHostConfigs()[0].setCertificateRevocationListFile(
                    new File(TesterSupport.POPULATED_CRL).getAbsolutePath());
        } else {
            tomcat.getConnector().findSslHostConfigs()[0].setCertificateRevocationListFile(
                    new File(TesterSupport.EMPTY_CRL).getAbsolutePath());
        }
    }


    @Test
    public void testCrlClient() throws Exception {
        if (clientCertificateIsRevoked) {
            TesterSupport.configureClientSsl(false, TesterSupport.CLIENT_CRL_JKS);
        } else {
            TesterSupport.configureClientSsl(false, TesterSupport.CLIENT_JKS);
        }

        getTomcatInstance().start();

        // Protected resource
        String body;
        try {
            ByteChunk res = getUrl("https://localhost:" + getPort() + "/protected");
            body = res.toString();
        } catch (SSLException | SocketException e) {
            // May be observed when client certificate is rejected
            body = "FAILED";
        }

        if (!clientCertificateIsRevoked || !crlIsPopulated) {
            Assert.assertEquals("OK-" + TesterSupport.ROLE, body);
        } else {
            Assert.assertFalse(body, body.startsWith("OK-"));
        }
    }
}
