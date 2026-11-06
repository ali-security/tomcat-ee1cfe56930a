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
package org.apache.catalina.realm;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;

import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.naming.NameParserImpl;
import org.apache.tomcat.unittest.TesterContext;
import org.apache.tomcat.util.security.MD5Encoder;
import org.easymock.EasyMock;

public class TestJNDIRealm {

    private static final String ALGORITHM = "MD5";

    private static final String USER = "test-user";
    private static final String PASSWORD = "test-password";
    private static final String REALM = "test-realm";

    private static final String NONCE = "test-nonce";
    private static final String HA2 = "test-md5a2";
    public static final String USER_PASSWORD_ATTR = "test-pwd";

    private static final String USER_PATTERN = "uid={0},ou=people,dc=example,dc=com";
    private static final String USER_DN = "uid=" + USER + ",ou=people,dc=example,dc=com";
    private static final String WRONG_PASSWORD = "wrong-password";

    private static MessageDigest md5Helper;

    @BeforeClass
    public static void setupClass() throws Exception {
        md5Helper = MessageDigest.getInstance(ALGORITHM);
    }

    @Test
    public void testAuthenticateWithoutUserPassword() throws Exception {
        // GIVEN
        JNDIRealm realm = buildRealm(PASSWORD);

        // WHEN
        String expectedResponse =
                MD5Encoder.encode(md5Helper.digest((ha1() + ":" + NONCE + ":" + HA2).getBytes()));
        Principal principal =
                realm.authenticate(USER, expectedResponse, NONCE, null, null, null, REALM, HA2);

        // THEN
        Assert.assertNull(principal);
    }

    @Test
    public void testAuthenticateWithUserPassword() throws Exception {
        // GIVEN
        JNDIRealm realm = buildRealm(PASSWORD);
        realm.setUserPassword(USER_PASSWORD_ATTR);

        // WHEN
        String expectedResponse =
                MD5Encoder.encode(md5Helper.digest((ha1() + ":" + NONCE + ":" + HA2).getBytes()));
        Principal principal =
                realm.authenticate(USER, expectedResponse, NONCE, null, null, null, REALM, HA2);

        // THEN
        Assert.assertTrue(principal instanceof GenericPrincipal);
        Assert.assertEquals(PASSWORD, ((GenericPrincipal)principal).getPassword());
    }

    @Test
    public void testAuthenticateWithUserPasswordAndCredentialHandler() throws Exception {
        // GIVEN
        JNDIRealm realm = buildRealm(ha1());
        realm.setCredentialHandler(buildCredentialHandler());
        realm.setUserPassword(USER_PASSWORD_ATTR);

        // WHEN
        String expectedResponse =
                MD5Encoder.encode(md5Helper.digest((ha1() + ":" + NONCE + ":" + HA2).getBytes()));
        Principal principal =
                realm.authenticate(USER, expectedResponse, NONCE, null, null, null, REALM, HA2);

        // THEN
        Assert.assertTrue(principal instanceof GenericPrincipal);
        Assert.assertEquals(ha1(), ((GenericPrincipal)principal).getPassword());
    }

    @Test
    public void testBindAsUserAuthenticationNoneWrongPassword() throws Exception {
        doTestBindAsUser("none", WRONG_PASSWORD, false);
    }

    @Test
    public void testBindAsUserAuthenticationNoneCorrectPassword() throws Exception {
        doTestBindAsUser("none", PASSWORD, true);
    }

    @Test
    public void testBindAsUserAuthenticationExternalWrongPassword() throws Exception {
        doTestBindAsUser("EXTERNAL", WRONG_PASSWORD, false);
    }

    @Test
    public void testBindAsUserAuthenticationExternalCorrectPassword() throws Exception {
        doTestBindAsUser("EXTERNAL", PASSWORD, true);
    }

    @Test
    public void testBindAsUserAuthenticationSimpleWrongPassword() throws Exception {
        doTestBindAsUser("simple", WRONG_PASSWORD, false);
    }

    @Test
    public void testBindAsUserAuthenticationSimpleCorrectPassword() throws Exception {
        doTestBindAsUser("simple", PASSWORD, true);
    }

    @Test
    public void testBindAsUserAuthenticationDefaultWrongPassword() throws Exception {
        doTestBindAsUser(null, WRONG_PASSWORD, false);
    }

    @Test
    public void testBindAsUserAuthenticationDefaultCorrectPassword() throws Exception {
        doTestBindAsUser(null, PASSWORD, true);
    }

    @Test
    public void testBindAsUserRestoresEnvironmentOnError() throws Exception {
        // GIVEN
        JNDIRealm realm = buildBindRealm("EXTERNAL");
        DirContext dirContext = getDirContext(realm);
        TesterLdapDirContext ldap = (TesterLdapDirContext) Proxy.getInvocationHandler(dirContext);
        ldap.setBindFailure(new CommunicationException("test-connection-failure"));

        // WHEN
        try {
            realm.bindAsUser(dirContext,
                    new JNDIRealm.User(USER, USER_DN, null, null, null), WRONG_PASSWORD);
            Assert.fail("Expected the bind failure to be propagated");
        } catch (CommunicationException expected) {
            // Expected
        }

        // THEN
        Assert.assertEquals(Collections.singletonList("simple"), ldap.getBindMechanisms());
        assertEnvironmentRestored(ldap, "EXTERNAL");
    }


    private void doTestBindAsUser(String authentication, String password,
            boolean expectAuthenticated) throws Exception {
        // GIVEN
        JNDIRealm realm = buildBindRealm(authentication);
        TesterLdapDirContext ldap =
                (TesterLdapDirContext) Proxy.getInvocationHandler(getDirContext(realm));

        // WHEN
        Principal principal = realm.authenticate(USER, password);

        // THEN
        if (expectAuthenticated) {
            Assert.assertTrue(principal instanceof GenericPrincipal);
            Assert.assertEquals(USER, principal.getName());
        } else {
            Assert.assertNull(principal);
        }
        // The user provided credentials must have been checked with a simple
        // bind, regardless of the configured authentication mechanism
        Assert.assertEquals(Collections.singletonList("simple"), ldap.getBindMechanisms());
        assertEnvironmentRestored(ldap, authentication);
    }


    private void assertEnvironmentRestored(TesterLdapDirContext ldap, String authentication) {
        Hashtable<Object,Object> env = ldap.getEnvironment();
        // The configured authentication mechanism must have been restored
        Assert.assertEquals(Boolean.valueOf(authentication != null),
                Boolean.valueOf(env.containsKey(javax.naming.Context.SECURITY_AUTHENTICATION)));
        Assert.assertEquals(authentication, env.get(javax.naming.Context.SECURITY_AUTHENTICATION));
        // The user's credentials must have been removed
        Assert.assertNull(env.get(javax.naming.Context.SECURITY_PRINCIPAL));
        Assert.assertNull(env.get(javax.naming.Context.SECURITY_CREDENTIALS));
    }


    private JNDIRealm buildBindRealm(String authentication) throws Exception {
        Context context = new TesterContext();
        JNDIRealm realm = new JNDIRealm();
        realm.setContainer(context);
        realm.setAuthentication(authentication);
        realm.setUserPattern(USER_PATTERN);
        realm.init();

        // Use the environment the realm would use to connect to the directory
        DirContext dirContext = (DirContext) Proxy.newProxyInstance(
                TestJNDIRealm.class.getClassLoader(), new Class<?>[] { DirContext.class },
                new TesterLdapDirContext(realm.getDirectoryContextEnvironment()));

        Field field = JNDIRealm.class.getDeclaredField("context");
        field.setAccessible(true);
        field.set(realm, dirContext);

        realm.start();

        return realm;
    }


    private DirContext getDirContext(JNDIRealm realm)
            throws NoSuchFieldException, IllegalAccessException {
        Field field = JNDIRealm.class.getDeclaredField("context");
        field.setAccessible(true);
        return (DirContext) field.get(realm);
    }


    private JNDIRealm buildRealm(String password) throws javax.naming.NamingException,
            NoSuchFieldException, IllegalAccessException, LifecycleException {
        Context context = new TesterContext();
        JNDIRealm realm = new JNDIRealm();
        realm.setContainer(context);
        realm.setUserSearch("");

        Field field = JNDIRealm.class.getDeclaredField("context");
        field.setAccessible(true);
        field.set(realm, mockDirContext(mockSearchResults(password)));

        realm.start();

        return realm;
    }

    private MessageDigestCredentialHandler buildCredentialHandler()
            throws NoSuchAlgorithmException {
        MessageDigestCredentialHandler credentialHandler = new MessageDigestCredentialHandler();
        credentialHandler.setAlgorithm(ALGORITHM);
        return credentialHandler;
    }

    private NamingEnumeration<SearchResult> mockSearchResults(String password)
            throws NamingException {
        @SuppressWarnings("unchecked")
        NamingEnumeration<SearchResult> searchResults =
                EasyMock.createNiceMock(NamingEnumeration.class);
        EasyMock.expect(Boolean.valueOf(searchResults.hasMore()))
                .andReturn(Boolean.TRUE)
                .andReturn(Boolean.FALSE)
                .andReturn(Boolean.TRUE)
                .andReturn(Boolean.FALSE);
        EasyMock.expect(searchResults.next())
                .andReturn(new SearchResult("ANY RESULT", "",
                        new BasicAttributes(USER_PASSWORD_ATTR, password)))
                .times(2);
        EasyMock.replay(searchResults);
        return searchResults;
    }

    private DirContext mockDirContext(NamingEnumeration<SearchResult> namingEnumeration)
            throws NamingException {
        DirContext dirContext = EasyMock.createNiceMock(InitialDirContext.class);
        EasyMock.expect(dirContext.search(EasyMock.anyString(), EasyMock.anyString(),
                        EasyMock.anyObject(SearchControls.class)))
                .andReturn(namingEnumeration)
                .times(2);
        EasyMock.expect(dirContext.getNameParser(""))
                .andReturn(new NameParserImpl()).times(2);
        EasyMock.expect(dirContext.getNameInNamespace())
                .andReturn("ANY NAME")
                .times(2);
        EasyMock.replay(dirContext);
        return dirContext;
    }

    private String ha1() {
        String a1 = USER + ":" + REALM + ":" + PASSWORD;
        return MD5Encoder.encode(md5Helper.digest(a1.getBytes()));
    }


    /*
     * Minimal stand-in for an LDAP DirContext. Reading the root DSE emulates
     * the bind performed by the JNDI LDAP provider: only a simple bind (the
     * default when credentials are present and no mechanism is configured)
     * checks the supplied password. A "none" bind is anonymous and an
     * "EXTERNAL" bind relies on the TLS client certificate so both succeed
     * whatever password was provided.
     */
    private static class TesterLdapDirContext implements InvocationHandler {

        private final Hashtable<Object,Object> environment = new Hashtable<>();
        private final List<Object> bindMechanisms = new ArrayList<>();
        private NamingException bindFailure = null;

        TesterLdapDirContext(Hashtable<String,String> initialEnvironment) {
            environment.putAll(initialEnvironment);
        }

        Hashtable<Object,Object> getEnvironment() {
            return environment;
        }

        List<Object> getBindMechanisms() {
            return bindMechanisms;
        }

        void setBindFailure(NamingException bindFailure) {
            this.bindFailure = bindFailure;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            switch (method.getName()) {
                case "getEnvironment":
                    return environment.clone();
                case "addToEnvironment":
                    return environment.put(args[0], args[1]);
                case "removeFromEnvironment":
                    return environment.remove(args[0]);
                case "getAttributes":
                    return bind();
                case "close":
                    return null;
                case "hashCode":
                    return Integer.valueOf(System.identityHashCode(proxy));
                case "equals":
                    return Boolean.valueOf(proxy == args[0]);
                case "toString":
                    return TesterLdapDirContext.class.getSimpleName();
                default:
                    throw new UnsupportedOperationException(method.toString());
            }
        }

        private Attributes bind() throws NamingException {
            Object mechanism = environment.get(javax.naming.Context.SECURITY_AUTHENTICATION);
            bindMechanisms.add(mechanism);
            if (bindFailure != null) {
                throw bindFailure;
            }
            if (mechanism == null || "simple".equalsIgnoreCase(mechanism.toString())) {
                if (!USER_DN.equals(environment.get(javax.naming.Context.SECURITY_PRINCIPAL)) ||
                        !PASSWORD.equals(environment.get(javax.naming.Context.SECURITY_CREDENTIALS))) {
                    throw new AuthenticationException("[LDAP: error code 49 - Invalid Credentials]");
                }
            }
            // Any other mechanism (none, EXTERNAL, ...) ignores the password
            return new BasicAttributes(true);
        }
    }
}
