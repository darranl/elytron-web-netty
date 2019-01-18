/*
 * Copyright 2019 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.elytron.web.netty.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.MechanismConfigurationSelector;
import org.wildfly.security.auth.server.MechanismRealmConfiguration;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.util.FilterServerMechanismFactory;
import org.wildfly.security.http.util.SecurityProviderServerMechanismFactory;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.permission.PermissionVerifier;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;

/**
 *
 * Cloned from the equivalent test under 'elytron-web-jetty' implemented by Farah Juma.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class BasicAuthenticationTest {

    private static final WildFlyElytronProvider ELYTRON_PROVIDER = new WildFlyElytronProvider();

    private static final int OK = 200;
    private static final int UNAUTHORIZED = 401;
    private static final int FORBIDDEN = 403;

    private static final String AUTHORIZATION = "Authorization";
    private static final String BASIC = "Basic";
    static final String ELYTRON_USER = "ElytronUser";
    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";
    private static final int PORT = 7776;

    private static SecurityDomain securityDomain;

    private static EventLoopGroup parentGroup;
    private static EventLoopGroup childGroup;
    private static Channel channel;

    @BeforeClass
    public static void setUp() throws Exception {
        securityDomain = createSecurityDomain();
        securityDomain.registerWithClassLoader(TestContentHandler.class.getClassLoader());

        parentGroup = new NioEventLoopGroup(1);
        childGroup = new NioEventLoopGroup(1);

        ElytronHandlers securityHandlers = ElytronHandlers.newInstance()
                .setSecurityDomain(securityDomain)
                .setFactory(createHttpAuthenticationFactory())
                .setMechanismConfigurationSelector(MechanismConfigurationSelector.constantSelector(
                        MechanismConfiguration.builder()
                                .addMechanismRealm(MechanismRealmConfiguration.builder().setRealmName("Elytron Realm").build())
                                .build()));

        ServerBootstrap bootstrap = new ServerBootstrap();
        bootstrap.option(ChannelOption.SO_BACKLOG, 1024);
        bootstrap.group(parentGroup, childGroup)
            .channel(NioServerSocketChannel.class)
            .handler(new LoggingHandler(LogLevel.INFO))
            .childHandler(new TestInitialiser(securityHandlers));

        channel = bootstrap.bind(PORT).sync().channel();
    }

    @AfterClass
    public static void tearDown() throws Exception {
        channel.close().sync();
        if (parentGroup != null) {
            parentGroup.shutdownGracefully();
            parentGroup = null;
        }

        if (childGroup != null) {
            childGroup.shutdownGracefully();
            childGroup = null;
        }
    }

    @Test
    public void testUnauthorized() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet get = new HttpGet(getURI());
        assertUnauthorizedResponse(httpClient.execute(get));
    }

    @Test
    public void testSuccessfulAuthentication() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet get = new HttpGet(getURI());

        get.addHeader(AUTHORIZATION.toString(), BASIC + " " + ByteIterator.ofBytes("alice:alice123+".getBytes(StandardCharsets.US_ASCII)).base64Encode().drainToString());

        HttpResponse result = httpClient.execute(get);
        assertEquals(OK, result.getStatusLine().getStatusCode());
        assertSuccessfulResponse(result, "alice");
    }

    @Test
    public void testFailedAuthentication() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet get = new HttpGet(getURI());

        get.addHeader(AUTHORIZATION.toString(), BASIC + " " + ByteIterator.ofBytes("alice:wrongpassword".getBytes(StandardCharsets.US_ASCII)).base64Encode().drainToString());
        assertUnauthorizedResponse(httpClient.execute(get));
    }

    // An authorization handler needs to be implemented to add this test.

    // @Test
    // public void testSuccessfulAuthenticationFailedAuthorization() throws Exception {
    // HttpClient httpClient = HttpClientBuilder.create().build();
    // HttpGet get = new HttpGet(getURI());
    //
    // get.addHeader(AUTHORIZATION.toString(), BASIC + " " +
    // ByteIterator.ofBytes("bob:bob123+".getBytes(StandardCharsets.US_ASCII)).base64Encode().drainToString());
    // assertEquals(FORBIDDEN, httpClient.execute(get).getStatusLine().getStatusCode());
    // }

    private URI getURI() throws Exception {
        return new URI("http", null, "localhost", PORT, null, null, null);
    }

    private void assertUnauthorizedResponse(HttpResponse result) {
        assertEquals(UNAUTHORIZED, result.getStatusLine().getStatusCode());

        Header wwwAuthenticateHeader = result.getFirstHeader(WWW_AUTHENTICATE);
        assertNotNull(wwwAuthenticateHeader);
        assertEquals("Basic realm=\"Elytron Realm\"", wwwAuthenticateHeader.getValue());
    }

    private void assertSuccessfulResponse(HttpResponse result, String expectedUserName) {
        Header[] values = result.getHeaders(ELYTRON_USER);
        assertEquals(1, values.length);
        assertEquals(expectedUserName, values[0].getValue());
    }

    private static SecurityDomain createSecurityDomain() throws Exception {

        // Create an Elytron map-backed security realm
        SimpleMapBackedSecurityRealm simpleRealm = new SimpleMapBackedSecurityRealm(() -> new Provider[] { ELYTRON_PROVIDER });
        Map<String, SimpleRealmEntry> identityMap = new HashMap<>();

        // Add user alice
        identityMap.put("alice", new SimpleRealmEntry(getCredentialsForClearPassword("alice123+"), getAttributesForRoles("employee", "admin")));

        // Add user bob
        identityMap.put("bob", new SimpleRealmEntry(getCredentialsForClearPassword("bob123+"), getAttributesForRoles("employee")));
        simpleRealm.setIdentityMap(identityMap);

        // Add the map-backed security realm to a new security domain's list of realms
        SecurityDomain.Builder builder = SecurityDomain.builder()
                .addRealm("ExampleRealm", simpleRealm).build()
                .setPermissionMapper((principal, roles) -> PermissionVerifier.from(new LoginPermission()))
                .setDefaultRealmName("ExampleRealm");

        return builder.build();
    }

    private static HttpServerAuthenticationMechanismFactory createHttpAuthenticationFactory() {
        HttpServerAuthenticationMechanismFactory factory = new SecurityProviderServerMechanismFactory(() -> new Provider[] { ELYTRON_PROVIDER });

        return  new FilterServerMechanismFactory(factory, true, "BASIC");
    }

    private static List<Credential> getCredentialsForClearPassword(String clearPassword) throws Exception {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(ALGORITHM_CLEAR, ELYTRON_PROVIDER);
        return Collections.singletonList(new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec(clearPassword.toCharArray()))));
    }

    private static MapAttributes getAttributesForRoles(String... roles) {
        MapAttributes attributes = new MapAttributes();
        HashSet<String> rolesSet = new HashSet<>();
        if (roles != null) {
            for (String role : roles) {
                rolesSet.add(role);
            }
        }
        attributes.addAll(RoleDecoder.KEY_ROLES, rolesSet);
        return attributes;
    }

}
