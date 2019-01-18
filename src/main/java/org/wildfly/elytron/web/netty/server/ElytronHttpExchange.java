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

import static org.wildfly.common.Assert.checkNotNullParam;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpExchangeSpi;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerCookie;
import org.wildfly.security.http.Scope;

import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpServerCodec;

/**
 * An implementation of {@link HttpExchangeSpi} compatible with the APIs used by {@link HttpServerCodec}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ElytronHttpExchange implements HttpExchangeSpi {

    private final HttpRequest httpRequest;
    private final ElytronResponse elytronResponse;
    private final SocketAddress remoteSocketAddress;

    private volatile SecurityIdentity securityIdentity;

    ElytronHttpExchange(final HttpRequest httpRequest, final ElytronResponse elytronResponse, final SocketAddress remoteSocketAddress) {
        this.httpRequest = checkNotNullParam("httpRequest", httpRequest);
        this.elytronResponse = checkNotNullParam("elytronResponse", elytronResponse);
        this.remoteSocketAddress = remoteSocketAddress;
    }

    /*
     * Scopes - Initially Not Supported.
     */

    @Override
    public HttpScope getScope(Scope scope) {
        return null;
    }

    @Override
    public Collection<String> getScopeIds(Scope scope) {
        return null;
    }

    @Override
    public HttpScope getScope(Scope scope, String id) {
        return null;
    }

    /*
     * Request Access Methods
     */

    @Override
    public List<String> getRequestHeaderValues(String headerName) {
        return httpRequest.headers().getAll(headerName);
    }

    @Override
    public String getRequestMethod() {
        return httpRequest.method().name();
    }

    @Override
    public URI getRequestURI() {
        try {
            return new URI(httpRequest.uri());
        } catch (URISyntaxException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String getRequestPath() {
        return getRequestURI().getPath();
    }

    @Override
    public Map<String, List<String>> getRequestParameters() {
        return Collections.emptyMap();
    }

    @Override
    public List<HttpServerCookie> getCookies() {
        return Collections.emptyList();
    }

    @Override
    public InputStream getRequestInputStream() {
        return null;
    }

    @Override
    public InetSocketAddress getSourceAddress() {
        if (remoteSocketAddress instanceof InetSocketAddress) {
            return (InetSocketAddress) remoteSocketAddress;
        }

        return null;
    }

    /*
     * Response Methods
     */


    @Override
    public void addResponseHeader(String headerName, String headerValue) {
        elytronResponse.addHeader(headerName, headerValue);
    }

    @Override
    public void setStatusCode(int statusCode) {
        elytronResponse.setStatusCode(statusCode);
    }

    @Override
    public void setResponseCookie(HttpServerCookie cookie) {
        // TODO
    }

    @Override
    public OutputStream getResponseOutputStream() {
        return elytronResponse.getOutputStream();
    }

    /*
     * Outcome Callback Methods
     */

    /* (non-Javadoc)
     * @see org.wildfly.security.http.HttpExchangeSpi#authenticationComplete(org.wildfly.security.auth.server.SecurityIdentity, java.lang.String)
     */
    @Override
    public void authenticationComplete(SecurityIdentity securityIdentity, String mechanismName) {
        this.securityIdentity = securityIdentity;
    }

    /* (non-Javadoc)
     * @see org.wildfly.security.http.HttpExchangeSpi#authenticationFailed(java.lang.String, java.lang.String)
     */
    @Override
    public void authenticationFailed(String message, String mechanismName) {
        // TODO Auto-generated method stub

    }

    /* (non-Javadoc)
     * @see org.wildfly.security.http.HttpExchangeSpi#badRequest(org.wildfly.security.http.HttpAuthenticationException, java.lang.String)
     */
    @Override
    public void badRequest(HttpAuthenticationException error, String mechanismName) {
        // TODO Auto-generated method stub

    }

    /*
     * Internal Access Methods
     */

    SecurityIdentity getSecurityIdentity() {
        return securityIdentity;
    }

}
