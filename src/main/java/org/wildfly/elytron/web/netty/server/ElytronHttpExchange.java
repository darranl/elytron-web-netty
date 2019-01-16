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

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpExchangeSpi;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerCookie;
import org.wildfly.security.http.Scope;

import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpServerCodec;

/**
 * An implementation of {@link HttpExchangeSpi} compatible with the APIs used by {@link HttpServerCodec}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ElytronHttpExchange implements HttpExchangeSpi {

    private final HttpRequest httpRequest;

    private volatile SecurityIdentity securityIdentity;

    ElytronHttpExchange(final HttpRequest httpRequest) {
        this.httpRequest = httpRequest;
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

    /* (non-Javadoc)
     * @see org.wildfly.security.http.HttpExchangeSpi#getRequestHeaderValues(java.lang.String)
     */
    @Override
    public List<String> getRequestHeaderValues(String headerName) {
        // TODO Auto-generated method stub
        return null;
    }

    /* (non-Javadoc)
     * @see org.wildfly.security.http.HttpExchangeSpi#getRequestMethod()
     */
    @Override
    public String getRequestMethod() {
        // TODO Auto-generated method stub
        return null;
    }

    /* (non-Javadoc)
     * @see org.wildfly.security.http.HttpExchangeSpi#getRequestURI()
     */
    @Override
    public URI getRequestURI() {
        // TODO Auto-generated method stub
        return null;
    }

    /* (non-Javadoc)
     * @see org.wildfly.security.http.HttpExchangeSpi#getRequestPath()
     */
    @Override
    public String getRequestPath() {
        // TODO Auto-generated method stub
        return null;
    }

    /* (non-Javadoc)
     * @see org.wildfly.security.http.HttpExchangeSpi#getRequestParameters()
     */
    @Override
    public Map<String, List<String>> getRequestParameters() {
        // TODO Auto-generated method stub
        return null;
    }

    /* (non-Javadoc)
     * @see org.wildfly.security.http.HttpExchangeSpi#getCookies()
     */
    @Override
    public List<HttpServerCookie> getCookies() {
        // TODO Auto-generated method stub
        return null;
    }

    /* (non-Javadoc)
     * @see org.wildfly.security.http.HttpExchangeSpi#getRequestInputStream()
     */
    @Override
    public InputStream getRequestInputStream() {
        // TODO Auto-generated method stub
        return null;
    }

    /* (non-Javadoc)
     * @see org.wildfly.security.http.HttpExchangeSpi#getSourceAddress()
     */
    @Override
    public InetSocketAddress getSourceAddress() {
        // TODO Auto-generated method stub
        return null;
    }

    /*
     * Response Methods
     */


    /* (non-Javadoc)
     * @see org.wildfly.security.http.HttpExchangeSpi#addResponseHeader(java.lang.String, java.lang.String)
     */
    @Override
    public void addResponseHeader(String headerName, String headerValue) {
        // TODO Auto-generated method stub

    }

    /* (non-Javadoc)
     * @see org.wildfly.security.http.HttpExchangeSpi#setStatusCode(int)
     */
    @Override
    public void setStatusCode(int statusCode) {
        // TODO Auto-generated method stub

    }

    /* (non-Javadoc)
     * @see org.wildfly.security.http.HttpExchangeSpi#setResponseCookie(org.wildfly.security.http.HttpServerCookie)
     */
    @Override
    public void setResponseCookie(HttpServerCookie cookie) {
        // TODO Auto-generated method stub

    }

    /* (non-Javadoc)
     * @see org.wildfly.security.http.HttpExchangeSpi#getResponseOutputStream()
     */
    @Override
    public OutputStream getResponseOutputStream() {
        // TODO Auto-generated method stub
        return null;
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
