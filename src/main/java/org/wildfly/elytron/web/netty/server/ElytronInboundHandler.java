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

import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpAuthenticator;

import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandler;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelOutboundHandler;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;

/**
 * A {@link ChannelInboundHandler} implementation to intercept incoming requests and ensure authentication occurs.
 *
 * This handler is only responsible for the incoming message, a separate {@link ChannelOutboundHandler} is responsible for any
 * outbound challenges.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ElytronInboundHandler extends ChannelInboundHandlerAdapter {

    private final HttpAuthenticationFactory httpAuthenticationFactory;
    private final SecurityDomain securityDomain;
    private final Predicate<HttpRequest> authenticationRequired;

    private volatile ElytronResponse elytronResponse;
    private volatile SecurityIdentity securityIdentity;

    public ElytronInboundHandler(final HttpAuthenticationFactory httpAuthenticationFactory, final Predicate<HttpRequest> authenticationRequired) {
        this.httpAuthenticationFactory = httpAuthenticationFactory;
        this.securityDomain = httpAuthenticationFactory.getSecurityDomain();
        this.authenticationRequired = authenticationRequired;

    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        System.out.println("ElytronInboundHandler.channelRead()");
        if (msg instanceof HttpRequest) {
            HttpRequest httpRequest = (HttpRequest) msg;
            boolean authenticationRequired = this.authenticationRequired != null ? this.authenticationRequired.test(httpRequest) : true;

            elytronResponse = new ElytronResponse();
            final ElytronHttpExchange elytronExchange = new ElytronHttpExchange(httpRequest, elytronResponse, ctx.channel().remoteAddress());

            HttpAuthenticator authenticator = HttpAuthenticator.builder()
                    .setSecurityDomain(securityDomain)
                    .setMechanismSupplier(() -> httpAuthenticationFactory.getMechanismNames().stream()
                            .map(mechanismName -> {
                                try {
                                    return httpAuthenticationFactory.createMechanism(mechanismName);
                                } catch (HttpAuthenticationException e) {
                                    throw new RuntimeException("Failed to create mechanism.", e);
                                }
                            })
                            .filter(m -> m != null)
                            .collect(Collectors.toList()))
                    .setHttpExchangeSpi(elytronExchange)
                    .setRequired(authenticationRequired)
                    .build();

            boolean authenticated = authenticator.authenticate();

            if (!authenticated) {
                System.out.println("ElytronInboundHandler - Lets turn this request around.");
                // Start by just turning the request around,
                byte[] responseBody = elytronResponse.getResponseBytes();
                HttpResponseStatus responseStatus = elytronResponse.getStatusCode() > 0 ? HttpResponseStatus.valueOf(elytronResponse.getStatusCode()) : HttpResponseStatus.OK;
                FullHttpResponse response = responseBody != null
                        ? new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, responseStatus, Unpooled.wrappedBuffer(responseBody))
                        : new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, responseStatus);
                ctx.write(response);
                return;
            }

            securityIdentity = elytronExchange.getSecurityIdentity();
        }

        super.channelRead(ctx, msg);
    }

    // TODO Hide these

    public SecurityIdentity getSecurityIdentity() {
        return securityIdentity;
    }

    public ElytronResponse getElytronResponse() {
        return elytronResponse;
    }

}
