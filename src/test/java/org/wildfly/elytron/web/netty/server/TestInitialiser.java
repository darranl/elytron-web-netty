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

import java.security.Provider;

import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.util.FilterServerMechanismFactory;
import org.wildfly.security.http.util.SecurityProviderServerMechanismFactory;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpServerExpectContinueHandler;

/**
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class TestInitialiser extends ChannelInitializer<SocketChannel> {

    private final SecurityDomain securityDomain;

    TestInitialiser(final SecurityDomain securityDomain) {
        this.securityDomain = securityDomain;
    }

    @Override
    protected void initChannel(SocketChannel ch) throws Exception {
        ChannelPipeline pipeline = ch.pipeline();
        pipeline.addLast(new HttpServerCodec());
        pipeline.addLast(new HttpServerExpectContinueHandler());
        // TODO - Here we want to insert the full set of Elytron handlers in one, ideally using some API.
        HttpServerAuthenticationMechanismFactory providerFactory = new SecurityProviderServerMechanismFactory(() -> new Provider[] {new WildFlyElytronProvider()});
        HttpServerAuthenticationMechanismFactory httpServerMechanismFactory = new FilterServerMechanismFactory(providerFactory, true, "BASIC");
        HttpAuthenticationFactory httpAuthenticationFactory = HttpAuthenticationFactory.builder()
                .setSecurityDomain(securityDomain)
                .setFactory(httpServerMechanismFactory)
                .build();
        ElytronInboundHandler inboundHandler = new ElytronInboundHandler(httpAuthenticationFactory, null);
        ElytronOutboundHandler outboundHandler = new ElytronOutboundHandler();
        ElytronRunAsHandler runAsHandler = new ElytronRunAsHandler(inboundHandler::getSecurityIdentity);

        pipeline.addLast(outboundHandler);
        pipeline.addLast(inboundHandler);
        pipeline.addLast(runAsHandler);

        pipeline.addLast(new TestContentHandler(securityDomain));
    }

}
