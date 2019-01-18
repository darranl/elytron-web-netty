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

import java.util.function.Function;
import java.util.function.Predicate;

import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.auth.server.MechanismConfigurationSelector;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

import io.netty.channel.ChannelPipeline;
import io.netty.handler.codec.http.HttpRequest;

/**
 * Utility to insert a set of WildFly Elytron authentication handlers into the Netty pipeline.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ElytronHandlers implements Function<ChannelPipeline, ChannelPipeline> {

    private SecurityDomain securityDomain;
    private MechanismConfigurationSelector mechanismConfigurationSelector;
    private HttpServerAuthenticationMechanismFactory httpServerAuthenticationMechanismFactory;
    private Predicate<HttpRequest> authenticationRequired;

    private ElytronHandlers() {}

    /**
     * Set the {@link SecurityDomain} to use for the applied security.
     *
     * @param securityDomain the {@link SecurityDomain} to use for the applied security.
     * @return this {@link ElytronHandlers} to allow method chaining.
     */
    public ElytronHandlers setSecurityDomain(final SecurityDomain securityDomain) {
        this.securityDomain = securityDomain;

        return this;
    }

    /**
     * Set the {@link MechanismConfigurationSelector} to use for the applied security.
     *
     * @param mechanismConfigurationSelector the {@link MechanismConfigurationSelector} to use for the applied security.
     * @return this {@link ElytronHandlers} to allow method chaining.
     */
    public ElytronHandlers setMechanismConfigurationSelector(final MechanismConfigurationSelector mechanismConfigurationSelector) {
        this.mechanismConfigurationSelector = mechanismConfigurationSelector;

        return this;
    }

    /**
     * Set the {@link HttpServerAuthenticationMechanismFactory} to use for the applied security.
     *
     * @param httpServerAuthenticationMechanismFactory the {@link HttpServerAuthenticationMechanismFactory} to use for the applied security.
     * @return this {@link ElytronHandlers} to allow method chaining.
     */
    public ElytronHandlers setFactory(final HttpServerAuthenticationMechanismFactory httpServerAuthenticationMechanismFactory) {
        this.httpServerAuthenticationMechanismFactory = httpServerAuthenticationMechanismFactory;

        return this;
    }

    /**
     * Set the {@link Predicate} to determine if authentication is required for a specific request.
     *
     * @param authenticationRequired the {@link Predicate} to determine if authentication is required for a specific request.
     * @return this {@link ElytronHandlers} to allow method chaining.
     */
    public ElytronHandlers setAuthenticationRequired(final Predicate<HttpRequest> authenticationRequired) {
        this.authenticationRequired = authenticationRequired;

        return this;
    }

    /**
     * Apply the configuration defined here to the provided {@link ChannelPipeline}.
     *
     * The instance can be cached and used to configure multiple pipelines.
     *
     * @param pipeline the {@link ChannelPipeline} to apply the security configuration to.
     */
    public ChannelPipeline apply(ChannelPipeline pipeline) {
        HttpAuthenticationFactory httpAuthenticationFactory = HttpAuthenticationFactory.builder()
                .setSecurityDomain(securityDomain)
                .setFactory(httpServerAuthenticationMechanismFactory)
                .setMechanismConfigurationSelector(mechanismConfigurationSelector)
                .build();
        ElytronInboundHandler inboundHandler = new ElytronInboundHandler(httpAuthenticationFactory, authenticationRequired);
        ElytronOutboundHandler outboundHandler = new ElytronOutboundHandler(inboundHandler::getElytronResponse);
        ElytronRunAsHandler runAsHandler = new ElytronRunAsHandler(inboundHandler::getSecurityIdentity);

        pipeline.addLast(outboundHandler);
        pipeline.addLast(inboundHandler);
        pipeline.addLast(runAsHandler);

        return pipeline;
    }

    /**
     * Create a new instance of {@link ElytronHandlers} to configure a Netty {@link ChannelPipeline}.
     *
     * @return a new instance of {@link ElytronHandlers} to configure a Netty {@link ChannelPipeline}.
     */
    public static ElytronHandlers newInstance() {
        return new ElytronHandlers();
    }

}
