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

import org.junit.Test;
import org.wildfly.security.auth.server.SecurityDomain;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;

import static org.junit.Assert.assertTrue;

import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;


import org.junit.AfterClass;
import org.junit.BeforeClass;

/**
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class BasicAuthenticationTest {

    private static final int PORT = 7776;

    private static SecurityDomain securityDomain;

    private static EventLoopGroup parentGroup;
    private static EventLoopGroup childGroup;
    private static Channel channel;

    @BeforeClass
    public static void setUp() throws Exception {
        securityDomain = createSecurityDomain();

        parentGroup = new NioEventLoopGroup(1);
        childGroup = new NioEventLoopGroup(1);

        ServerBootstrap bootstrap = new ServerBootstrap();
        bootstrap.option(ChannelOption.SO_BACKLOG, 1024);
        bootstrap.group(parentGroup, childGroup)
            .channel(NioServerSocketChannel.class)
            .handler(new LoggingHandler(LogLevel.INFO))
            .childHandler(new TestInitialiser(securityDomain));

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
    public void performTest() {
        assertTrue("Computer says no", false);
    }

    private static SecurityDomain createSecurityDomain() {
        return SecurityDomain.builder()
            .build();
    }

}
