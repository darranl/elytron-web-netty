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

import java.util.function.Supplier;

import org.wildfly.elytron.web.netty.server.ElytronResponse.Header;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandler;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.http.HttpMessage;

/**
 * The {@link ChannelOutboundHandler} responsible for setting any headers on the outbound response.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ElytronOutboundHandler extends ChannelOutboundHandlerAdapter {

    private final Supplier<ElytronResponse> elytronResponse;

    public ElytronOutboundHandler(final Supplier<ElytronResponse> elytronResponse) {
        this.elytronResponse = elytronResponse;
    }

    @Override
    public void read(ChannelHandlerContext ctx) throws Exception {
        System.out.println("ElytronOutboundHandler.read()");
        super.read(ctx);
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        System.out.println("ElytronOutboundHandler.write()");
        ElytronResponse response;
        if (msg instanceof HttpMessage && (response = elytronResponse.get()) != null) {
            HttpMessage httpMessage = (HttpMessage) msg;
            for (Header header : response.getHeaders()) {
                httpMessage.headers().add(header.getName(), header.getValue());
            }
        }

        super.write(ctx, msg, promise);
    }

}
