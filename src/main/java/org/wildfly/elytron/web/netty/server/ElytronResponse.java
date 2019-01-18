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

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * At the time authentication is performed we don't have access to a response object to manipulate, this response object is used
 * to cache any manipulation to apply later.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ElytronResponse {

    private final List<Header> headers = new ArrayList<>();
    private volatile ByteArrayOutputStream outputStream;
    private volatile int statusCode;

    void setStatusCode(final int statusCode) {
        this.statusCode = statusCode;
    }

    int getStatusCode() {
        return statusCode;
    }

    void addHeader(final String name, final String value) {
        headers.add(new Header(name, value));
    }

    OutputStream getOutputStream() {
        if (outputStream == null) {
            outputStream = new ByteArrayOutputStream();
        }

        return outputStream;
    }

    byte[] getResponseBytes() {
        if (outputStream != null) {
            return outputStream.toByteArray();
        }

        return null;
    }

    List<Header> getHeaders() {
        return headers;
    }

    static class Header {
        private final String name;
        private final String value;

        Header(final String name, final String value) {
            this.name = name;
            this.value = value;
        }

        String getName() {
            return name;
        }

        String getValue() {
            return value;
        }

    }

}
