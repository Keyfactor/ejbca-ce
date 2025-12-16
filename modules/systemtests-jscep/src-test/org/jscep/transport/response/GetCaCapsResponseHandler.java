/*
 * Copyright (c) 2009-2010 David Grant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jscep.transport.response;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;

import net.jcip.annotations.ThreadSafe;

import static java.nio.charset.StandardCharsets.US_ASCII;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class handles responses to <code>GetCACaps</code> requests.
 *
 * @author David Grant
 */
@ThreadSafe
public final class GetCaCapsResponseHandler implements
        ScepResponseHandler<Capabilities> {
    private static final String TEXT_PLAIN = "text/plain";
    private static final Logger LOGGER = LoggerFactory
            .getLogger(GetCaCapsResponseHandler.class);

    /**
     * {@inheritDoc}
     *
     * @throws InvalidContentTypeException if the response is invalid
     */
    @Override
    public Capabilities getResponse(final byte[] content, final String mimeType)
            throws ContentException {
        if (mimeType == null || !mimeType.startsWith(TEXT_PLAIN)) {
            LOGGER.warn(
                    "Content-Type mismatch: was '{}', expected 'text/plain'",
                    mimeType);
        }

        final EnumSet<Capability> caps = EnumSet.noneOf(Capability.class);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("CA capabilities:");
        }
        BufferedReader reader = new BufferedReader(new InputStreamReader(
                new ByteArrayInputStream(content),
                Charset.forName(US_ASCII.name())));
        Set<String> caCaps = new HashSet<String>();
        String capability;
        try {
            while ((capability = reader.readLine()) != null) {
                caCaps.add(capability);
            }
        } catch (IOException e) {
            throw new InvalidContentTypeException(e);
        } finally {
            try {
                reader.close();
            } catch (IOException e) {
                LOGGER.error("Error closing reader", e);
            }
        }

        for (Capability enumValue : Capability.values()) {
            if (caCaps.contains(enumValue.toString())) {
                LOGGER.debug("[\u2713] {}", enumValue.getDescription());
                caps.add(enumValue);
            } else {
                LOGGER.debug("[\u2717] {}", enumValue.getDescription());
            }
        }

        return new Capabilities(caps.toArray(new Capability[caps.size()]));
    }
}
