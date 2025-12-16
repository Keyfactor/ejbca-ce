/*
 * Copyright (c) 2009-2012 David Grant
 * Copyright (c) 2010 ThruPoint Ltd
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
package org.jscep.transport.request;

/**
 * This class represents a <code>GetCACaps</code> request.
 * 
 * @author David Grant
 */
public final class GetCaCapsRequest extends Request {
    private final String profile;

    /**
     * Creates a new {@code GetCaCapsRequest} without a CA profile.
     */
    public GetCaCapsRequest() {
        this(null);
    }

    /**
     * Creates a new {@code GetCaCapsRequest} with the given CA profile.
     * 
     * @param profile
     *            the CA profile to use.
     */
    public GetCaCapsRequest(final String profile) {
        super(Operation.GET_CA_CAPS);
        this.profile = profile;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getMessage() {
        if (profile == null) {
            return "";
        }
        return profile;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        if (profile != null) {
            return "GetCACaps(" + profile + ")";
        } else {
            return "GetCACaps";
        }
    }
}
