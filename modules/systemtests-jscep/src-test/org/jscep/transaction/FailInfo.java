/*
 * Copyright (c) 2009-2010 David Grant
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
package org.jscep.transaction;

/**
 * This class represents the SCEP <code>failInfo</code> attribute.
 * 
 * @author David Grant
 */
public enum FailInfo {
    /**
     * Unrecognized or unsupported algorithm identifier.
     */
    badAlg(0),
    /**
     * Integrity check failed.
     */
    badMessageCheck(1),
    /**
     * Transaction not permitted or supported.
     */
    badRequest(2),
    /**
     * The signingTime attribute from the PKCS#7 SignedAttributes was not
     * sufficiently close to the system time.
     */
    badTime(3),
    /**
     * No certificate could be identified matching the provided criteria.
     */
    badCertId(4);

    private final int value;

    private FailInfo(final int value) {
        this.value = value;
    }

    /**
     * Returns the protocol-specific value for this {@code failInfo}
     * 
     * @return the protocol-specific value.
     */
    public int getValue() {
        return value;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return name();
    }

    /**
     * Returns the {@code failInfo} for the given value.
     * <p>
     * If the provided value is not 0-4 inclusive, this method throws an
     * {@link IllegalArgumentException}
     * 
     * @param value
     *            the {@code failInfo} value.
     * @return the corresponding {@code failInfo}
     */
    public static FailInfo valueOf(final int value) {
        for (FailInfo failInfo : FailInfo.values()) {
            if (failInfo.getValue() == value) {
                return failInfo;
            }
        }
        // Fall back to bad request (see issue 39).
        return FailInfo.badRequest;
    }
}
