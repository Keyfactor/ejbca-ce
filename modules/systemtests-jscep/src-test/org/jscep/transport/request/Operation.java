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
package org.jscep.transport.request;

/**
 * This enum represents the different types of transaction operations in SCEP.
 * 
 * @author David Grant
 */
public enum Operation {
    /**
     * The operation for {@code GetCACaps}.
     * 
     * @see <a
     *      href="http://tools.ietf.org/html/draft-nourse-scep-20#appendix-C.1">SCEP
     *      Internet-Draft Reference</a>
     */
    GET_CA_CAPS("GetCACaps"),
    /**
     * The operation for {@code GetCACert}.
     * 
     * @see <a
     *      href="http://tools.ietf.org/html/draft-nourse-scep-20#section-5.2.1">SCEP
     *      Internet-Draft Reference</a>
     */
    GET_CA_CERT("GetCACert"),
    /**
     * The operation for {@code GetNextCACert}.
     * 
     * @see <a
     *      href="http://tools.ietf.org/html/draft-nourse-scep-20#section-5.2.6">SCEP
     *      Internet-Draft Reference</a>
     */
    GET_NEXT_CA_CERT("GetNextCACert"),
    /**
     * The operation for {@code PKCSReq}, {@code GetCertInitial},
     * {@code GetCert} and {@code GetCRL}.
     * 
     * @see <a
     *      href="http://tools.ietf.org/html/draft-nourse-scep-20#section-5.2.2">SCEP
     *      Internet-Draft Reference</a>
     * @see <a
     *      href="http://tools.ietf.org/html/draft-nourse-scep-20#section-5.2.3">SCEP
     *      Internet-Draft Reference</a>
     * @see <a
     *      href="http://tools.ietf.org/html/draft-nourse-scep-20#section-5.2.4">SCEP
     *      Internet-Draft Reference</a>
     * @see <a
     *      href="http://tools.ietf.org/html/draft-nourse-scep-20#section-5.2.5">SCEP
     *      Internet-Draft Reference</a>
     */
    PKI_OPERATION("PKIOperation");

    private final String name;

    private Operation(final String name) {
        this.name = name;
    }

    /**
     * Returns the protocol-specific name for this operation.
     * 
     * @return the protocol-specific name for this operation.
     */
    public String getName() {
        return name;
    }

    /**
     * Returns the corresponding {@code Operation} instance for the provided
     * name.
     * <p>
     * If the provided name is not one of:
     * <ul>
     * <li>{@code GetCACaps};</li>
     * <li>{@code GetCACert};</li>
     * <li>{@code GetNextCACert}; or</li>
     * <li>{@code PKIOperation}</li>
     * </ul>
     * then this method will throw an {@link IllegalArgumentException}.
     * 
     * @param name
     *            the protocol-specific name.
     * @return the corresponding {@code Operation}
     */
    public static Operation forName(final String name) {
        if (name == null) {
            throw new NullPointerException();
        }
        for (Operation op : Operation.values()) {
            if (op.name.equals(name)) {
                return op;
            }
        }
        throw new IllegalArgumentException(name + " not found");
    }
}
