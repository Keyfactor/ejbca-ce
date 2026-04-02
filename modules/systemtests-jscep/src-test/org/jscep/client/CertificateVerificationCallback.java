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
package org.jscep.client;

import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.callback.Callback;

/**
 * This class is used to obtain verification of a CA certificate.
 *
 * @author David Grant
 */
public final class CertificateVerificationCallback implements Callback {
    /**
     * The certificate to verify.
     */
    private final X509Certificate caCertificate;
    /**
     * The verification status.
     */
    private final AtomicBoolean verified = new AtomicBoolean(false);

    /**
     * Construct a <code>CertificateVerificationCallback</code> with the CA
     * certificate.
     *
     * @param caCertificate
     *            the CA certificate to verify.
     */
    public CertificateVerificationCallback(final X509Certificate caCertificate) {
        this.caCertificate = caCertificate;
    }

    /**
     * Returns the CA certificate to verify.
     *
     * @return the CA certificate to verify.
     */
    public X509Certificate getCertificate() {
        return caCertificate;
    }

    /**
     * Returns the outcome of the verification process.
     *
     * @return {@code true} if the certificate was verified, {@code false}
     *         otherwise.
     */
    public boolean isVerified() {
        return verified.get();
    }

    /**
     * Sets the outcome of the callback.
     * 
     * {@link #isVerified()} returns {@code false} by default, so this method
     * only needs to be called if the CA certificate can be successfully
     * verified.
     *
     * @param verified
     *            the outcome.
     */
    public void setVerified(final boolean verified) {
        this.verified.set(verified);
    }
}
