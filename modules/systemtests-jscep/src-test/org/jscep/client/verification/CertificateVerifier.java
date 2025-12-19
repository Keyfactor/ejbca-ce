package org.jscep.client.verification;

import java.security.cert.X509Certificate;

import org.jscep.client.CertificateVerificationCallback;

/**
 * Interface for verifying the identity of a given certificate.
 * 
 * @see CertificateVerificationCallback
 */
public interface CertificateVerifier {
    /**
     * Verifies the certificate.
     * 
     * @param cert
     *            the certificate to verify.
     * @return {@code true} if the identity of the certificate can be verified,
     *         {@code false} otherwise.
     */
    boolean verify(X509Certificate cert);
}
