package org.jscep.client.verification;

import java.security.cert.X509Certificate;

/**
 * This {@code CertificateVerifier} uses a pre-provisioned certificate for
 * verification.
 * <p>
 * The certificate passed to {@link #verify(X509Certificate)} is deemed to be
 * verified if it is equal to the certificate passed in the constructor, as
 * determined by the {@link X509Certificate#equals(Object)} method.
 */
public final class PreProvisionedCertificateVerifier implements
        CertificateVerifier {
    /**
     * The pre-provisioned certificate.
     */
    private final X509Certificate cert;

    /**
     * Creates a new instance of this class with a pre-provisioned certificate.
     * 
     * @param cert
     *            the pre-provisioned certificate.
     */
    public PreProvisionedCertificateVerifier(final X509Certificate cert) {
        this.cert = cert;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verify(final X509Certificate cert) {
        return this.cert.equals(cert);
    }

}
