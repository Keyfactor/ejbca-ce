package org.jscep.client.verification;

import java.security.cert.X509Certificate;

/**
 * This {@code CertificateVerifier} always returns {@code false}.
 * <p>
 * This implementation is primarily used for testing, although it can also be
 * used for disabling your SCEP client.
 */
public final class PessimisticCertificateVerifier implements
        CertificateVerifier {
    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verify(final X509Certificate cert) {
        return false;
    }

}
