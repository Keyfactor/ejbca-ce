package org.jscep.client.inspect;

import java.security.cert.CertStore;

/**
 * Abstract factory for creating CertStoreInspector instances.
 */
public interface CertStoreInspectorFactory {
    /**
     * Inspects the given CertStore to extract an CertStoreInspector instance.
     * <p>
     * This method will inspect the given CertStore with pre-configured
     * selectors to match RA certificates for encryption and verification, plus
     * the issuing CA certificate.
     * <p>
     * If the CertStore only contains a single CA certificate, that certificate
     * will be used for all three roles.
     *
     * @param store
     *            the store to inspect.
     * @return the CertStoreInspector instance.
     */
    CertStoreInspector getInstance(CertStore store);
}
