package org.jscep.client.inspect;

import java.security.cert.X509Certificate;

/**
 * Interface to represent the operations for retrieval of certificates for
 * different purposes.
 */
public interface CertStoreInspector {

    /**
     * Returns the verifier certificate.
     *
     * @return the verifier certificate.
     */
    X509Certificate getSigner();

    /**
     * Returns the encrypter certificate.
     *
     * @return the encrypter certificate.
     */
    X509Certificate getRecipient();

    /**
     * Returns the issuer certificate.
     *
     * @return the issuer certificate.
     */
    X509Certificate getIssuer();

}
