/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.certificates.pinning;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import com.keyfactor.util.CertTools;

/**
 * Restricts trust of a certificate chain.
 * 
 * @version $Id$
 */
public interface TrustEntry {
    /**
     * Compute the certificate chain used for validation by {@link CertTools}.
     * 
     * @param leafCertificate the leaf certificate received during the TLS handshake.
     * @return an optional containing a certificate chain used for validation, or an empty optional if the leaf certificate is not trusted.
     */
    public Optional<List<X509Certificate>> getChain(X509Certificate leafCertificate);

    /**
     * Get the issuer in the certificate chain. The CA certificate returned from this method 
     * is be added to the list of accepted issuers used by the {@link TrustManager} performing
     * the certificate chain validation. 
     * 
     * @return the issuer of this trust entry.
     */
    public X509Certificate getIssuer();
}
