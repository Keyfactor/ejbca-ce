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

/**
 * Restricts trust to a certificate issued by a trusted chain of issuers.
 * 
 * @version $Id$
 */
public class TrustedChain implements TrustEntry {
    final List<X509Certificate> trustedChain;

    public TrustedChain(final List<X509Certificate> trustedChain) {
        this.trustedChain = trustedChain;
    }

    @Override
    public Optional<List<X509Certificate>> getChain(final X509Certificate leafCertificate) {
        return Optional.of(trustedChain);
    }

    @Override
    public X509Certificate getIssuer() {
        return trustedChain.get(0);
    }
}
