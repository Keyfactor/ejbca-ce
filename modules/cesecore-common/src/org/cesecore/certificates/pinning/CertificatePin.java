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

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Restricts trust to a certificate with the specified certificate serial number issued by a 
 * trusted chain of issuers.
 * 
 * @version $Id$
 */
public class CertificatePin implements TrustEntry {
    final List<X509Certificate> trustedChain;
    final BigInteger pinnedCertificateSerialNumber;

    public CertificatePin(final List<X509Certificate> trustedChain, final BigInteger pinnedCertificateSerialNumber) {
        this.trustedChain = trustedChain;
        this.pinnedCertificateSerialNumber = pinnedCertificateSerialNumber;
    }

    @Override
    public Optional<List<X509Certificate>> getChain(final X509Certificate leafCertificate) {
        if (leafCertificate.getSerialNumber().equals(pinnedCertificateSerialNumber) && isSignedBy(leafCertificate, trustedChain.get(0))) {
            final ArrayList<X509Certificate> chain = new ArrayList<>();
            chain.add(leafCertificate);
            chain.addAll(trustedChain);
            return Optional.of(chain);
        }
        return Optional.empty();
    }

    private boolean isSignedBy(final X509Certificate leafCertificate, final X509Certificate issuer) {
        try {
            leafCertificate.verify(issuer.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public X509Certificate getIssuer() {
        return trustedChain.get(0);
    }
}
