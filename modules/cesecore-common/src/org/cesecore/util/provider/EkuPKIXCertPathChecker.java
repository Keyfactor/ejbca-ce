/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.util.provider;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.Extension;
import org.cesecore.util.CertTools;

/**
 * Validate the EKUs of a leaf certificate.
 * 
 * If a EKU extension exists and is marked as critical, this PKIXCertPathChecker will ensure that
 * at least the specified extended key usages are present. Additional EKUs will be ignored as long
 * as the required ones are there. 
 * 
 * @version $Id$
 */
public class EkuPKIXCertPathChecker extends PKIXCertPathChecker {
    
    private static final Logger log = Logger.getLogger(EkuPKIXCertPathChecker.class);
    private static final List<String> EMPTY = new ArrayList<String>(0);
    private final List<String> requiredKeyPurposeOids;

    /**
     * Create a new instance that will check a critical EKU of the leaf certificate.
     * 
     * Parameters OIDs could be supplied using org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_*.getId()
     * 
     * @param requiredKeyPurposeOids a list of EKUs that at a minimum must be present if the EKU exists and is critical.
     */
    public EkuPKIXCertPathChecker(final String...requiredKeyPurposeOids) {
        super();
        if (requiredKeyPurposeOids==null) {
            this.requiredKeyPurposeOids = EMPTY;
        } else {
            this.requiredKeyPurposeOids = Arrays.asList(requiredKeyPurposeOids);
        }
    }

    /**
     * Create a new instance that will check a critical EKU of the leaf certificate.
     * 
     * Parameters OIDs could be supplied using org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_*.getId()
     * 
     * @param requiredKeyPurposeOids a list of EKUs that at a minimum must be present if the EKU exists and is critical.
     */
    public EkuPKIXCertPathChecker(final List<String> requiredKeyPurposeOids) {
        super();
        if (requiredKeyPurposeOids==null) {
            this.requiredKeyPurposeOids = EMPTY;
        } else {
            this.requiredKeyPurposeOids = requiredKeyPurposeOids;
        }
    }

    @Override
    public void check(final Certificate cert, final Collection<String> unresolvedCritExts) throws CertPathValidatorException {
        if (!CertTools.isCA(cert) && cert instanceof X509Certificate) {
            final X509Certificate x509Certificate = (X509Certificate) cert;
            try {
                List<String> ekus = x509Certificate.getExtendedKeyUsage();
                if (ekus==null) {
                    ekus = EMPTY;
                }
                if (ekus.containsAll(requiredKeyPurposeOids)) {
                    // All the required EKUs are present, so mark the EKU extension as processed
                    unresolvedCritExts.remove(Extension.extendedKeyUsage.getId());
                } else {
                    final List<String> ekusMissing = new ArrayList<String>(requiredKeyPurposeOids);
                    ekusMissing.removeAll(ekus);
                    if (log.isDebugEnabled()) {
                        log.debug("EKUs in certificate: " +Arrays.toString(ekus.toArray()) + " EKUs required: " +Arrays.toString(requiredKeyPurposeOids.toArray()));
                    }
                    log.info("Validation of certificate with subject " + CertTools.getSubjectDN(cert) + " failed critical EKU validation. The missing EKUs were: " + Arrays.toString(ekusMissing.toArray()));
                    return;
                }
            } catch (CertificateParsingException e) {
                throw new CertPathValidatorException(e);
            }
        }
    }

    @Override
    public Set<String> getSupportedExtensions() {
        return Collections.singleton(Extension.extendedKeyUsage.getId());
    }

    @Override
    public void init(final boolean forward) throws CertPathValidatorException {
        // NOOP: We don't care about the order, we handle EKUs for non-CA certs 
    }

    @Override
    public boolean isForwardCheckingSupported() {
        // We don't care about the order, we handle EKUs for non-CA certs 
        return true;
    }
}
