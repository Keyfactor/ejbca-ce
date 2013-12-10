/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keybind.impl;

import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.cesecore.config.ExtendedKeyUsageConfiguration;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keybind.InternalKeyBindingBase;
import org.cesecore.util.CertTools;

/**
 * Used when this EJBCA instance authenticates to other instances.
 * 
 * @version $Id$
 */
public class AuthenticationKeyBinding extends InternalKeyBindingBase {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(AuthenticationKeyBinding.class);

    public static final String IMPLEMENTATION_ALIAS = "AuthenticationKeyBinding"; // This should not change, even if we rename the class in EJBCA 5.3+..


    @Override
    public String getImplementationAlias() {
        return IMPLEMENTATION_ALIAS;
    }

    @Override
    public float getLatestVersion() {
        return serialVersionUID;
    }

    @Override
    public void assertCertificateCompatability(Certificate certificate) throws CertificateImportException {
        if (!isClientSSLCertificate(certificate)) {
            throw new CertificateImportException("Not a vlid Client SSL authentication certificate.");
        }
    }

    @Override
    protected void upgrade(float latestVersion, float currentVersion) {
        // Nothing to do   
    }

    public static boolean isClientSSLCertificate(Certificate certificate) {
        if (certificate == null) {
            log.debug("No certificate provided.");
            return false;
        }
        if (!(certificate instanceof X509Certificate)) {
            log.debug("Only X509 supported.");
            return false;
        }
        try {
            final X509Certificate x509Certificate = (X509Certificate) certificate;
            log.debug("SubjectDN: " + CertTools.getSubjectDN(x509Certificate) + " IssuerDN: " + CertTools.getIssuerDN(x509Certificate));
            final boolean[] ku = x509Certificate.getKeyUsage();
            log.debug("Key usages: " + Arrays.toString(ku));
            if (ku != null) {
                log.debug("Key usage (digitalSignature): " + x509Certificate.getKeyUsage()[0]);
                log.debug("Key usage (keyEncipherment): " + x509Certificate.getKeyUsage()[2]);
            }
            if (x509Certificate.getExtendedKeyUsage() == null) {
                log.debug("No EKU to verify.");
                return false;
            }
            for (String extendedKeyUsage : x509Certificate.getExtendedKeyUsage()) {
                log.debug("EKU: " + extendedKeyUsage + " (" +
                        ExtendedKeyUsageConfiguration.getExtendedKeyUsageOidsAndNames().get(extendedKeyUsage) + ")");
            }
            if (!x509Certificate.getExtendedKeyUsage().contains(KeyPurposeId.id_kp_clientAuth.getId())) {
                log.debug("Extended Key Usage 1.3.6.1.5.5.7.3.2 (EKU_PKIX_CLIENTAUTH) is required.");
                return false;
            }
            if (!x509Certificate.getKeyUsage()[0]) {
                log.debug("Key usage digitalSignature is required.");
                return false;
            }
            if (!x509Certificate.getKeyUsage()[2]) {
                log.debug("Key usage keyEncipherment is required.");
                return false;
            }
        } catch (CertificateParsingException e) {
            log.debug(e.getMessage());
            return false;
        }
        return true;
    }
}
