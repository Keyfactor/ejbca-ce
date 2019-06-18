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
package org.cesecore.keybind.impl;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keybind.InternalKeyBindingBase;
import org.cesecore.util.CertTools;
import org.cesecore.util.ui.DynamicUiProperty;

/**
 * Used when this EJBCA instance authenticates to other instances.
 * 
 * @version $Id$
 */
public class AuthenticationKeyBinding extends InternalKeyBindingBase {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(AuthenticationKeyBinding.class);

    public static final String IMPLEMENTATION_ALIAS = "AuthenticationKeyBinding"; // This should not change, even if we rename the class in EJBCA 5.3+..
    public static final String PROPERTY_PROTOCOL_AND_CIPHER_SUITE = "protocolAndCipherSuite";

    {
        final String[] CIPHER_SUITES_SUBSET = CesecoreConfiguration.getAvailableCipherSuites();
        addProperty(new DynamicUiProperty<String>(PROPERTY_PROTOCOL_AND_CIPHER_SUITE, CIPHER_SUITES_SUBSET[0], Arrays.asList(CIPHER_SUITES_SUBSET)));
    }

    /** @return an array of supported protocols named according to JSSE */
    public String[] getSupportedProtocols() {
        return getSelectedProtocolOrSuite(0);
    }

    /** @return an array of supported cipher suites named according to JSSE */
    public String[] getSupportedCipherTextSuites() {
        return getSelectedProtocolOrSuite(1);
    }

    private String[] getSelectedProtocolOrSuite(final int pos) {
        final String value = (String) getProperty(PROPERTY_PROTOCOL_AND_CIPHER_SUITE).getValue();
        final String[] values = value.split(CesecoreConfiguration.AVAILABLE_CIPHER_SUITES_SPLIT_CHAR);
        if (log.isDebugEnabled() && pos==0) {
            log.debug("Configured cipher suite for this AuthenticationKeyBinding: " + value);
        }
        if (values.length==2) {
            return new String[] { values[pos] };
        }
        return new String[0];
    }

    @Override
    public String getImplementationAlias() {
        return IMPLEMENTATION_ALIAS;
    }

    @Override
    public float getLatestVersion() {
        return serialVersionUID;
    }

    @Override
    public void assertCertificateCompatability(Certificate certificate, final AvailableExtendedKeyUsagesConfiguration ekuConfig) throws CertificateImportException {
        if (!isClientSSLCertificate(certificate, ekuConfig)) {
            throw new CertificateImportException("Not a valid Client SSL authentication certificate.");
        }
    }

    @Override
    protected void upgrade(float latestVersion, float currentVersion) {
        // Nothing to do   
    }

    public static boolean isClientSSLCertificate(Certificate certificate, final AvailableExtendedKeyUsagesConfiguration ekuConfig) {
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
            if (log.isDebugEnabled()) {
                log.debug("SubjectDN: " + CertTools.getSubjectDN(x509Certificate) + " IssuerDN: " + CertTools.getIssuerDN(x509Certificate));
            }
            final boolean[] ku = x509Certificate.getKeyUsage();
            if (ku != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Key usages: " + Arrays.toString(ku));
                    log.debug("Key usage (digitalSignature): " + ku[0]);
                    log.debug("Key usage (keyEncipherment): " + ku[2]);
                }
            } else {
                log.debug("No Key Usage to verify.");
                return false;            	
            }
            if (x509Certificate.getExtendedKeyUsage() == null) {
                log.debug("No EKU to verify.");
                return false;
            }
            for (String extendedKeyUsage : x509Certificate.getExtendedKeyUsage()) {
                log.debug("EKU: " + extendedKeyUsage + " (" +
                        ekuConfig.getAllEKUOidsAndNames().get(extendedKeyUsage) + ")");
            }
            if (!x509Certificate.getExtendedKeyUsage().contains(KeyPurposeId.id_kp_clientAuth.getId())) {
                log.debug("Extended Key Usage 1.3.6.1.5.5.7.3.2 (EKU_PKIX_CLIENTAUTH) is required.");
                return false;
            }
            // For TLS _client_ certificates you can actually be without KU completely, but we take the safe route here and require digitalSignature
            // for TLS _server_ certificates also keyEncipherment is required, but not for client (it doesn't hurt it it's there for clients as well though)
            if (!ku[0]) {
                log.debug("Key usage digitalSignature is required.");
                return false;
            }
        } catch (CertificateParsingException e) {
            log.debug(e.getMessage());
            return false;
        }
        return true;
    }

    @Override
    public byte[] generateCsrForNextKeyPair(String providerName, KeyPair keyPair, String signatureAlgorithm, X500Name subjectDn)
            throws IOException, OperatorCreationException {
        return CertTools
                .genPKCS10CertificationRequest(signatureAlgorithm, subjectDn, keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), providerName)
                .getEncoded();
    }
}
