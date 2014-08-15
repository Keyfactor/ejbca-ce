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
import org.cesecore.keybind.InternalKeyBindingProperty;
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
    
    /*
     * Java 6: http://docs.oracle.com/javase/6/docs/technotes/guides/security/SunProviders.html#SunJSSEProvider
     *  TLS versions: SSLv3, TLSv1, SSLv2Hello
     * Java 7: http://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html#SunJSSEProvider
     *  TLS versions: SSLv3, TLSv1, SSLv2Hello, TLSv1.1, TLSv1.2
     *  Cipher suites with SHA384 and SHA256 are available only for TLS 1.2 or later.
     */
    private final String TLS_VERSION_10 = "TLSv1";
    private final String TLS_VERSION_12 = "TLSv1.2";
    private final String SPLIT_CHAR = " ";
    private final String[] CIPHER_SUITES_SUBSET = {
            // Java 7
            TLS_VERSION_12 + SPLIT_CHAR + "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
            TLS_VERSION_12 + SPLIT_CHAR + "TLS_RSA_WITH_AES_256_CBC_SHA256",
            // Java 6
            TLS_VERSION_10 + SPLIT_CHAR + "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
            TLS_VERSION_10 + SPLIT_CHAR + "TLS_RSA_WITH_AES_256_CBC_SHA"
    };

    public static final String PROPERTY_PROTOCOL_AND_CIPHER_SUITE = "protocolAndCipherSuite";

    {
        addProperty(new InternalKeyBindingProperty<String>(PROPERTY_PROTOCOL_AND_CIPHER_SUITE, CIPHER_SUITES_SUBSET[0], CIPHER_SUITES_SUBSET));
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
        final String[] values = value.split(SPLIT_CHAR);
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
