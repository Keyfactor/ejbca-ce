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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keybind.impl.OcspKeyBinding.ResponderIdType;
import org.cesecore.util.SimpleTime;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

/**
 * Test of OcspKeyBinding implementation.
 * 
 * @version $Id$
 */
public class OcspKeyBindingTest {

    private static List<Extension> ekuExtensionOnly;

    // Define a traceLogMethodsRule similar to the system tests TraceLogMethodsRule() implementation.
    @Rule
    public TestRule traceLogMethodsRule = new TestWatcher() {
        @Override
        protected void starting(Description description) {
            final Logger log = Logger.getLogger(description.getClassName());
            if (log.isTraceEnabled()) {
                log.trace(">" + description.getMethodName());
            }
            super.starting(description);
        };
        @Override
        protected void finished(Description description) {
            final Logger log = Logger.getLogger(description.getClassName());
            if (log.isTraceEnabled()) {
                log.trace("<" + description.getMethodName());
            }
            super.finished(description);
        }
    };

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProvider();
        ekuExtensionOnly = Collections.singletonList(getExtendedKeyUsageExtension());
    }

    @Test
    public void testOcspSigningCertificateValidationPositives() throws IOException, InvalidAlgorithmParameterException, OperatorCreationException, CertificateException {
        AvailableExtendedKeyUsagesConfiguration ekuConfig = new AvailableExtendedKeyUsagesConfiguration();
        assertTrue("KU=digitalSignature and EKU=id_kp_OCSPSigning should be treated as a valid OCSP singing certificate.",
                OcspKeyBinding.isOcspSigningCertificate(getCertificate(X509KeyUsage.digitalSignature, ekuExtensionOnly), ekuConfig));
        assertTrue("KU=digitalSignature and EKU=id_kp_OCSPSigning should be treated as a valid OCSP singing certificate.",
                OcspKeyBinding.isOcspSigningCertificate(getCertificate(X509KeyUsage.digitalSignature + X509KeyUsage.cRLSign, ekuExtensionOnly), ekuConfig));
        assertTrue("KU=nonRepudiation and EKU=id_kp_OCSPSigning should be treated as a valid OCSP singing certificate.",
                OcspKeyBinding.isOcspSigningCertificate(getCertificate(X509KeyUsage.nonRepudiation + X509KeyUsage.cRLSign, ekuExtensionOnly), ekuConfig));
        assertTrue("KU=digitalSignature+nonRepudiation and EKU=id_kp_OCSPSigning should be treated as a valid OCSP singing certificate.",
                OcspKeyBinding.isOcspSigningCertificate(getCertificate(X509KeyUsage.digitalSignature + X509KeyUsage.nonRepudiation, ekuExtensionOnly), ekuConfig));
        assertTrue("Non existing KU is ok according to RFC5280 and should be treated as a valid OCSP signing certificate.",
                OcspKeyBinding.isOcspSigningCertificate(getCertificate(0, ekuExtensionOnly), ekuConfig));
    }

    @Test
    public void testOcspSigningCertificateAssertionPositives() throws IOException, InvalidAlgorithmParameterException, OperatorCreationException, CertificateException {
        try {
            new OcspKeyBinding().assertCertificateCompatability(getCertificate(X509KeyUsage.digitalSignature, ekuExtensionOnly), new AvailableExtendedKeyUsagesConfiguration());
        } catch (CertificateImportException e) {
            fail("KU=digitalSignature and EKU=id_kp_OCSPSigning should be treated as a valid OCSP singing certificate.");
        }
    }

    @Test
    public void testOcspSigningCertificateValidationNegatives() throws IOException, InvalidAlgorithmParameterException, OperatorCreationException, CertificateException {
        AvailableExtendedKeyUsagesConfiguration ekuConfig = new AvailableExtendedKeyUsagesConfiguration();
        assertFalse("KU!=digitalSignature|nonRepudiation and EKU=id_kp_OCSPSigning should be treated as an invalid OCSP singing certificate.",
                OcspKeyBinding.isOcspSigningCertificate(getCertificate(X509KeyUsage.keyAgreement + X509KeyUsage.cRLSign, ekuExtensionOnly), ekuConfig));
        assertFalse("KU=digitalSignature and EKU!=id_kp_OCSPSigning should be treated as an invalid OCSP singing certificate.",
                OcspKeyBinding.isOcspSigningCertificate(getCertificate(X509KeyUsage.digitalSignature, null), ekuConfig));
        assertFalse("KU=nonRepudiation and EKU!=id_kp_OCSPSigning should be treated as an invalid OCSP singing certificate.",
                OcspKeyBinding.isOcspSigningCertificate(getCertificate(X509KeyUsage.nonRepudiation, null), ekuConfig));
 }

    @Test
    public void testOcspSigningCertificateAssertionNegatives() throws IOException, InvalidAlgorithmParameterException, OperatorCreationException, CertificateException {
        try {
            new OcspKeyBinding().assertCertificateCompatability(getCertificate(X509KeyUsage.cRLSign, null), new AvailableExtendedKeyUsagesConfiguration() );
            fail("KU=cRLSign and EKU!=id_kp_OCSPSigning should be treated as an invalid OCSP singing certificate.");
        } catch (CertificateImportException e) {
            // Expected outcome
        }
    }

    /** @return A self-signed certificate. */
    private X509Certificate getCertificate(final int keyUsage, final List<Extension> extensions) throws InvalidAlgorithmParameterException, OperatorCreationException, CertificateException, IOException {
        final KeyPair keyPair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        return CertTools.genSelfCertForPurpose("CN=OcspSinger", 365, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA256WithRSA", false,
                keyUsage, null, null, BouncyCastleProvider.PROVIDER_NAME, true, extensions);
    }

    /** @return An extended key usage extension with id_kp_OCSPSigning set. */
    private static Extension getExtendedKeyUsageExtension() throws IOException {
        final ASN1Encodable usage = KeyPurposeId.getInstance(KeyPurposeId.id_kp_OCSPSigning);
        final ASN1Sequence seq = ASN1Sequence.getInstance(new DERSequence(usage));
        return new Extension(Extension.extendedKeyUsage, true, seq.getEncoded());
    }
    
    @Test
    public void testProperties() {
        final OcspKeyBinding keybind = new OcspKeyBinding();
        // Check defaults (please update if changed)
        assertTrue("getIncludeSignCert", keybind.getIncludeSignCert());
        assertFalse("getRequireTrustedSignature", keybind.getRequireTrustedSignature());
        assertEquals("getResponderIdType", ResponderIdType.KEYHASH, keybind.getResponderIdType());
        assertEquals("Default retention period should be 1 year.", "1y", keybind.getRetentionPeriod().toString());
        assertEquals("ETSI Archive Cutoff should be disabled by default.", false, keybind.getUseIssuerNotBeforeAsArchiveCutoff());
        // Test getters and setters
        keybind.setNonExistingGood(true);
        keybind.setIncludeCertChain(false);
        keybind.setIncludeSignCert(false);
        keybind.setRequireTrustedSignature(true);
        keybind.setResponderIdType(ResponderIdType.NAME);
        keybind.setUseIssuerNotBeforeAsArchiveCutoff(true);
        keybind.setUseIssuerNotBeforeAsArchiveCutoff(true);
        keybind.setRetentionPeriod(SimpleTime.getInstance("10y"));
        assertTrue("setNonExistingGood", keybind.getNonExistingGood());
        assertFalse("setIncludeSignCert", keybind.getIncludeSignCert());
        assertFalse("setIncludeCertChain", keybind.getIncludeCertChain());
        assertTrue("setRequireTrustedSignature", keybind.getRequireTrustedSignature());
        assertEquals("setResponderIdType", ResponderIdType.NAME, keybind.getResponderIdType());
        assertEquals("Retention period did not change.", "10y", keybind.getRetentionPeriod().toString());
        assertEquals("Use ETSI archive cutoff option did not change.", true, keybind.getUseIssuerNotBeforeAsArchiveCutoff());
    }

}
