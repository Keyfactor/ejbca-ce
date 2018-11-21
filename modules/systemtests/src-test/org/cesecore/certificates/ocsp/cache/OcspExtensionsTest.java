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
package org.cesecore.certificates.ocsp.cache;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cesecore.certificates.ocsp.extension.OCSPExtension;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.FileTools;
import org.ejbca.core.protocol.ocsp.extension.certhash.OcspCertHashExtension;
import org.ejbca.core.protocol.ocsp.extension.unid.OCSPUnidExtension;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Unit test for the OCSP Extensions cache and 
 * 
 * @version $Id$
 *
 */
public class OcspExtensionsTest {

    private static final String OCSP_UNID_OID = "2.16.578.1.16.3.2";
    private static final String OCSP_UNID_CLASSNAME = OCSPUnidExtension.class.getName();
    private static final String OCSP_CERTHASH_CLASSNAME = OcspCertHashExtension.class.getName();
    private static File trustDir;
    private static Certificate certificate;
    private static File trustedCertificateFile;
    private static File caCertificateFile;

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        trustDir = FileTools.createTempDirectory();
        caCertificateFile = File.createTempFile("tmp", ".pem");
        trustedCertificateFile = File.createTempFile("tmp", ".pem", trustDir);
        KeyPair caKeyPair = KeyTools.genKeys("1024", "RSA");
        Certificate caCertificate = CertTools.genSelfCert("CN=TESTCA", 10L, null, caKeyPair.getPrivate(), caKeyPair.getPublic(), "SHA256WithRSA", true);
        FileOutputStream fileOutputStream = new FileOutputStream(caCertificateFile);
        try {
            fileOutputStream.write(CertTools.getPemFromCertificateChain(Arrays.asList(caCertificate)));
        } finally {
            fileOutputStream.close();
        }
        Date firstDate = new Date();
        firstDate.setTime(firstDate.getTime() - (10 * 60 * 1000));
        Date lastDate = new Date();
        lastDate.setTime(lastDate.getTime() + (24 * 60 * 60 * 1000));
        byte[] serno = new byte[8];
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(new Date().getTime());
        random.nextBytes(serno);
        KeyPair certificateKeyPair = KeyTools.genKeys("1024", "RSA");
        final SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(certificateKeyPair.getPublic().getEncoded());
        final String certDn = "CN=TEST,SN=4711";
        X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(CertTools.stringToBcX500Name(certDn, false), new BigInteger(serno).abs(),
                firstDate, lastDate, CertTools.stringToBcX500Name(certDn, false), pkinfo);
        final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder("SHA256WithRSA").setProvider(
                BouncyCastleProvider.PROVIDER_NAME).build(caKeyPair.getPrivate()), 20480);
        final X509CertificateHolder certHolder = certbuilder.build(signer);
        certificate = CertTools.getCertfromByteArray(certHolder.getEncoded(), Certificate.class);
        fileOutputStream = new FileOutputStream(trustedCertificateFile);
        try {
            fileOutputStream.write(CertTools.getPemFromCertificateChain(Arrays.asList(certificate)));
        } finally {
            fileOutputStream.close();
        }
        ConfigurationHolder.updateConfiguration("ocsp.extensionoid", OCSP_UNID_OID+';'+OcspCertHashExtension.CERT_HASH_OID);
        ConfigurationHolder.updateConfiguration("ocsp.extensionclass", OCSP_UNID_CLASSNAME+';'+OCSP_CERTHASH_CLASSNAME);
        ConfigurationHolder.updateConfiguration("ocsp.uniddatsource", "foo");
        ConfigurationHolder.updateConfiguration("ocsp.unidtrustdir", trustDir.getAbsolutePath());
        ConfigurationHolder.updateConfiguration("ocsp.unidcacert", caCertificateFile.getAbsolutePath());
        OcspExtensionsCache.INSTANCE.reloadCache();

    }

    @AfterClass
    public static void afterClass() {
        FileTools.delete(trustDir);
        FileTools.delete(caCertificateFile);
    }

    /**
     * Tests retrieving an ocsp unid extension. Actually processing the request falls under system testing. 
     */
    @Test
    public void testRetrieveOcspUnidExtension() throws IOException {
        Map<String, OCSPExtension> extensions = OcspExtensionsCache.INSTANCE.getExtensions();
        OCSPExtension ocspUnidExtension = extensions.get(OCSPUnidExtension.OCSP_UNID_OID);
        assertNotNull("OCSP Unid extension was not loaded", ocspUnidExtension);
    }

    /**
     * Tests retrieving an ocsp cert hash extension. Actually processing the request falls under system testing. 
     */
    @Test
    public void testRetrieveOcspCertHashExtension() throws IOException {
        Map<String, OCSPExtension> extensions = OcspExtensionsCache.INSTANCE.getExtensions();
        OCSPExtension ocspCertHashExtension = extensions.get(OcspCertHashExtension.CERT_HASH_OID);
        assertNotNull("OCSP CertHash extension was not loaded", ocspCertHashExtension);
    }
    
    /**
     * Tests retrieving an ocsp CT SCT extension. Actually processing the request falls under system testing.
     */
    @Test
    public void testRetrieveOcspCtSstListExtension() {
        try {
            Class.forName("org.ejbca.core.protocol.ocsp.extension.certificatetransparency.OcspCtSctListExtension");
        } catch (ClassNotFoundException e) {
            assumeTrue("Skipping test on Community Edition (class OcspCtSctListExtension does not exist)", false);
        }

        // we cant use OcspCtSctListExtension.OCSP_SCTLIST_OID, 
        // because org.ejbca.core.protocol.ocsp.extension.certificatetransparency.OcspCtSctListExtension is not included in Community edition
        final String OCSP_SCTLIST_OID = "1.3.6.1.4.1.11129.2.4.5";
        
        Map<String, OCSPExtension> extensions = OcspExtensionsCache.INSTANCE.getExtensions();
        OCSPExtension ocspCtSstListExtension = extensions.get(OCSP_SCTLIST_OID);
        assertNotNull("OCSP CtSct extension was not loaded", ocspCtSstListExtension);
    }

}
