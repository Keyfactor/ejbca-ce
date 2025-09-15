/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.license;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.Date;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.ejbca.core.ejb.license.model.LicenseData;
import org.ejbca.core.ejb.license.model.LicenseTestUtil;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.Marshaller;

// intentionally does not contain UnitTest suffix to omit from test runs
public class GenerateExampleLicense {
    
    private static final Logger log = Logger.getLogger(GenerateExampleLicense.class);
    
    private static final String TEST_LICENSE_DIR = "testLicenses/";
        
    @BeforeClass
    public static void setupSampleKeyStoreForLicenseSign() throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        String keyAlias = "mykey";
        String keyPassword = "changeit";
        String keystorePassword = "changeit";

        // Generate RSA 2048 key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        // Generate a self-signed certificate
        X500Name dnName = new X500Name("CN=Test, O=MyOrg, C=US");
        BigInteger certSerialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Date startDate = new Date();
        Date endDate = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000); // 1 year

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName,
                certSerialNumber,
                startDate,
                endDate,
                dnName,
                keyPair.getPublic()
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(keyPair.getPrivate());

        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certBuilder.build(signer));

        cert.checkValidity(new Date());
        cert.verify(keyPair.getPublic(), "BC");

        // Create a keystore and store the key + certificate
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC"); // or "JKS"
        keyStore.load(null, null);

        keyStore.setKeyEntry(keyAlias, keyPair.getPrivate(), keyPassword.toCharArray(),
                new Certificate[]{cert});
        
        File directory = new File(String.valueOf(TEST_LICENSE_DIR));

        if (!directory.exists()) {
            directory.mkdir();
        }

        try (FileOutputStream fos = new FileOutputStream(TEST_LICENSE_DIR + "keystore.p12")) {
            keyStore.store(fos, keystorePassword.toCharArray());
        }
        
        // This PEM is to be put in LicenseVerifierEnterpriseSessionBean
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(TEST_LICENSE_DIR + "public_key.pem"))) {
            pemWriter.writeObject(keyPair.getPublic());
        }
        
        log.error("Generated key store for license signing");

    }
    
    @Test
    public void validLicense() throws Exception {
        prepareExampleLicense(ZonedDateTime.of(2026, 12, 10, 5, 4, 3, 0, ZoneId.of("UTC")), "custom-valid-license.xml");
    }
    
    @Test
    public void expire60DaysLicense() throws Exception {
        prepareExampleLicense(ZonedDateTime.now().plusDays(59), "expires-in-60-days.xml");
    }
    
    @Test
    public void expire30DaysLicense() throws Exception {
        prepareExampleLicense(ZonedDateTime.now().plusDays(29), "expires-in-30-days.xml");
    }
    
    @Test
    public void expire5DaysLicense() throws Exception {
        prepareExampleLicense(ZonedDateTime.now().plusDays(4), "expires-in-5-days.xml");
    }
        
    private void prepareExampleLicense(ZonedDateTime expiryDate, String outputFileName) throws Exception {
        
        // Prepare the license
        LicenseData licenseData = LicenseTestUtil.createSampleLicense(expiryDate);
        
        // 1) Marshal Java object into an XML Document
        JAXBContext jaxbContext = JAXBContext.newInstance(LicenseData.class);
        Marshaller marshaller = jaxbContext.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().newDocument();
        marshaller.marshal(licenseData, doc);

        // 2) Load signing key from keystore
        String keystorePath = TEST_LICENSE_DIR + "keystore.p12";
        String keystorePassword = "changeit";
        String keyAlias = "mykey";
        String keyPassword = "changeit";

        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(keystorePath), keystorePassword.toCharArray());

        KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry)
                ks.getEntry(keyAlias, new KeyStore.PasswordProtection(keyPassword.toCharArray()));

        PrivateKey privateKey = keyEntry.getPrivateKey();

        // 3) Create XML Signature Factory
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        // Reference: sign the entire document with enveloped transform
        Reference ref = fac.newReference(
                "",
                fac.newDigestMethod(DigestMethod.SHA256, null),
                Collections.singletonList(
                        fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)
                ),
                null,
                null
        );

        SignedInfo si = fac.newSignedInfo(
                fac.newCanonicalizationMethod(
                        CanonicalizationMethod.INCLUSIVE,
                        (C14NMethodParameterSpec) null),
                fac.newSignatureMethod(SignatureMethod.RSA_SHA256, null),
                Collections.singletonList(ref)
        );

        // Create the XML Signature
        XMLSignature signature = fac.newXMLSignature(si, null);

        // Sign
        DOMSignContext dsc = new DOMSignContext(privateKey, doc.getDocumentElement());
        signature.sign(dsc);

        // 4) Output signed XML
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.setOutputProperty(javax.xml.transform.OutputKeys.OMIT_XML_DECLARATION, "no");
        trans.setOutputProperty(javax.xml.transform.OutputKeys.INDENT, "no");
        trans.transform(new DOMSource(doc), new StreamResult(new File(TEST_LICENSE_DIR + outputFileName)));

        log.error("Signed XML created: " + outputFileName);

    }
}
