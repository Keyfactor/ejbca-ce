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

package org.cesecore.certificates.request;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.cmc.CertificationRequest;
import org.bouncycastle.asn1.cmc.OtherMsg;
import org.bouncycastle.asn1.cmc.PKIData;
import org.bouncycastle.asn1.cmc.TaggedAttribute;
import org.bouncycastle.asn1.cmc.TaggedCertificationRequest;
import org.bouncycastle.asn1.cmc.TaggedContentInfo;
import org.bouncycastle.asn1.cmc.TaggedRequest;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.crypto.util.AlgorithmIdentifierFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.junit.Test;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.keys.KeyTools;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class PKCS10RequestMessageTest {

    @Test
    public void testSerializeDeserialize() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        final KeyPair keyPair = KeyTools.genKeys("512", "RSA");
        final SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic());
        final ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        extensionsGenerator.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
        extensionsGenerator.addExtension(Extension.keyUsage,true, new KeyUsage(KeyUsage.digitalSignature));
        final PKCS10CertificationRequestBuilder pkcs10CertificationRequestBuilder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=Foo"), keyPair.getPublic())
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
        final ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());
        final PKCS10RequestMessage pkcs10 = new PKCS10RequestMessage(pkcs10CertificationRequestBuilder.build(contentSigner).getEncoded());
        try (final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            try (final ObjectOutputStream oos = new ObjectOutputStream(byteArrayOutputStream)) {
                oos.writeObject(pkcs10);
            }
            try (final ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()))) {
                final PKCS10RequestMessage deserializedPkcs10 = (PKCS10RequestMessage) ois.readObject();
                assertNotNull("Could not deserialize, getPublicKey() == null", deserializedPkcs10.getRequestPublicKey());
                assertEquals("CN=Foo", deserializedPkcs10.getRequestDN());
            }
        }
    }
    
    @Test
    public void testKeyArchivalMessage() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        
        // dummy self-signed CAExchange certificate  
        final KeyPair caEncKeyPair = KeyTools.genKeys("2048", "RSA");
        String encCertSubjectDn = "CN=IssuerCa-Xchg";
        X509Certificate encCertificate = CertTools.genSelfCert(encCertSubjectDn, 10L, "1.1.1.1", caEncKeyPair.getPrivate(),
                caEncKeyPair.getPublic(), "SHA256WithRSA", false);
        
        // step 1: PKCS10 for user public key 
        final KeyPair eeKeyPair = KeyTools.genKeys("2048", "RSA");
        String eeSubjectDn = "CN=SomeEE";
        final SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(eeKeyPair.getPublic());
        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        extensionsGenerator.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
        extensionsGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        final PKCS10CertificationRequestBuilder pkcs10CertificationRequestBuilder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name(eeSubjectDn), eeKeyPair.getPublic())
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
        final ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(eeKeyPair.getPrivate());
        final PKCS10CertificationRequest pkcs10 = pkcs10CertificationRequestBuilder.build(contentSigner);
        
        CertificationRequest certRequest = CertificationRequest.getInstance(pkcs10.getEncoded()); // same ASN1
        System.out.println(certRequest.getSubject());

        // step 2: encrypting user private key
        CMSTypedData msg = new CMSProcessableByteArray(eeKeyPair.getPrivate().getEncoded());
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(encCertificate).setProvider("BC"));
        CMSEnvelopedData envelopedPrivKey = edGen.generate(
                                        msg,
                                        new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)
                                               .setProvider("BC").build());
        
        // step 3: creating CMC, skipped optional RegInfo in 3.ii
        BodyPartID bodyId = new BodyPartID(123456L); // random??
        TaggedCertificationRequest tcr = new TaggedCertificationRequest(bodyId, certRequest);
        TaggedRequest taggedReq = new TaggedRequest(tcr);
        
        BodyPartID bodyId2 = new BodyPartID(123457L); // same as before?? random??
        final MessageDigest md = MessageDigest.getInstance("SHA256"); // hard coding
        final byte[] envelopedPrivKeyHash = md.digest(envelopedPrivKey.getEncoded());
        
        final String szOID_ENCRYPTED_KEY_HASH = "1.3.6.1.4.1.311.21.21";
        TaggedAttribute taggedAttribute = new TaggedAttribute(bodyId2,
                new ASN1ObjectIdentifier(szOID_ENCRYPTED_KEY_HASH),
                new DERSet(new DERBitString(envelopedPrivKeyHash)));
        
        PKIData pkiData = new PKIData(new TaggedAttribute[]{taggedAttribute}, 
                                        new TaggedRequest[]{taggedReq}, 
                                        new TaggedContentInfo[] {}, 
                                        // may need to provide ContentInfo which refers to the BodyPartIDs
                                        new OtherMsg[] {});
        
        // step 4: construct CMS
        
        // create the inner encapInfo
        ContentInfo encapInfo = new ContentInfo(CMCObjectIdentifiers.id_cct_PKIData, pkiData); // step 3
        
        msg = new CMSProcessableByteArray(envelopedPrivKey.getEncoded()); // step 2
        
        // creating SignedData and signerInfo -not done----------------------------
        SignerIdentifier signerId = new SignerIdentifier(DEROctetString.fromByteArray(subjectKeyIdentifier.getEncoded()));
        
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(eeKeyPair.getPrivate());

        JcaSignerInfoGeneratorBuilder signerInfobuilder = new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build());
        
        String szOID_ARCHIVED_KEY_ATTR = "1.3.6.1.4.1.311.21.13";
        signerInfobuilder.setUnsignedAttributeGenerator(null);
                
        gen.addSignerInfoGenerator(signerInfobuilder.build(sha256Signer, subjectKeyIdentifier.getEncoded())); // used subjectKeyIdentifier

        CMSSignedData sigData = gen.generate(msg, false);
        SignedData signedData = null;
        // ----------------------------------
        
        // outermost layer
        String szOID_RSA_signedData = "1.2.840.113549.1.7.2";
        ContentInfo info = new ContentInfo(PKCSObjectIdentifiers.signedData, signedData);
        
    }
}
