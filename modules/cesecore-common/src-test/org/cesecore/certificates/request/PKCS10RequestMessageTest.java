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
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
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
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.crypto.util.AlgorithmIdentifierFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.junit.Test;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.keys.KeyTools;
import com.novell.ldap.asn1.ASN1Sequence;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

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
        System.out.println("pkidata: " + Hex.toHexString(pkiData.getEncoded()));
        
        // step 4: construct CMS
        
        // create the inner encapInfo
        ContentInfo encapInfo = new ContentInfo(CMCObjectIdentifiers.id_cct_PKIData, pkiData); // step 3
        
        msg = new CMSProcessableByteArray(encapInfo.getEncoded()); // step 2
        
        // creating SignedData and signerInfo -not done----------------------------
        //SignerIdentifier signerId = new SignerIdentifier(DEROctetString.fromByteArray(subjectKeyIdentifier.getEncoded()));
        
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(eeKeyPair.getPrivate());

        JcaSignerInfoGeneratorBuilder signerInfobuilder = new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build());
        
        String szOID_ARCHIVED_KEY_ATTR = "1.3.6.1.4.1.311.21.13";
        Attribute archivedAttribute = new Attribute(new ASN1ObjectIdentifier(szOID_ARCHIVED_KEY_ATTR), 
                                new DERSet(envelopedPrivKey.toASN1Structure()));
        AttributeTable attrTable = new AttributeTable(archivedAttribute);
        signerInfobuilder.setUnsignedAttributeGenerator(new SimpleAttributeTableGenerator(attrTable));
                
        gen.addSignerInfoGenerator(signerInfobuilder.build(sha256Signer, subjectKeyIdentifier.getEncoded())); // used subjectKeyIdentifier

        CMSSignedData sigData = gen.generate(msg, false);
        SignedData signedData = null;
        ContentInfo info = sigData.toASN1Structure();
        
        System.out.println(Base64.toBase64String(info.getEncoded()));
        // ----------------------------------
        
        // outermost layer
        String szOID_RSA_signedData = "1.2.840.113549.1.7.2";
        //ContentInfo info = new ContentInfo(PKCSObjectIdentifiers.signedData, signedData);
        
    }
    
    @Test
    public void testKeyArchivalMessageParsing() throws Exception {
        CMSSignedDataParser sp = new CMSSignedDataParser(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(), Hex.decode(SAMPLE_REQUEST));
        
        sp.getSignedContent().drain();
        
        //byte[] signedContent = sp.getSignedContent().getContentStream().readAllBytes();

        Store certStore = sp.getCertificates();
        SignerInformationStore  signers = sp.getSignerInfos();
        
        Collection c = signers.getSigners();
        Iterator it = c.iterator();

        while (it.hasNext()) {
            SignerInformation signer = (SignerInformation)it.next();
            System.out.println(signer.getDigestAlgOID());
            System.out.println(signer.getEncryptionAlgOID());
            System.out.println(signer.getContentType());
            //System.out.println(Hex.toHexString(signer.getContentDigest()));
            
            AttributeTable attrTable = signer.getUnsignedAttributes();
            for(Attribute attr: attrTable.toASN1Structure().getAttributes()) {
                byte[] attrValue = attr.getAttributeValues()[0].toASN1Primitive().getEncoded();
                System.out.println("attr: " + attr.getAttrType() + " : " + 
                               Hex.toHexString(attrValue));
                
                CMSEnvelopedDataParser     ep = new CMSEnvelopedDataParser(attrValue);
                RecipientInformationStore  recipients = ep.getRecipientInfos();

                Collection  c2 = recipients.getRecipients();
                Iterator it2 = c2.iterator();
                
                if (it2.hasNext())
                {
                    RecipientInformation recipient = (RecipientInformation)it2.next();
                    
                    PrivateKey privateKey = null;
                    CMSTypedStream recData = recipient.getContentStream(new JceKeyTransEnvelopedRecipient(privateKey).setProvider("BC"));
                    recData.getContentStream();
                    
                    System.out.println(recipient.getContentType());
                }
            }
        }
    }
    
    @Test
    public void testKeyArchivalMessageParsingWorking() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        ContentInfo info = ContentInfo.getInstance(Hex.decode(SAMPLE_REQUEST));
        
        System.out.println(info.getContentType());
        
        SignedData signedData = SignedData.getInstance(info.getContent());
        ContentInfo contentInfo = signedData.getEncapContentInfo();
        System.out.println(contentInfo.getContentType());
        String content = Hex.toHexString(contentInfo.getContent().toASN1Primitive().getEncoded());
        System.out.println(content.substring(8)); // strange
        
        PKIData pkiData = PKIData.getInstance(Hex.decode(content.substring(8)));
        PublicKey eePubKey = null;
        for (TaggedRequest tr: pkiData.getReqSequence()) { // only one
            TaggedCertificationRequest tcr = TaggedCertificationRequest.getInstance(tr.getValue());
            
            // got the CSR
            final PKCS10RequestMessage pkcs10 = new PKCS10RequestMessage(tcr.getCertificationRequest().getEncoded());
            pkcs10.verify();
            // repeating the pkcs10 testSerilaizeDeserialize
            try (final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
                try (final ObjectOutputStream oos = new ObjectOutputStream(byteArrayOutputStream)) {
                    oos.writeObject(pkcs10);
                }
                try (final ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()))) {
                    final PKCS10RequestMessage deserializedPkcs10 = (PKCS10RequestMessage) ois.readObject();
                    assertNotNull("Could not deserialize, getPublicKey() == null", deserializedPkcs10.getRequestPublicKey());
                    assertEquals("CN=TestCN,O=TestOrg", deserializedPkcs10.getRequestDN());
                    eePubKey = deserializedPkcs10.getRequestPublicKey();
                }
            }
        }
        
        for (TaggedAttribute ta: pkiData.getControlSequence()) {
            System.out.println(ta.getAttrType());
            System.out.println(Hex.toHexString(ta.getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded()));
            org.bouncycastle.asn1.ASN1Sequence asnseq = 
                    org.bouncycastle.asn1.ASN1Sequence.getInstance(ta.getAttrValues().getObjectAt(0).toASN1Primitive());
            ASN1Set asnset = ASN1Set.getInstance(asnseq.getObjectAt(2));
            
            for (ASN1Encodable x: asnset) { // szOID_ENCRYPTED_KEY_HASH(first) + szOID_REQUEST_CLIENT_INFO(optional)
                Attribute attr = Attribute.getInstance(x);
                System.out.println(attr.getAttrType());
            }
        }
        
        CMSSignedDataParser sp = new CMSSignedDataParser(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(), Hex.decode(SAMPLE_REQUEST));
        
        sp.getSignedContent().drain();
        
        //byte[] signedContent = sp.getSignedContent().getContentStream().readAllBytes();

        Store certStore = sp.getCertificates();
        SignerInformationStore  signers = sp.getSignerInfos();
        
        Collection c = signers.getSigners();
        Iterator it = c.iterator();

        while (it.hasNext()) { // only one
            SignerInformation   signer = (SignerInformation)it.next();
            // verifies the outer request, with public key from CSR
            System.out.println("verify returns: " + signer.verify(
                    new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(eePubKey)));
            
            System.out.println(signer.getUnsignedAttributes().size());
            
            AttributeTable attrTable = signer.getUnsignedAttributes();
            for(Attribute attr: attrTable.toASN1Structure().getAttributes()) { // only one
                byte[] attrValue = attr.getAttributeValues()[0].toASN1Primitive().getEncoded();
                System.out.println("attr: " + attr.getAttrType() + " : " + // szOID_ARCHIVED_KEY_ATTR
                               Hex.toHexString(attrValue)); // private key encrypted and enveloped
                
                // we can parse and decrypt the DES3 key manually and then get the private key by decrypting wth DES3
                // or with BC wrapper CMSEnvelopedDataParser, 
                // we can try this only with real test data where private key is known
                
//                CMSEnvelopedDataParser     ep = new CMSEnvelopedDataParser(attrValue);
//                RecipientInformationStore  recipients = ep.getRecipientInfos();
//
//                Collection  c2 = recipients.getRecipients();
//                Iterator it2 = c2.iterator();
//                
//                if (it2.hasNext())
//                {
//                    RecipientInformation recipient = (RecipientInformation)it2.next();
//                    
//                    PrivateKey privateKey = null;
//                    CMSTypedStream recData = recipient.getContentStream(new JceKeyTransEnvelopedRecipient(privateKey).setProvider("BC"));
//                    recData.getContentStream();
//                    
//                    System.out.println(recipient.getContentType());
//                }
            }
        }
    }
    
    private static final String SAMPLE_REQUEST = "308208a906092a864886f70d010702a082089a30820896020103310b300906052b0e0"
            + "3021a0500308203e506082b06010505070c02a08203d7048203d3308203cf3081a030819d020102060a2b0601040182370a0a013"
            + "1818b3081880201003003020101317e302306092b0601040182371515311604147746e7e66bb597a67d08bf6e059c79e16dd66b8"
            + "3305706092b0601040182371514314a30480201090c237669636833642e6a646f6d6373632e6e74746573742e6d6963726f736f6"
            + "6742e636f6d0c154a444f4d4353435c61646d696e6973747261746f720c076365727472657130820324a08203200201013082031"
            + "9308202820201003023310f300d0603550403130654657374434e3110300e060355040a1307546573744f726730819f300d06092"
            + "a864886f70d010101050003818d0030818902818100dab2cc813700c9c8a0903da0f6b7a76880bf43441962fd9b713249c0b0a34"
            + "554d1e524c1cde3e6458a2de53fefcd7eebbc68de7488117661f37765c69c54ee546df9e59bc7ec8215bd6b15889793ec0d0aefa"
            + "85ede0ce794e07de73d44a4771dbdd803dfbfb489a1883c8572e336967ce07fe4ac848a696e02690be453fb2c950203010001a08"
            + "201b4301a060a2b0601040182370d0203310c160a362e302e353336312e323042060a2b0601040182370d0201313430321e26004"
            + "3006500720074006900660069006300610074006500540065006d0070006c0061007400651e080055007300650072305706092b0"
            + "601040182371514314a30480201090c237669636833642e6a646f6d6373632e6e74746573742e6d6963726f736f66742e636f6d0"
            + "c154a444f4d4353435c61646d696e6973747261746f720c07636572747265713074060a2b0601040182370d02023166306402010"
            + "11e5c004d006900630072006f0073006f0066007400200045006e00680061006e006300650064002000430072007900700074006"
            + "f0067007200610070006800690063002000500072006f00760069006400650072002000760031002e003003010030818206092a8"
            + "64886f70d01090e31753073301706092b0601040182371402040a1e08005500730065007230290603551d2504223020060a2b060"
            + "1040182370a030406082b0601050507030406082b06010505070302300e0603551d0f0101ff0404030205a0301d0603551d0e041"
            + "6041415bbba05358d0b21fb5db0f4a38fe3bf0f2ce0c5300d06092a864886f70d0101050500038181006ac9bc0cf7675e9161c78"
            + "ce7df37dc5fcc59cb38c071e61748cbf1d615f28161a330a8242f5d661094d3813445dffa3963ffc617a84ae545f9e814e2aaf4e"
            + "50cde845cf279c5e4419180b975d50c0df708c2adc790be8ff51f9d47e4b750ffaf40b6e21a9986d864dce2d4e41d82c66eab458"
            + "c7be3b5dcd8feaf9978cb1b7086300030003182049930820495020103801415bbba05358d0b21fb5db0f4a38fe3bf0f2ce0c5300"
            + "906052b0e03021a0500a03e301706092a864886f70d010903310a06082b06010505070c02302306092a864886f70d01090431160"
            + "414e088afba3f9bde527ff0887fced97debfa363f72300d06092a864886f70d01010105000481804505b61926013cc202172d9e1"
            + "d194df8ff4358e5544a24525b93e636005bbaaebfbc70d9c7f5d149e9e36ebdb7ac33c9147a81b59eb1a97c2287588b9028874f8"
            + "65b016ecb6fde4a6689e6e5bcaed259b5882381a552a071f0b0d457b8ac64fca03b7bbd8a5e571a711c4705708f27bc7a25beda7"
            + "910d083e08ac3f8d1ff513aa182039b3082039706092b060104018237150d318203883082038406092a864886f70d010703a0820"
            + "375308203710201003181ea3081e70201003050304231123010060355040a13094d6963726f736f6674312c302a0603550403132"
            + "34a444f4d435343204c6f6e67686f726e20456e746572707269736520526f6f74204341020a488a9b22000000000a39300d06092"
            + "a864886f70d0101010500048180960b583191d1fdd1ee45ccfa7a368ca09fb52df2a07def463b1a33a3bf861f00fb3b237cdb504"
            + "e5303e9c147a0186e4bba4a63df419395e6d56b03b117363adba12870f814c45d9e5e4414ae4947e22f357c9e8d9245c9fbe0bc3"
            + "8c9d674cdd93eaf70664476b9943c980b717a5a363ba72d45aa3d816eaf42a89631b1a76d263082027d06092a864886f70d01070"
            + "1301406082a864886f70d030704086cd44389e15a7fc380820258fae61aa513fcae9caefc78fe0b8f0698dcc5f3fd71e29a17488"
            + "65f30edcc4631a90ebead68ff6cfe7ecf6bfdeb647cde6eafe1a9956782388e0c9011f0fb976489701fdd38b3fddf73bf90e39f2"
            + "b11d664798ec3571264fea37c47958860c2193f454cbb48273f1db3b45c800161a4b677b27e22039418181b38e86ef01379c219f"
            + "54e43f5131ea035a9a9fdf2cf14ab2ab41618c0b6fd43d8a9672ee1a7d587a27d8460ecfe441c74cc2c7a9c2272a5d944d154185"
            + "bfc6bfef08bfd09dbe76100fe2abb421c549099df83f1915d22076fcc908445206fc3ed97b243adae5eabdcab69f857aefbb37b4"
            + "e1381b134a0171774e921d1a76870d6f69639924fe26f88ca6d318db267043e39234d1eefcbc8ef34ded1a02a95c3aec792ee136"
            + "cdeeb72e02cbb7b721d03df60c5bfae61bbf7742a0f1855c1c83652cfbf2c5b7704d7615524b85ce13851dd909d6bfd55644d7bf"
            + "045b660f998f1026a74841b4f9016945924988c84c0459f9bea120ebff3ac629f254e1281f5b5f9a0fb3add3883b87753672104b"
            + "6b2bf580cdf64b9da6cd51391a1e4dc007a527e9e6be1ee8ab4eb6349babc605a5de21f62949ee1e7773e12c607d0cb5bd4e33b6"
            + "5ac0ce0cd413af1072f3b8dea07fbe9bdcde0ba1f93767cac5276f48224eaddf8b4cff3a8cdbfe8d7fa9281bc549486533edd218"
            + "5344660ddc0af797887e2a322e52d6cb250211482260b369a0bd0897c93f763671e72ea2470916c68902fb6e687f4e7f0d1eec87"
            + "c1b15a5a978d24d10362ad4e67494c267d02f987815e735ac1e723101baae7e6e7c5154693c5cbd023289392fffdb58644971dfc"
            + "7f8fb";
}
