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
package org.cesecore.certificates.certificate.request;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Random;

import javax.crypto.Cipher;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmc.PKIData;
import org.bouncycastle.asn1.cmc.TaggedAttribute;
import org.bouncycastle.asn1.cmc.TaggedCertificationRequest;
import org.bouncycastle.asn1.cmc.TaggedRequest;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.certificate.CertificateCreateException;

import com.keyfactor.util.CertTools;

public class MsKeyArchivalRequestMessage extends PKCS10RequestMessage {

    private static final long serialVersionUID = -6190846421248462160L;
    private static final Logger log = Logger.getLogger(MsKeyArchivalRequestMessage.class);
    
    public static final ASN1ObjectIdentifier szOID_ARCHIVED_KEY_ATTR = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.13");
    public static final ASN1ObjectIdentifier szOID_ENCRYPTED_KEY_HASH = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.21");
    // optional: for later use
    public static final ASN1ObjectIdentifier szOID_REQUEST_CLIENT_INFO = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.21.20");
    
    private static final Map<ASN1ObjectIdentifier, String> hashAlgorithmMap = new HashMap<>();
    
    static {
        // TODO: move to x509-common-utils
        hashAlgorithmMap.put(PKCSObjectIdentifiers.sha1WithRSAEncryption,"SHA1");
        hashAlgorithmMap.put(PKCSObjectIdentifiers.sha224WithRSAEncryption,"SHA224");
        hashAlgorithmMap.put(PKCSObjectIdentifiers.sha256WithRSAEncryption,"SHA256");
        hashAlgorithmMap.put(PKCSObjectIdentifiers.sha384WithRSAEncryption,"SHA384");
        hashAlgorithmMap.put(PKCSObjectIdentifiers.sha512WithRSAEncryption,"SHA512");
        hashAlgorithmMap.put(PKCSObjectIdentifiers.sha512_224WithRSAEncryption,"SHA512(224)");
        hashAlgorithmMap.put(PKCSObjectIdentifiers.sha512_256WithRSAEncryption,"SHA512(256)");
        hashAlgorithmMap.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224,"SHA3-224");
        hashAlgorithmMap.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256,"SHA3-256");
        hashAlgorithmMap.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384,"SHA3-384");
        hashAlgorithmMap.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512,"SHA3-512");
    }

    private byte[] message;
    private byte[] encryptedPrivateKey;
    private PKIData pkiData;
    private KeyPair requestKeyPair;
    
    // private String kraReference; we may attach this from RA from MSAE alias and use it while adding recovery data

    public MsKeyArchivalRequestMessage() {

    }

    public MsKeyArchivalRequestMessage(byte[] msg) throws IOException {
        if (log.isTraceEnabled()) {
            log.trace(">MsKeyArchivalRequestMessage(byte[])");
        }
        this.message = msg;

        ContentInfo info = ContentInfo.getInstance(msg);
        SignedData signedData = SignedData.getInstance(info.getContent());
        ContentInfo contentInfo = signedData.getEncapContentInfo();
        DEROctetString octetData = (DEROctetString) DEROctetString.getInstance(contentInfo.getContent());

        pkiData = PKIData.getInstance(octetData.getOctets()); // need to unwrap manually(remove Tag and Length)
        for (TaggedRequest tr : pkiData.getReqSequence()) { // only one
            TaggedCertificationRequest tcr = TaggedCertificationRequest.getInstance(tr.getValue());
            p10msg = tcr.getCertificationRequest().getEncoded();
            pkcs10 = new JcaPKCS10CertificationRequest(p10msg);
        }
        if (log.isTraceEnabled()) {
            log.trace("<MsKeyArchivalRequestMessage(byte[])");
        }
    }

    public boolean verify() throws InvalidKeyException, NoSuchAlgorithmException {
        try {
            if (log.isTraceEnabled()) {
                log.trace(">verify()");
            }
            final ContentVerifierProvider verifierProvider;
            verifierProvider = CertTools.genContentVerifierProvider(pkcs10.getPublicKey());
            
            if (!pkcs10.isSignatureValid(verifierProvider)) {
                log.debug("Innner PKCS10 verification failed.");
                return false;
            }
            
            CMSSignedDataParser signedDataParser = new CMSSignedDataParser(
                    new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(), message);
            signedDataParser.getSignedContent().drain();
            
            SignerInformationStore signers = signedDataParser.getSignerInfos();
            
            if (signers.getSigners().size()!=1) {
                log.info("Verification failed: MS Key archival request should "
                        + "only be be signed with end entity(CSR) key.");
                return false;
            }
            
            SignerInformation signer = signers.getSigners().iterator().next();
            // verifies the outer request, with public key from CSR
            if(!signer.verify(
                    new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC")
                    .build(pkcs10.getPublicKey()))){
                log.debug("MS Key archival request outer signed data verification failed.");
                return false;
            }
                            
            AttributeTable attrTable = signer.getUnsignedAttributes();
            for(Attribute attr: attrTable.toASN1Structure().getAttributes()) {
                if(!attr.getAttrType().equals(szOID_ARCHIVED_KEY_ATTR)) {
                    continue;
                }
                encryptedPrivateKey = attr.getAttributeValues()[0].toASN1Primitive().getEncoded();
             }
            
            if (encryptedPrivateKey==null) {
                log.debug("MS Key archival request is malforemd does not contain the encrpyted private key.");
                return false;
            }
            
            // should also verify the private key hash as enveloped private key is not signed(unauthenticated)
            final MessageDigest md = MessageDigest.getInstance(
                    hashAlgorithmMap.get(pkcs10.getSignatureAlgorithm().getAlgorithm())); 
            pkcs10.getSignatureAlgorithm();
            final String envelopedPrivKeyHash = Hex.toHexString(md.digest(encryptedPrivateKey));
            
            for (TaggedAttribute ta: pkiData.getControlSequence()) {
                org.bouncycastle.asn1.ASN1Sequence asnseq = 
                        org.bouncycastle.asn1.ASN1Sequence.getInstance(ta.getAttrValues().getObjectAt(0).toASN1Primitive());
                ASN1Set asnset = ASN1Set.getInstance(asnseq.getObjectAt(2)); // to verify this index
                
                for (ASN1Encodable x: asnset) { // szOID_ENCRYPTED_KEY_HASH(first) + szOID_REQUEST_CLIENT_INFO(optional)
                    Attribute attr = Attribute.getInstance(x);
                    if(!attr.getAttrType().equals(szOID_ENCRYPTED_KEY_HASH)) {
                        continue;
                    }
                    if (attr.getAttributeValues().length!=1 || 
                            !Hex.toHexString(attr.getAttributeValues()[0].toASN1Primitive().getEncoded())
                                .endsWith(envelopedPrivKeyHash)) { // not unwrapping ASN1String
                        log.debug("MS Key archival request is private key hash did not match.");
                        return false;
                    }
                }
            }
            
            log.debug("verified MS key archival outer request.");
            return true;
        } catch (OperatorCreationException e) {
            log.error("Content verifier provider could not be created.", e);
            return false;
        } catch (PKCSException e) {
            log.error("Signature could not be processed.", e);
            return false;
        } catch (CMSException|IOException e) {
            log.error("CMS data could not be parsed.", e);
            return false;
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<verify()");
            }
        }
    }
    
    public void decryptPrivateKey(String provider, PrivateKey caEncryptionKey) throws CertificateCreateException {
        // TODO: untested
        if (log.isTraceEnabled()) {
            log.trace("<decryptPrivateKey()");
        }
        try {
            CMSEnvelopedDataParser ep = new CMSEnvelopedDataParser(encryptedPrivateKey);
            RecipientInformationStore recipients = ep.getRecipientInfos();

            if (recipients.getRecipients().size() != 1) {
                log.info("Decryption failed: MS Key archival should contain only one recepient.");
                return;
            }

            RecipientInformation recipient = recipients.getRecipients().iterator().next();
            CMSTypedStream recData = recipient.getContentStream(
                    new JceKeyTransEnvelopedRecipient(caEncryptionKey).setProvider(provider));
            byte[] encodedPrivateKey = recData.getContentStream().readAllBytes();
            
            System.out.println(Hex.toHexString(encodedPrivateKey));
            KeyFactory kf = KeyFactory.getInstance("RSA"); // signature and non-RSA keys are not supported
            PrivateKey requestPrivatekey = kf.generatePrivate(new PKCS8EncodedKeySpec(encodedPrivateKey));
            requestKeyPair = new KeyPair(getRequestPublicKey(), requestPrivatekey);
            
            testKeyPair();

        } catch (CMSException|IOException e) {
            throw new IllegalStateException(e);
        } catch (InvalidKeySpecException|InvalidKeyException e) {
            throw new IllegalStateException(e);
        } catch (NoSuchAlgorithmException e) {
            // nopmd
        }

        log.debug("decrypted MS key archival private key.");
        if (log.isTraceEnabled()) {
            log.trace(">decryptPrivateKey()");
        }
    }
    
    private void testKeyPair() throws CertificateCreateException {
        if (log.isTraceEnabled()) {
            log.trace("<testKeyPair()");
        }
        byte[] randomBytes = new byte[20];
        byte[] decryptedBytes = null;
        try {
            new Random().nextBytes(randomBytes);
            Cipher encCipher = Cipher.getInstance("RSA");
            encCipher.init(Cipher.ENCRYPT_MODE, requestKeyPair.getPublic());
            byte[] encryptedBytes = encCipher.doFinal(randomBytes);
            
            Cipher decCipher = Cipher.getInstance("RSA");
            decCipher.init(Cipher.DECRYPT_MODE, requestKeyPair.getPrivate());
            decryptedBytes = decCipher.doFinal(encryptedBytes);
                    
        } catch (Exception e) {
            log.info("MS key archival key testing failed", e);
        }
        
        if (decryptedBytes==null || !Objects.deepEquals(randomBytes, decryptedBytes)) {
            throw new CertificateCreateException("MS key archival keys are invalid or did not match.");
        }
        if (log.isTraceEnabled()) {
            log.trace(">testKeyPair()");
        }
    }
    
    public KeyPair getKeyPairToArchive() {
        return requestKeyPair;
    }

}
