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

package org.ejbca.core.protocol.cmp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIFreeText;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIMessages;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.POPOPrivKey;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.util.Base64;
import org.ejbca.core.model.InternalEjbcaResources;

/**
 * Helper class to create different standard parts of CMP messages
 * 
 * @version $Id$
 */
public class CmpMessageHelper {
    private static Logger LOG = Logger.getLogger(CmpMessageHelper.class);
    private static final InternalEjbcaResources INTRES = InternalEjbcaResources.getInstance();
    private static final SecureRandom secureRandom = new SecureRandom();

    private static final String CMP_ERRORGENERAL = "cmp.errorgeneral";
    public static final int MAX_LEVEL_OF_NESTING = 15;

    /** Array that converts our error codes from FailInfo to CMP BITString error codes. FailInfo use plain integer codes, which are
     * the same as positions in the CMP bit string
     * @see org.bouncycastle.asn1.cmp.PKIFailureInfo
     */
    private static int[] bcconversion = { PKIFailureInfo.badAlg, PKIFailureInfo.badMessageCheck, PKIFailureInfo.badRequest, PKIFailureInfo.badTime,
            PKIFailureInfo.badCertId, PKIFailureInfo.badDataFormat, PKIFailureInfo.wrongAuthority, PKIFailureInfo.incorrectData,
            PKIFailureInfo.missingTimeStamp, PKIFailureInfo.badPOP, PKIFailureInfo.certRevoked, PKIFailureInfo.certConfirmed,
            PKIFailureInfo.wrongIntegrity, PKIFailureInfo.badRecipientNonce, PKIFailureInfo.timeNotAvailable, PKIFailureInfo.unacceptedPolicy,
            PKIFailureInfo.unacceptedExtension, PKIFailureInfo.addInfoNotAvailable, PKIFailureInfo.badSenderNonce, PKIFailureInfo.badCertTemplate,
            PKIFailureInfo.signerNotTrusted, PKIFailureInfo.transactionIdInUse, PKIFailureInfo.unsupportedVersion, PKIFailureInfo.notAuthorized,
            PKIFailureInfo.systemUnavail, PKIFailureInfo.systemFailure, PKIFailureInfo.duplicateCertReq };

    /** Returns the PKIFailureInfo that is the correct format for CMP, i.e. a DERBitString as specified in PKIFailureInfo.
     * @see org.bouncycastle.asn1.cmp.PKIFailureInfo
     * @see org.cesecore.certificates.certificate.request.FailInfo
     * 
     * @param failInfo
     * @return PKIFailureInfo for use in CMP error messages
     */
    public static PKIFailureInfo getPKIFailureInfo(int failInfo) {
        return new PKIFailureInfo(bcconversion[failInfo]);
    }

    public static PKIHeaderBuilder createPKIHeaderBuilder(GeneralName sender, GeneralName recipient, String senderNonce, String recipientNonce,
            String transactionId) {
        PKIHeaderBuilder pkiHeader = new PKIHeaderBuilder(PKIHeader.CMP_2000, sender, recipient);
        pkiHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        if (senderNonce != null) {
            pkiHeader.setSenderNonce(new DEROctetString(Base64.decode(senderNonce.getBytes())));
        }
        if (recipientNonce != null) {
            pkiHeader.setRecipNonce(new DEROctetString(Base64.decode(recipientNonce.getBytes())));
        }
        if (transactionId != null) {
            pkiHeader.setTransactionID(new DEROctetString(Base64.decode(transactionId.getBytes())));
        }
        return pkiHeader;
    }

    public static byte[] signPKIMessage(PKIMessage pkiMessage, Collection<Certificate> signCertChain, PrivateKey signKey, String digestAlg,
            String provider) throws InvalidKeyException, NoSuchProviderException, NoSuchAlgorithmException, SecurityException, SignatureException,
            CertificateEncodingException {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">signPKIMessage()");
        }
        final List<CMPCertificate> extraCertsList = new ArrayList<>();
        for (final Certificate certificate : signCertChain) {
            extraCertsList.add(CMPCertificate.getInstance(((X509Certificate)certificate).getEncoded()));
        }
        final CMPCertificate[] extraCerts = extraCertsList.toArray(new CMPCertificate[signCertChain.size()]);
        final PKIMessage signedPkiMessage = buildCertBasedPKIProtection(pkiMessage, extraCerts, signKey, digestAlg, provider);
        if (LOG.isTraceEnabled()) {
            LOG.trace("<signPKIMessage()");
        }
        // Return response as byte array 
        return pkiMessageToByteArray(signedPkiMessage);
    }

    public static PKIMessage buildCertBasedPKIProtection(PKIMessage pkiMessage, CMPCertificate[] extraCerts, PrivateKey key, String digestAlg,
            String provider) throws NoSuchProviderException, NoSuchAlgorithmException, SecurityException, SignatureException, InvalidKeyException {
        // Select which signature algorithm we should use for the response, based on the digest algorithm and key type.
        ASN1ObjectIdentifier oid = AlgorithmTools.getSignAlgOidFromDigestAndKey(digestAlg, key.getAlgorithm());
        if (LOG.isDebugEnabled()) {
            LOG.debug("Selected signature alg oid: " + oid.getId()+", key algorithm: "+key.getAlgorithm());
        }
        // According to PKCS#1 AlgorithmIdentifier for RSA-PKCS#1 has null Parameters, this means a DER Null (asn.1 encoding of null), not Java null.
        // For the RSA signature algorithms specified above RFC3447 states "...the parameters MUST be present and MUST be NULL."
        PKIHeaderBuilder headerBuilder = getHeaderBuilder(pkiMessage.getHeader());
        AlgorithmIdentifier pAlg = null;
        if ("RSA".equalsIgnoreCase(key.getAlgorithm())) {
            pAlg = new AlgorithmIdentifier(oid, DERNull.INSTANCE);
        } else {
            pAlg = new AlgorithmIdentifier(oid);
        }
        headerBuilder.setProtectionAlg(pAlg);
        // Most PKCS#11 providers don't like to be fed an OID as signature algorithm, so 
        // we use BC classes to translate it into a signature algorithm name instead
        PKIHeader head = headerBuilder.build();
        String signatureAlgorithmName = AlgorithmTools.getAlgorithmNameFromOID(oid);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signing CMP message with signature alg: " + signatureAlgorithmName);
        }
        Signature sig = Signature.getInstance(signatureAlgorithmName, provider);
        sig.initSign(key);
        sig.update(getProtectedBytes(head, pkiMessage.getBody()));
        final PKIMessage protectedPkiMessage;
        if (extraCerts != null && extraCerts.length > 0) {
            protectedPkiMessage = new PKIMessage(head, pkiMessage.getBody(), new DERBitString(sig.sign()), extraCerts);
        } else {
            protectedPkiMessage = new PKIMessage(head, pkiMessage.getBody(), new DERBitString(sig.sign()));
        }
        return protectedPkiMessage;
    }

    //TODO see if we could do this in a better way
    public static PKIHeaderBuilder getHeaderBuilder(PKIHeader head) {
        PKIHeaderBuilder builder = new PKIHeaderBuilder(head.getPvno().getValue().intValue(), head.getSender(), head.getRecipient());
        builder.setFreeText(head.getFreeText());
        builder.setGeneralInfo(head.getGeneralInfo());
        builder.setMessageTime(head.getMessageTime());
        builder.setRecipKID((DEROctetString) head.getRecipKID());
        builder.setRecipNonce(head.getRecipNonce());
        builder.setSenderKID(head.getSenderKID());
        builder.setSenderNonce(head.getSenderNonce());
        builder.setTransactionID(head.getTransactionID());
        return builder;
    }

    /** verifies signature protection on CMP PKI messages
     *  
     * @param pKIMessage the CMP message to verify signature on, if protected by signature protection
     * @param pubKey the public key used to verify the signature
     * @return true if verification is ok or false if verification fails
     * @throws NoSuchAlgorithmException message is signed by an unknown algorithm
     * @throws InvalidKeyException pubKey is not valid for signature verification
     * @throws SignatureException if the passed-in signature is improperly encoded or of the wrong type, if this signature algorithm is unable to process the input data provided, etc.
     */
    public static boolean verifyCertBasedPKIProtection(PKIMessage pKIMessage, PublicKey pubKey) throws NoSuchAlgorithmException,
             InvalidKeyException, SignatureException {
        if(pKIMessage.getProtection() == null) {
            throw new SignatureException("Message was not signed.");
        }
        AlgorithmIdentifier sigAlg = pKIMessage.getHeader().getProtectionAlg();
        if(sigAlg == null) {
            throw new SignatureException("No signature algorithm was provided.");
        }
      
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verifying signature with algorithm: " + sigAlg.getAlgorithm().getId());
        }
        Signature sig;
        try {
            sig = Signature.getInstance(sigAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle provider not installed.", e);
        }
        sig.initVerify(pubKey);
        sig.update(getProtectedBytes(pKIMessage));
        boolean result = sig.verify(pKIMessage.getProtection().getBytes());
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verification result: " + result);
        }
        return result;
    }
        
    public static byte[] protectPKIMessageWithPBE(PKIMessage msg, String keyId, String raSecret, String digestAlgId, String macAlgId,
            int iterationCount) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">protectPKIMessageWithPBE()");
        }
        // Create the PasswordBased protection of the message
        PKIHeaderBuilder head = getHeaderBuilder(msg.getHeader());
        byte[] keyIdBytes = keyId.getBytes(StandardCharsets.UTF_8);
        head.setSenderKID(new DEROctetString(keyIdBytes));
        // SHA1
        AlgorithmIdentifier owfAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier(digestAlgId));
        // iterations, usually something like 1024
        ASN1Integer iteration = new ASN1Integer(iterationCount);
        // HMAC/SHA1
        AlgorithmIdentifier macAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier(macAlgId));
        // We need some random bytes for the nonce
        byte[] saltbytes = createSenderNonce();
        DEROctetString derSalt = new DEROctetString(saltbytes);

        // Create the new protected return message
        //String objectId = "1.2.840.113533.7.66.13" = passwordBasedMac;
        String objectId = CMPObjectIdentifiers.passwordBasedMac.getId();
        PBMParameter pp = new PBMParameter(derSalt, owfAlg, iteration, macAlg);
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier(objectId), pp);
        head.setProtectionAlg(pAlg);

        // Calculate the protection bits
        byte[] rasecret = raSecret.getBytes();
        byte[] basekey = new byte[rasecret.length + saltbytes.length];
        System.arraycopy(rasecret, 0, basekey, 0, rasecret.length);
        System.arraycopy(saltbytes, 0, basekey, rasecret.length, saltbytes.length);
        // Construct the base key according to rfc4210, section 5.1.3.1
        MessageDigest dig = MessageDigest.getInstance(owfAlg.getAlgorithm().getId(), "BC");
        for (int i = 0; i < iterationCount; i++) {
            basekey = dig.digest(basekey);
            dig.reset();
        }

        PKIHeader pkiHeader = head.build();
        // Do the mac
        String macOid = macAlg.getAlgorithm().getId();
        byte[] protectedBytes = getProtectedBytes(pkiHeader, msg.getBody());
        Mac mac = Mac.getInstance(macOid, BouncyCastleProvider.PROVIDER_NAME);
        SecretKey key = new SecretKeySpec(basekey, macOid);
        mac.init(key);
        mac.reset();
        mac.update(protectedBytes, 0, protectedBytes.length);
        byte[] out = mac.doFinal();
        DERBitString bs = new DERBitString(out);

        if (LOG.isTraceEnabled()) {
            LOG.trace("<protectPKIMessageWithPBE()");
        }
        // Return response as byte array 
        return pkiMessageToByteArray(new PKIMessage(pkiHeader, msg.getBody(), bs, msg.getExtraCerts()));
    }

    /** @return response as byte array */ 
    public static byte[] pkiMessageToByteArray(final PKIMessage pkiMessage) {
        try {
            return pkiMessage.getEncoded();
        } catch (IOException e) {
            throw new IllegalStateException("Caught unexpected IOException.", e);
        }
    }

    /** 
     * Creates a 16 bytes random sender nonce.
     * 
     * @return byte array of length 16
     */
    public static byte[] createSenderNonce() {
        byte[] senderNonce = new byte[16];
        secureRandom.nextBytes(senderNonce);
        return senderNonce;
    }

    /** Creates a very simple error message in response to msg (that's why we switch sender and recipient) */
    public static ResponseMessage createUnprotectedErrorMessage(BaseCmpMessage cmpRequestMessage, FailInfo failInfo, String failText) {
        return createUnprotectedErrorMessage(cmpRequestMessage.getHeader(), failInfo, failText);
    }
    
    /**
     * Create a standard error message with PKIStatus.rejection and PKIFailureInfo.badRequest.
     * @return The byte representation of the error message
     */
    public static byte[] createUnprotectedErrorMessage() {
        final PKIHeader pkiHeader = new PKIHeaderBuilder(PKIHeader.CMP_2000, PKIHeader.NULL_NAME, PKIHeader.NULL_NAME).
                build();
        final ErrorMsgContent errorMessage = new ErrorMsgContent(
                new PKIStatusInfo(PKIStatus.rejection, 
                        new PKIFreeText("Not a valid CMP message."), 
                        new PKIFailureInfo(PKIFailureInfo.badRequest))); 
        final PKIBody pkiBody = new PKIBody(PKIBody.TYPE_ERROR, errorMessage);
        final PKIMessage pkiResponse = new PKIMessage(pkiHeader, pkiBody);
        return CmpMessageHelper.pkiMessageToByteArray(pkiResponse);
    }
    
    /**
     * Create an unsigned RFC 4210 error message as described in section 5.3.21 based on a raw PKIMessage obtained from
     * a previous CMP client request message. The byte representation of the message must be checked for validity before
     * being passed to this method.
     * @param pkiHeader A PKIHeader extracted from the previous CMP request
     * @param failInfo An error code describing the type of error
     * @param failText A human-readable description of the error
     * @return An <code>org.cesecore.certificates.certificate.request.ResponseMessage</code> data structure containing the error
     */
    public static ResponseMessage createUnprotectedErrorMessage(final byte[] pkiRequestBytes, final FailInfo failInfo, final String failText) {
        final PKIMessage pkiRequest = PKIMessage.getInstance(pkiRequestBytes);
        if (pkiRequest == null) {
            throw new IllegalStateException("Cannot create CMP error message because I was unable to parse your CMP request.");
        }
        return createUnprotectedErrorMessage(pkiRequest.getHeader(), failInfo, failText);
    }
    
    /**
     * Create an unsigned RFC 4210 error message as described in section 5.3.21 based on a PKIHeader obtained from
     * a previous CMP client request message.
     * @param pkiHeader A PKIHeader extracted from the previous CMP request
     * @param failInfo An error code describing the type of error
     * @param failText A human-readable description of the error
     * @return An <code>org.cesecore.certificates.certificate.request.ResponseMessage</code> data structure containing the error
     */
    public static ResponseMessage createUnprotectedErrorMessage(PKIHeader pkiHeader, FailInfo failInfo, String failText) {
        final CmpErrorResponseMessage resp = new CmpErrorResponseMessage(); 
        try {
            if (pkiHeader == null) {
                pkiHeader = new PKIHeader(PKIHeader.CMP_2000, PKIHeader.NULL_NAME, PKIHeader.NULL_NAME);
            }
            // Create a failure message
            if (LOG.isDebugEnabled()) {
                LOG.debug("Creating an unprotected error message with failInfo=" + failInfo + ", failText=" + failText);
            }
            resp.setSenderNonce(new String(Base64.encode(createSenderNonce())));
            // Sender nonce is optional and might not always be included
            if (pkiHeader.getSenderNonce() != null) {
                resp.setRecipientNonce(new String(Base64.encode(pkiHeader.getSenderNonce().getOctets())));
            }
            resp.setSender(pkiHeader.getRecipient());
            resp.setRecipient(pkiHeader.getSender());
            if (pkiHeader.getTransactionID() != null) {
                resp.setTransactionId(new String(Base64.encode(pkiHeader.getTransactionID().getOctets())));
            } else {
                // Choose a random transaction ID if the client did not provide one
                resp.setTransactionId(new String(Base64.encode(createSenderNonce())));
            }
            resp.setFailInfo(failInfo);
            resp.setFailText(failText);
            resp.create();
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException e) {
            LOG.error("Exception during CMP processing: ", e);
        } 
        return resp;
    }
    
    /**
     * creates a simple error message in response to msg.
     * 
     * The protection parameters can be null to create an unprotected message
     * 
     * @return IResponseMessage that can be sent to user
     */
    public static CmpErrorResponseMessage createErrorMessage(BaseCmpMessage msg, FailInfo failInfo, String failText, int requestId, int requestType,
            CmpPbeVerifyer verifyer, String keyId, String responseProt) {
        final CmpErrorResponseMessage cresp = new CmpErrorResponseMessage();
        cresp.setRecipientNonce(msg.getSenderNonce());
        cresp.setSenderNonce(new String(Base64.encode(createSenderNonce())));
        cresp.setSender(msg.getRecipient());
        cresp.setRecipient(msg.getSender());
        if (msg.getTransactionId() != null) {
            cresp.setTransactionId(msg.getTransactionId());
        } else {
            // Choose a random transaction ID if the client did not provide one
            cresp.setTransactionId(new String(Base64.encode(createSenderNonce())));
        }
        cresp.setFailText(failText);
        cresp.setFailInfo(failInfo);
        cresp.setRequestId(requestId);
        cresp.setRequestType(requestType);
        // Set all protection parameters, this is another message than if we generated a cert above
        if (verifyer != null) {
            final String pbeDigestAlg = verifyer.getOwfOid();
            final String pbeMacAlg = verifyer.getMacOid();
            final int pbeIterationCount = verifyer.getIterationCount();
            final String raAuthSecret = verifyer.getLastUsedRaSecret();
            if (StringUtils.equals(responseProt, "pbe") && (pbeDigestAlg != null) && (pbeMacAlg != null) && (keyId != null) && (raAuthSecret != null)) {
                cresp.setPbeParameters(keyId, raAuthSecret, pbeDigestAlg, pbeMacAlg, pbeIterationCount);
            }
        }
        try {
            // Here we need to create the response message, when coming from SignSession it has already been "created"
            cresp.create();
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException e) {
            LOG.error(INTRES.getLocalizedMessage(CMP_ERRORGENERAL), e);
        } 
        return cresp;
    }

    /**
     * creates a very simple error message in response to msg (that's why we switch sender and recipient)
     */
    public static PKIBody createCertRequestRejectBody(PKIStatusInfo pkiStatusInfo, int requestId, int requestType) {
        // Create a failure message
        if (LOG.isDebugEnabled()) {
            LOG.debug("Creating a CertRepMessage 'rejected'");
        }
        CertResponse[] certResponses = { new CertResponse(new ASN1Integer(requestId), pkiStatusInfo) };
        CertRepMessage certRepMessage = new CertRepMessage(null, certResponses);
        int respType = requestType + 1; // 1 = intitialization response, 3 = certification response etc
        if (LOG.isDebugEnabled()) {
            LOG.debug("Creating response body of type " + respType);
        }
        return new PKIBody(respType, certRepMessage);
    }

    /**
     * Converts the header and the body of a PKIMessage to an ASN1Encodable and 
     * returns the as a byte array
     * 
     * @param msg
     * @return the PKIMessage's header and body in byte array
     */
    public static byte[] getProtectedBytes(PKIMessage msg) {
        return getProtectedBytes(msg.getHeader(), msg.getBody());
    }

    /**
     * Converts the header and the body of a PKIMessage to an ASN1Encodable and 
     * returns the as a byte array
     *  
     * @param header
     * @param body
     * @return the PKIMessage's header and body in byte array
     */
    public static byte[] getProtectedBytes(PKIHeader header, PKIBody body) {
        byte[] res = null;
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(header);
        v.add(body);
        ASN1Encodable protectedPart = new DERSequence(v);
        try {
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(protectedPart);
            res = bao.toByteArray();
        } catch (Exception ex) {
            LOG.error(ex.getLocalizedMessage(), ex);
        }
        return res;
    }

    /**
     * Parses a CRMF request created with novosec library classes and return a bouncycastle CertReqMsg object
     * 
     * @param messages
     * @return
     */
    public static CertReqMsg getNovosecCertReqMsg(CertReqMessages messages) {
        // The encoding of the ProofOfPosession in bouncycastle and novosec is different.
        // Novosec generator explicitly tags the PopoSigningKey while it should be implicitly tagged.
        // Through novosec, the ProofOfPosession comes through as:
        //         Sequence
        //             DERSequence
        //                 DERSequence
        //                     ObjectIdentifier(1.2.840.113549.1.1.5)
        //                 DERBitString[64,0]
        //
        // But it should be:
        //         DERSequence
        //             DERSequence
        //                 ObjectIdentifier(1.2.840.113549.1.1.5)
        //             DERBitString[64,0]
        //
        // The bouncycastle parser expects an implicit tag, so to it, it looks like the sequence is containing a single element.
        //--------------------------------------
        // A comment from bouncycastle that might not effect anything here but maybe effect something else in the future: 
        //         What's happened is the novosec generator has explicitly tagged the PopoSigningKey structure, it should be 
        //         implicitly tagged (this isn't true if it's a POPOPrivKey, but that's because it's a CHOICE item so the tag 
        //         has to be preserved, but that is a different story).

        // Reconstructing the CertRequest
        ASN1Encodable o2 = ((DERSequence) messages.toASN1Primitive()).getObjectAt(0);
        ASN1Encodable o3 = ((DERSequence) o2).getObjectAt(0);
        CertRequest cr = CertRequest.getInstance(o3);

        // Reconstructing the proof-of-posession
        ASN1TaggedObject o4 = (ASN1TaggedObject) ((DERSequence) o2).getObjectAt(1);
        ProofOfPossession pp;
        int tagnr = o4.getTagNo();
        ASN1Encodable o5;
        switch (tagnr) {
        case 0:
            o5 = DERNull.INSTANCE;
            pp = new ProofOfPossession();
            break;
        case 1:
            o5 = POPOSigningKey.getInstance(o4.getObject());
            pp = new ProofOfPossession((POPOSigningKey) o5);
            break;
        case 2:
        case 3:
            o5 = POPOPrivKey.getInstance(o4, false);
            pp = new ProofOfPossession(tagnr, (POPOPrivKey) o5);
            break;
        default:
            throw new IllegalArgumentException("unknown tag: " + tagnr);
        }

        // Reconstructing the regToken
        ASN1Sequence o6 = (ASN1Sequence) ((ASN1Sequence) o2.toASN1Primitive()).getObjectAt(2);
        final AttributeTypeAndValue av = AttributeTypeAndValue.getInstance(((ASN1Sequence) o6).getObjectAt(0));
        final AttributeTypeAndValue[] avs = { av };

        // finally, recreating the CertReqMsg object
        return new CertReqMsg(cr, pp, avs);
    }

    public static RevDetails getNovosecRevDetails(RevReqContent revContent) {
        // Novosec implements RFC2510, while bouncycastle 1.47 implements RFC4210.
        //
        // In RFC2510/novosec, the RevDetails structure looks like this:
        //              RevDetails ::= SEQUENCE {
        //                                  certDetails         CertTemplate,
        //                                  revocationReason    ReasonFlags      OPTIONAL,
        //                                  badSinceDate        GeneralizedTime  OPTIONAL,
        //                                  crlEntryDetails     Extensions       OPTIONAL
        //             }
        //
        // In RFC4210/bouncycastle, the REVDetails structure looks like this:
        //                 RevDetails ::= SEQUENCE {
        //                                  certDetails         CertTemplate,
        //                                  crlEntryDetails     Extensions       OPTIONAL
        //                  }
        //
        // This means that there is a chance that the request generated using novosec specifies the revocation reason in 'revocationReason' and not
        // as an extension, leading to Ejbca not being able to parse the request using bouncycastle OR not setting the correct revocation reason.

        ASN1Encodable o2 = ((DERSequence) revContent.toASN1Primitive()).getObjectAt(0);
        ASN1Encodable o3 = ((DERSequence) o2).getObjectAt(0);
        CertTemplate ct = CertTemplate.getInstance(o3);

        ReasonFlags reasonbits = null;
        Extensions crlEntryDetails = null;
        int seqSize = ((DERSequence) o2).size();
        for (int i = 1; i < seqSize; i++) {
            ASN1Encodable o4 = ((DERSequence) o2).getObjectAt(i);
            if (o4 instanceof DERBitString) {
                reasonbits = new ReasonFlags((DERBitString) o4);
            } else if (o4 instanceof DERGeneralizedTime) {
                DERGeneralizedTime.getInstance(o4); // bad since time, not used in the bouncycastle class
            } else if (o4 instanceof DERSequence) {
                crlEntryDetails = Extensions.getInstance(o4);
            }
        }

        if ((crlEntryDetails != null) && (reasonbits != null)) {
            Extension reason = crlEntryDetails.getExtension(Extension.reasonCode);
            if (reason == null) {
                reason = new Extension(Extension.reasonCode, true, ASN1OctetString.getInstance(reasonbits.getBytes()));
            }
        } else if ((crlEntryDetails == null) && (reasonbits != null)) {
            ExtensionsGenerator extgen = new ExtensionsGenerator();
            try {
                extgen.addExtension(Extension.reasonCode, true, ASN1OctetString.getInstance(reasonbits.getBytes()));
                crlEntryDetails = extgen.generate();
            } catch (IOException e) {
                LOG.error(e.getLocalizedMessage(), e);
            }
        }

        //The constructor RevDetails(certTemplate, crlEntryDetails) only sets 'crlEntryDetails' and ignores 'certTemplate'
        //This is a reported bug in bouncycastle. For now, the only way to have both of them set is to create a ASN1/DERSequence 
        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(ct);
        seq.add(crlEntryDetails);
        RevDetails res = RevDetails.getInstance(new DERSequence(seq));
        return res;
    }

    /** @return SenderKeyId of in the header or null none was found. */
    public static String getStringFromOctets(final ASN1OctetString octets) {
        String str = null;
        if (octets != null) {
            str = new String(octets.getOctets(), StandardCharsets.UTF_8);
            if (StringUtils.isAsciiPrintable(str)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Found string: " + str);
                }
            } else {
                str = new String(Hex.encode(octets.getOctets()));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("DEROCtetString content is not asciiPrintable, converting to hex: " + str);
                }
            }
        }
        return str;
    }

    /** @return the PKIMessage if the bytes can be interpreted as a valid ASN.1 encoded CMP request message or null otherwise */
    public static PKIMessage getPkiMessageFromBytes(final byte[] pkiMessageBytes, final boolean sanityCheckMaxLevelOfNesting) {
        try {
            if (pkiMessageBytes!=null) {
                final PKIMessage pkiMessage = PKIMessage.getInstance(pkiMessageBytes);
                if (sanityCheckMaxLevelOfNesting) {
                    // Also validate nesting, if present
                    PKIMessage nestedPkiMessage = pkiMessage;
                    int levelOfNesting = 0;
                    while (nestedPkiMessage!=null && nestedPkiMessage.getBody().getType()==PKIBody.TYPE_NESTED) {
                        nestedPkiMessage = PKIMessages.getInstance(pkiMessage.getBody().getContent()).toPKIMessageArray()[0];
                        if (levelOfNesting++ > MAX_LEVEL_OF_NESTING) {
                            final String msg = "Rejected CMP request due to unreasonable level of nesting (>"+MAX_LEVEL_OF_NESTING+").";
                            LOG.info(msg);
                            throw new IllegalArgumentException(msg);
                        }
                    }
                }
                return pkiMessage;
            }
        } catch (RuntimeException e) {
            // BC library will throw an IllegalArgumentException if the underlying ASN.1 could not be parsed. 
            if (LOG.isDebugEnabled()) {
                LOG.debug(INTRES.getLocalizedMessage("cmp.errornotcmpmessage"), e);
            }
        }
        return null;
    }
}
