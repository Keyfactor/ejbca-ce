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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
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
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
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
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.InternalEjbcaResources;

/**
 * Helper class to create different standard parts of CMP messages
 * 
 * @version $Id$
 */
public class CmpMessageHelper {
    private static Logger LOG = Logger.getLogger(CmpMessageHelper.class);
    private static final InternalEjbcaResources INTRES = InternalEjbcaResources.getInstance();

    private static final String CMP_ERRORGENERAL = "cmp.errorgeneral";

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
        PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(2, sender, recipient);
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        if (senderNonce != null) {
            myPKIHeader.setSenderNonce(new DEROctetString(Base64.decode(senderNonce.getBytes())));
        }
        if (recipientNonce != null) {
            myPKIHeader.setRecipNonce(new DEROctetString(Base64.decode(recipientNonce.getBytes())));
        }
        if (transactionId != null) {
            myPKIHeader.setTransactionID(new DEROctetString(Base64.decode(transactionId.getBytes())));
        }
        return myPKIHeader;
    }

    public static byte[] signPKIMessage(PKIMessage myPKIMessage, Collection<Certificate> signCertChain, PrivateKey signKey, String digestAlg,
            String provider) throws InvalidKeyException, NoSuchProviderException, NoSuchAlgorithmException, SecurityException, SignatureException,
            CertificateEncodingException {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">signPKIMessage()");
        }
        CMPCertificate[] extraCerts = new CMPCertificate[signCertChain.size()];
        Iterator<Certificate> itr = signCertChain.iterator();
        int i = 0;
        while (itr.hasNext()) {
            X509Certificate tmp = (X509Certificate) itr.next();
            ASN1InputStream asn1InputStream = null;
            try {
                try {
                    asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(tmp.getEncoded()));
                    CMPCertificate signStruct = CMPCertificate.getInstance(asn1InputStream.readObject());
                    extraCerts[i] = signStruct;
                } finally {
                    asn1InputStream.close();
                }
            } catch (IOException e) {
                throw new IllegalStateException("Caught unexpected IOException", e);
            }
            i++;
        }
        myPKIMessage = CmpMessageHelper.buildCertBasedPKIProtection(myPKIMessage, extraCerts, signKey, digestAlg, provider);
        if (LOG.isTraceEnabled()) {
            LOG.trace("<signPKIMessage()");
        }
        // Return response as byte array 
        return CmpMessageHelper.pkiMessageToByteArray(myPKIMessage);

    }

    public static PKIMessage buildCertBasedPKIProtection(PKIMessage pKIMessage, CMPCertificate[] extraCerts, PrivateKey key, String digestAlg,
            String provider) throws NoSuchProviderException, NoSuchAlgorithmException, SecurityException, SignatureException, InvalidKeyException {
        // Select which signature algorithm we should use for the response, based on the digest algorithm and key type.
        ASN1ObjectIdentifier oid = AlgorithmTools.getSignAlgOidFromDigestAndKey(digestAlg, key.getAlgorithm());
        if (LOG.isDebugEnabled()) {
            LOG.debug("Selected signature alg oid: " + oid.getId()+", key algorithm: "+key.getAlgorithm());
        }
        // According to PKCS#1 AlgorithmIdentifier for RSA-PKCS#1 has null Parameters, this means a DER Null (asn.1 encoding of null), not Java null.
        // For the RSA signature algorithms specified above RFC3447 states "...the parameters MUST be present and MUST be NULL."
        PKIHeaderBuilder headerBuilder = getHeaderBuilder(pKIMessage.getHeader());
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
        sig.update(CmpMessageHelper.getProtectedBytes(head, pKIMessage.getBody()));

        if ((extraCerts != null) && (extraCerts.length > 0)) {
            pKIMessage = new PKIMessage(head, pKIMessage.getBody(), new DERBitString(sig.sign()), extraCerts);
        } else {
            pKIMessage = new PKIMessage(head, pKIMessage.getBody(), new DERBitString(sig.sign()));
        }
        return pKIMessage;
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
     * @throws NoSuchProviderException the BouncyCastle (BC) provider is not installed
     * @throws InvalidKeyException pubKey is not valid for signature verification
     * @throws SignatureException if the passed-in signature is improperly encoded or of the wrong type, if this signature algorithm is unable to process the input data provided, etc.
     */
    public static boolean verifyCertBasedPKIProtection(PKIMessage pKIMessage, PublicKey pubKey) throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException, SignatureException {
        AlgorithmIdentifier sigAlg = pKIMessage.getHeader().getProtectionAlg();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verifying signature with algorithm: " + sigAlg.getAlgorithm().getId());
        }
        Signature sig = Signature.getInstance(sigAlg.getAlgorithm().getId(), "BC");
        sig.initVerify(pubKey);
        sig.update(CmpMessageHelper.getProtectedBytes(pKIMessage));
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
        byte[] keyIdBytes;
        try {
            keyIdBytes = keyId.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            keyIdBytes = keyId.getBytes();
            LOG.info("UTF-8 not available, using platform default encoding for keyIdBytes.");
        }
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
        byte[] protectedBytes = CmpMessageHelper.getProtectedBytes(pkiHeader, msg.getBody()); //ret.getProtectedBytes();
        Mac mac = Mac.getInstance(macOid, "BC");
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
        return CmpMessageHelper.pkiMessageToByteArray(new PKIMessage(pkiHeader, msg.getBody(), bs, msg.getExtraCerts()));
    }

    public static byte[] pkiMessageToByteArray(PKIMessage msg) {
        // Return response as byte array 
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DEROutputStream mout = new DEROutputStream(baos);
        try {
            mout.writeObject(msg);
            mout.close();
        } catch (IOException e) {
            throw new IllegalStateException("Caught unexpected IOException.");
        }
        return baos.toByteArray();
    }

    /** Creates a 16 bytes random sender nonce
     * 
     * @return byte array of length 16
     */
    public static byte[] createSenderNonce() {
        // Sendernonce is a random number
        byte[] senderNonce = new byte[16];
        Random randomSource;
        randomSource = new Random();
        randomSource.nextBytes(senderNonce);
        return senderNonce;
    }

    /**
     * creates a very simple error message in response to msg (that's why we switch sender and recipient)
     * @param msg
     * @param status
     * @param failInfo
     * @param failText
     * @return IResponseMessage that can be sent to user
     */
    public static ResponseMessage createUnprotectedErrorMessage(BaseCmpMessage msg, FailInfo failInfo, String failText) {
        // Create a failure message
        if (LOG.isDebugEnabled()) {
            LOG.debug("Creating an unprotected error message with failInfo=" + failInfo + ", failText=" + failText);
        }
        CmpErrorResponseMessage resp = new CmpErrorResponseMessage();
        resp.setSenderNonce(new String(Base64.encode(CmpMessageHelper.createSenderNonce())));
        if (msg != null) {
            resp.setRecipientNonce(msg.getSenderNonce());
            resp.setSender(msg.getRecipient());
            resp.setRecipient(msg.getSender());
            resp.setTransactionId(msg.getTransactionId());
        } else {
            // We didn't even have a request to get these from, so send back some dummy values
            resp.setSender(new GeneralName(CertTools.stringToBcX500Name("CN=Failure Sender")));
            resp.setRecipient(new GeneralName(CertTools.stringToBcX500Name("CN=Failure Recipient")));
        }
        resp.setFailInfo(failInfo);
        resp.setFailText(failText);
        try {
            resp.create();
        } catch (InvalidKeyException e) {
            LOG.error("Exception during CMP processing: ", e);
        } catch (NoSuchAlgorithmException e) {
            LOG.error("Exception during CMP processing: ", e);
        } catch (NoSuchProviderException e) {
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
        CmpErrorResponseMessage resp = null;
        final CmpErrorResponseMessage cresp = new CmpErrorResponseMessage();
        cresp.setRecipientNonce(msg.getSenderNonce());
        cresp.setSenderNonce(new String(Base64.encode(CmpMessageHelper.createSenderNonce())));
        cresp.setSender(msg.getRecipient());
        cresp.setRecipient(msg.getSender());
        cresp.setTransactionId(msg.getTransactionId());
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
        resp = cresp;
        try {
            // Here we need to create the response message, when coming from SignSession it has already been "created"
            resp.create();
        } catch (InvalidKeyException e) {
            LOG.error(INTRES.getLocalizedMessage(CMP_ERRORGENERAL), e);
        } catch (NoSuchAlgorithmException e) {
            LOG.error(INTRES.getLocalizedMessage(CMP_ERRORGENERAL), e);
        } catch (NoSuchProviderException e) {
            LOG.error(INTRES.getLocalizedMessage(CMP_ERRORGENERAL), e);
        } 
        return resp;
    }

    /**
     * creates a very simple error message in response to msg (that's why we switch sender and recipient)
     * @param msg
     * @param status
     * @param failInfo
     * @param failText
     * @return IResponseMessage that can be sent to user
     * @throws IOException 
     */
    public static PKIBody createCertRequestRejectBody(PKIStatusInfo info, int requestId, int requestType) {
        // Create a failure message
        if (LOG.isDebugEnabled()) {
            LOG.debug("Creating a cert request rejection message");
            LOG.debug("Creating a CertRepMessage 'rejected'");
        }

        CertResponse myCertResponse = new CertResponse(new ASN1Integer(requestId), info);
        CertResponse[] resps = { myCertResponse };
        CertRepMessage myCertRepMessage = new CertRepMessage(null, resps);

        int respType = requestType + 1; // 1 = intitialization response, 3 = certification response etc
        if (LOG.isDebugEnabled()) {
            LOG.debug("Creating response body of type " + respType);
        }
        PKIBody myPKIBody = new PKIBody(respType, myCertRepMessage);

        return myPKIBody;
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
            try {
                str = new String(octets.getOctets(), "UTF-8");
            } catch (UnsupportedEncodingException e2) {
                str = new String(octets.getOctets());
                LOG.info("UTF-8 not available, using platform default encoding for keyId.");
            }

            if (!StringUtils.isAsciiPrintable(str)) {
                str = new String(Hex.encode(octets.getOctets()));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("DEROCtetString content is not asciiPrintable, converting to hex: " + str);
                }
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Found string: " + str);
            }
        }
        return str;
    }

}
