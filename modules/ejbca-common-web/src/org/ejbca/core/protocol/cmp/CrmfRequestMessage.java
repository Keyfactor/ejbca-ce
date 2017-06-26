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
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.POPOSigningKeyInput;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.util.Arrays;
import org.cesecore.util.CeSecoreNameStyle;
import org.cesecore.util.CertTools;
import org.ejbca.core.protocol.cmp.authentication.RegTokenPasswordExtractor;

/**
 * Certificate request message (crmf) according to RFC4211.
 * - Supported POPO: 
 * -- raVerified (null), i.e. no POPO verification is done, it should be configurable if the CA should allow this or require a real POPO
 * -- Self signature, using the key in CertTemplate, or POPOSigningKeyInput (name and public key), option 2 and 3 in RFC4211, section "4.1.  Signature Key POP"
 * 
 * @version $Id$
 */
public class CrmfRequestMessage extends BaseCmpMessage implements ICrmfRequestMessage {
	
	private static final Logger log = Logger.getLogger(CrmfRequestMessage.class);
	
    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
    static final long serialVersionUID = 1002L;

    private int requestType = 0;
    private int requestId = 0;
    private String b64SenderNonce = null;
    private String b64TransId = null;
    /** Default CA DN */
    private String defaultCADN = null;
    private boolean allowRaVerifyPopo = false;
    private String extractUsernameComponent = null;
    /** manually set username */
    private String username = null;
    /** manually set password */
    private String password = null;

    /** Because PKIMessage is not serializable we need to have the serializable bytes save as well, so 
     * we can restore the PKIMessage after serialization/deserialization. */
    private byte[] pkimsgbytes = null;
    private transient CertReqMsg req = null;

    /** Because CertReqMsg is not serializable we may need to encode/decode bytes if the object is lost during deserialization. */
    private CertReqMsg getReq() {
        if (req == null) {
            init();
        }
        return this.req;
    }

    /** preferred digest algorithm to use in replies, if applicable */
    private String preferredDigestAlg = CMSSignedGenerator.DIGEST_SHA1;

    public CrmfRequestMessage() { }

    /**
     * 
     * @param pkiMessage PKIMessage
     * @param defaultCA possibility to enforce a certain CA, instead of taking the CA subject DN from the request, if set to null the CA subject DN is taken from the request
     * @param allowRaVerifyPopo true if we allows the user/RA to specify the POP should not be verified
     * @param extractUsernameComponent Defines which component from the DN should be used as username in EJBCA. Can be CN, UID or nothing. Null means that the username should have been pre-set, or that here it is the same as CN.
     */
    public CrmfRequestMessage(final PKIMessage pkiMessage, final String defaultCADN, final boolean allowRaVerifyPopo, final String extractUsernameComponent) {
        if (log.isTraceEnabled()) {
            log.trace(">CrmfRequestMessage");
        }
        setPKIMessage(pkiMessage);
        this.defaultCADN = defaultCADN;
        this.allowRaVerifyPopo = allowRaVerifyPopo;
        this.extractUsernameComponent = extractUsernameComponent;
        init();
        if (log.isTraceEnabled()) {
            log.trace("<CrmfRequestMessage");
        }
    }

    public PKIMessage getPKIMessage() {
        if (getMessage() == null) {
            setMessage(PKIMessage.getInstance(pkimsgbytes));
        }
        return getMessage();
    }

    public void setPKIMessage(final PKIMessage msg) {
        try {
            this.pkimsgbytes = msg.toASN1Primitive().getEncoded();
        } catch (IOException e) {
            log.error("Error getting encoded bytes from PKIMessage: ", e);
        }
        setMessage(msg);
    }

    private void init() {
        final PKIBody pkiBody = getPKIMessage().getBody();
        final PKIHeader pkiHeader = getPKIMessage().getHeader();
        requestType = pkiBody.getType();
        final CertReqMessages msgs = getCertReqFromTag(pkiBody, requestType);
        try {
            this.req = msgs.toCertReqMsgArray()[0];
        } catch(Exception e) {
            this.req = CmpMessageHelper.getNovosecCertReqMsg(msgs);
        }
        requestId = this.req.getCertReq().getCertReqId().getValue().intValue();
        setTransactionId(getBase64FromAsn1OctetString(pkiHeader.getTransactionID()));
        setSenderNonce(getBase64FromAsn1OctetString(pkiHeader.getSenderNonce()));
        setRecipient(pkiHeader.getRecipient());
        setSender(pkiHeader.getSender());
    }

    @Override
    public PublicKey getRequestPublicKey() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        final CertRequest request = getReq().getCertReq();
        final CertTemplate templ = request.getCertTemplate();
        final SubjectPublicKeyInfo keyInfo = templ.getPublicKey();
        final PublicKey pk = getPublicKey(keyInfo, "BC");
        return pk;
    }

    private PublicKey getPublicKey(final SubjectPublicKeyInfo subjectPKInfo, final String provider) throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException {
        try {
            final X509EncodedKeySpec xspec = new X509EncodedKeySpec(new DERBitString(subjectPKInfo).getBytes());
            final AlgorithmIdentifier keyAlg = subjectPKInfo.getAlgorithm();
            return KeyFactory.getInstance(keyAlg.getAlgorithm().getId(), provider).generatePublic(xspec);
        } catch (InvalidKeySpecException | IOException e) {
            final InvalidKeyException newe = new InvalidKeyException("Error decoding public key.");
            newe.initCause(e);
            throw newe;
        }
    }

    /** force a password, i.e. ignore the password in the request */
    public void setPassword(final String pwd) {
        this.password = pwd;
    }

    @Override
    public String getPassword() {
        if(password != null) {
            return this.password;
        }

        RegTokenPasswordExtractor regTokenExtractor = new RegTokenPasswordExtractor();

        if(regTokenExtractor.verifyOrExtract(getPKIMessage(), null)) {
            this.password = regTokenExtractor.getAuthenticationString();
        } else {
            if(log.isDebugEnabled()) {
                log.debug(regTokenExtractor.getErrorMessage());
            }
        }
        return this.password;
    }

    /** force a username, i.e. ignore the DN/username in the request */
    public void setUsername(final String username) {
        this.username = username;
    }

    @Override
    public String getUsername() {
        String ret = null;
        if (username != null) {
            ret = username;
        } else {
            // We can configure which part of the users DN should be used as username in EJBCA, for example CN or UID
            String component = extractUsernameComponent;
            if (StringUtils.isEmpty(component)) {
                component = "CN";
            }
            String name = CertTools.getPartFromDN(getRequestDN(), component);
            if (name == null) {
                log.error("No component " + component + " in DN: " + getRequestDN());
            } else {
                ret = name;
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Username is: " + ret);
        }
        return ret;
    }

    public void setIssuerDN(final String issuer) {
        this.defaultCADN = issuer;
    }

    @Override
    public String getIssuerDN() {
        String ret = null;
        final CertTemplate templ = getReq().getCertReq().getCertTemplate();
        final X500Name name = templ.getIssuer();
        if (name != null) {
            ret = CertTools.stringToBCDNString(name.toString());
        } else {
            ret = defaultCADN;
        }
        if (log.isDebugEnabled()) {
            log.debug("Issuer DN is: " + ret);
        }
        return ret;
    }

    @Override
    public BigInteger getSerialNo() {
        return null;
    }

    @Override
    public String getCRLIssuerDN() {
        return null;
    }

    @Override
    public BigInteger getCRLSerialNo() {
        return null;
    }

    /** Gets a requested certificate serial number of the subject. This is a standard field in the CertTemplate in the request.
     * However the standard RFC 4211, section 5 (CertRequest syntax) says it MUST not be used. 
     * Requesting custom certificate serial numbers is a very non-standard procedure anyhow, so we use it anyway. 
     * 
     * @return BigInteger the requested custom certificate serial number or null, normally this should return null.
     */
    public BigInteger getSubjectCertSerialNo() {
        BigInteger ret = null;
        final CertRequest request = getReq().getCertReq();
        final CertTemplate templ = request.getCertTemplate();
        final ASN1Integer serno = templ.getSerialNumber();
        if (serno != null) {
            ret = serno.getValue();
        }
        return ret;
    }

    @Override
    public String getRequestDN() {
        String ret = null;
        final X500Name name = getRequestX500Name();
        if (name != null) {
            ret = CertTools.stringToBCDNString(name.toString());
        }
        if (log.isDebugEnabled()) {
            log.debug("Request DN is: " + ret);
        }
        return ret;
    }

    @Override
    public X500Name getRequestX500Name() {
        final CertTemplate templ = getReq().getCertReq().getCertTemplate();
        X500Name name = templ.getSubject();
        if(name != null) {
            name = X500Name.getInstance(new CeSecoreNameStyle(), name);
        }
        if (log.isDebugEnabled()) {
            log.debug("Request X500Name is: " + name);
        }
        return name;
    }

    @Override
    public String getRequestAltNames() {
        String ret = null;
        final CertTemplate templ = getReq().getCertReq().getCertTemplate();
        final Extensions exts = templ.getExtensions();
        if (exts != null) {
            final Extension ext = exts.getExtension(Extension.subjectAlternativeName);
            if (ext != null) {
                ret = CertTools.getAltNameStringFromExtension(ext);
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Request altName is: " + ret);
        }
        return ret;
    }

    @Override
    public Date getRequestValidityNotBefore() {
        Date ret = null;
        final CertTemplate templ = getReq().getCertReq().getCertTemplate();
        final OptionalValidity val = templ.getValidity();
        if (val != null) {
            final Time time = val.getNotBefore();
            if (time != null) {
                ret = time.getDate();
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Request validity notBefore is: " + (ret == null ? "null" : ret.toString()));
        }
        return ret;
    }

    @Override
    public Date getRequestValidityNotAfter() {
        Date ret = null;
        final CertTemplate templ = getReq().getCertReq().getCertTemplate();
        final OptionalValidity val = templ.getValidity();
        if (val != null) {
            final Time time = val.getNotAfter();
            if (time != null) {
                ret = time.getDate();
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Request validity notAfter is: " + (ret == null ? "null" : ret.toString()));
        }
        return ret;
    }

    @Override
    public Extensions getRequestExtensions() {
        final CertTemplate templ = getReq().getCertReq().getCertTemplate();
        final Extensions exts = templ.getExtensions();
        if (log.isDebugEnabled()) {
            if (exts != null) {
                log.debug("Request contains extensions");
            } else {
                log.debug("Request does not contain extensions");
            }
        }
        return exts;
    }

    @Override
    public boolean verify() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        boolean ret = false;
        final ProofOfPossession pop = getReq().getPopo();
        if (log.isDebugEnabled()) {
            log.debug("allowRaVerifyPopo: " + allowRaVerifyPopo);
            log.debug("pop.getRaVerified(): " + (pop.getType() == ProofOfPossession.TYPE_RA_VERIFIED));
        }
        if (allowRaVerifyPopo && (pop.getType() == ProofOfPossession.TYPE_RA_VERIFIED)) {
            ret = true;
        } else if (pop.getType() == ProofOfPossession.TYPE_SIGNING_KEY) {
            try {
                final POPOSigningKey sk = (POPOSigningKey) pop.getObject();
                final POPOSigningKeyInput pski = sk.getPoposkInput();
                ASN1Encodable protObject = pski;
                // Use of POPOSigningKeyInput or not, as described in RFC4211, section 4.1.
                if (pski == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Using CertRequest as POPO input because POPOSigningKeyInput is missing.");
                    }
                    protObject = getReq().getCertReq();
                } else {
                    // Assume POPOSigningKeyInput with the public key and name, MUST be the same as in the request according to RFC4211
                    if (log.isDebugEnabled()) {
                        log.debug("Using POPOSigningKeyInput as POPO input.");
                    }
                    final CertRequest req = getReq().getCertReq();
                    // If subject is present in cert template it must be the same as in POPOSigningKeyInput
                    final X500Name subject = req.getCertTemplate().getSubject();
                    if (subject != null && !subject.toString().equals(pski.getSender().getName().toString())) {
                        log.info("Subject '" + subject.toString() + "', is not equal to '" + pski.getSender().toString() + "'.");
                        protObject = null; // pski is not a valid protection object
                    }
                    // If public key is present in cert template it must be the same as in POPOSigningKeyInput
                    final SubjectPublicKeyInfo pk = req.getCertTemplate().getPublicKey();
                    if (pk != null && !Arrays.areEqual(pk.getEncoded(), pski.getPublicKey().getEncoded())) {
                        log.info("Subject key in cert template, is not equal to subject key in POPOSigningKeyInput.");
                        protObject = null; // pski is not a valid protection object
                    }
                }
                // If a protectObject is present we extract the bytes and verify it
                if (protObject != null) {
                    final ByteArrayOutputStream bao = new ByteArrayOutputStream();
                    new DEROutputStream(bao).writeObject(protObject);
                    final byte[] protBytes = bao.toByteArray();
                    final AlgorithmIdentifier algId = sk.getAlgorithmIdentifier();
                    if (log.isDebugEnabled()) {
                        log.debug("POP protection bytes length: " + (protBytes != null ? protBytes.length : "null"));
                        log.debug("POP algorithm identifier is: " + algId.getAlgorithm().getId());
                    }
                    final Signature sig = Signature.getInstance(algId.getAlgorithm().getId(), "BC");
                    sig.initVerify(getRequestPublicKey());
                    sig.update(protBytes);
                    final DERBitString bs = sk.getSignature();
                    ret = sig.verify(bs.getBytes());
                    if (log.isDebugEnabled()) {
                        log.debug("POP verify returns: " + ret);
                    }
                }
            } catch (IOException e) {
                log.error("Error encoding CertReqMsg: ", e);
            } catch (SignatureException e) {
                log.error("SignatureException verifying POP: ", e);
            }
        }
        return ret;
    }

    @Override
    public boolean requireKeyInfo() {
        return false;
    }

    @Override
    public void setKeyInfo(final Certificate cert, final PrivateKey key, final String provider) {
    }

    @Override
    public int getErrorNo() {
        return 0;
    }

    @Override
    public String getErrorText() {
        return null;
    }

    public void setSenderNonce(final String b64nonce) {
        this.b64SenderNonce = b64nonce;
    }

    @Override
    public String getSenderNonce() {
        return b64SenderNonce;
    }

    public void setTransactionId(final String b64transid) {
        this.b64TransId = b64transid;
    }

    @Override
    public String getTransactionId() {
        return b64TransId;
    }

    @Override
    public byte[] getRequestKeyInfo() {
        return null;
    }

    @Override
    public String getPreferredDigestAlg() {
        return preferredDigestAlg;
    }

    public void setPreferredDigestAlg(String digestAlgo) {
        if(StringUtils.isNotEmpty(digestAlgo)) {
            preferredDigestAlg = digestAlgo;
        }
    }
    
    @Override
    public boolean includeCACert() {
        return false;
    }

    @Override
    public int getRequestType() {
        return requestType;
    }

    @Override
    public int getRequestId() {
        return requestId;
    }

    // Returns the subject DN from the request, used from CrmfMessageHandler
    public String getSubjectDN() {
        String ret = null;
        final CertTemplate templ = getReq().getCertReq().getCertTemplate();
        final X500Name name = templ.getSubject();
        if (name != null) {
            ret = CertTools.stringToBCDNString(name.toString());
        }
        return ret;
    }

    private CertReqMessages getCertReqFromTag(final PKIBody body, final int tag) {
        CertReqMessages msgs = null;
        if (tag == 0 || tag == 2 || tag == 7 || tag == 9 || tag == 13) {
            msgs = (CertReqMessages) body.getContent();
        }
        return msgs;
    }

    @Override
    public void setResponseKeyInfo(PrivateKey key, String provider) {
        //These values are never used for this type of message
        if(log.isDebugEnabled()) {
            log.debug("Key and provider were set for a CrmfRequestMessage. These values are not used and will be ignored.");
        }
    }

    @Override
    public boolean isImplicitConfirm() {
        InfoTypeAndValue[] infos = this.getHeader().getGeneralInfo();
        if (infos != null) {
            for (int i = 0; i < infos.length; i++) {
                if (CMPObjectIdentifiers.it_implicitConfirm.equals(infos[i].getInfoType())) {
                    return true;
                }
            }
        }
        return false;
    }

}
