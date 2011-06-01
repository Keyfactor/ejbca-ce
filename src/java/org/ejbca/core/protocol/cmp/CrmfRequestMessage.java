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

package org.ejbca.core.protocol.cmp;

import java.io.ByteArrayInputStream;
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
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.util.Arrays;
import org.ejbca.core.protocol.IRequestMessage;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.RequestMessageUtils;

import com.novosec.pkix.asn1.cmp.PKIBody;
import com.novosec.pkix.asn1.cmp.PKIHeader;
import com.novosec.pkix.asn1.cmp.PKIMessage;
import com.novosec.pkix.asn1.crmf.AttributeTypeAndValue;
import com.novosec.pkix.asn1.crmf.CRMFObjectIdentifiers;
import com.novosec.pkix.asn1.crmf.CertReqMessages;
import com.novosec.pkix.asn1.crmf.CertReqMsg;
import com.novosec.pkix.asn1.crmf.CertRequest;
import com.novosec.pkix.asn1.crmf.CertTemplate;
import com.novosec.pkix.asn1.crmf.OptionalValidity;
import com.novosec.pkix.asn1.crmf.POPOSigningKey;
import com.novosec.pkix.asn1.crmf.POPOSigningKeyInput;
import com.novosec.pkix.asn1.crmf.ProofOfPossession;

/**
 * Certificate request message (crmf) according to RFC4211.
 * - Supported POPO: 
 * -- raVerified (null), i.e. no POPO verification is done, it should be configurable if the CA should allow this or require a real POPO
 * -- Self signature, using the key in CertTemplate, or POPOSigningKeyInput (name and public key), option 2 and 3 in RFC4211, section "4.1.  Signature Key POP"
 * 
 * @author tomas
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

    public CrmfRequestMessage() {
        
    }
    
    /**
     * 
     * @param msg PKIMessage
     * @param defaultCA possibility to enforce a certain CA, instead of taking the CA subject DN from the request, if set to null the CA subject DN is taken from the request
     * @param allowRaVerifyPopo true if we allows the user/RA to specify the POP should not be verified
     * @param extractUsernameComponent Defines which component from the DN should be used as username in EJBCA. Can be CN, UID or nothing. Null means that the username should have been pre-set, or that here it is the same as CN.
     */
	public CrmfRequestMessage(final PKIMessage msg, final String defaultCADN, final boolean allowRaVerifyPopo, final String extractUsernameComponent) {
    	if (log.isTraceEnabled()) {
    		log.trace(">CrmfRequestMessage");
    	}
		setPKIMessage(msg);
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
			try {
				setMessage(PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(pkimsgbytes)).readObject()));				
			} catch (IOException e) {
				log.error("Error decoding bytes for PKIMessage: ", e);
			}
		}
		return getMessage();
	}
	public void setPKIMessage(final PKIMessage msg) {
		try {
			this.pkimsgbytes = msg.getDERObject().getEncoded();
		} catch (IOException e) {
			log.error("Error getting encoded bytes from PKIMessage: ", e);
		}
		setMessage(msg);
	}

	private void init() {
		final PKIBody body = getPKIMessage().getBody();
		final PKIHeader header = getPKIMessage().getHeader();
		requestType = body.getTagNo();
		final CertReqMessages msgs = getCertReqFromTag(body, requestType);
		requestId = msgs.getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
		this.req = msgs.getCertReqMsg(0);
		DEROctetString os = header.getTransactionID();
		if (os != null) {
			byte[] val = os.getOctets();
			if (val != null) {
				setTransactionId(new String(Base64.encode(val)));							
			}
		}
		os = header.getSenderNonce();
		if (os != null) {
			byte[] val = os.getOctets();
			if (val != null) {
				setSenderNonce(new String(Base64.encode(val)));							
			}
		}
		setRecipient(header.getRecipient());
		setSender(header.getSender());
	}
	
	@Override
	public PublicKey getRequestPublicKey() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
		final CertRequest request = getReq().getCertReq();
		final CertTemplate templ = request.getCertTemplate();
		final SubjectPublicKeyInfo keyInfo = templ.getPublicKey();
		final PublicKey pk = getPublicKey(keyInfo, "BC");
		return pk;
	}
	private PublicKey getPublicKey(final SubjectPublicKeyInfo subjectPKInfo, final String  provider) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {		
		try {
			final X509EncodedKeySpec xspec = new X509EncodedKeySpec(new DERBitString(subjectPKInfo).getBytes());
			final AlgorithmIdentifier keyAlg = subjectPKInfo.getAlgorithmId ();
			return KeyFactory.getInstance(keyAlg.getObjectId().getId (), provider).generatePublic(xspec);
		} catch (java.security.spec.InvalidKeySpecException e) {
			final InvalidKeyException newe = new InvalidKeyException("Error decoding public key.");
			newe.initCause(e);
			throw newe;
		}
	}
	
    /** force a password, i.e. ignore the password in the request
     */
	public void setPassword(final String pwd) {
        this.password = pwd;
    }
	
	@Override
	public String getPassword() {
		String ret = null;
		if (password != null) {
			if (log.isDebugEnabled()) {
				log.debug("Returning a pre-set password in CRMF request");
			}
			ret = password;
		} else {
			// If there is "Registration Token Control" in the CertReqMsg regInfo containing a password, we can use that
			AttributeTypeAndValue av = null;
			int i = 0;
			do {
				av = getReq().getRegInfo(i);
				if (av != null) {
					if (StringUtils.equals(CRMFObjectIdentifiers.regCtrl_regToken.getId(), av.getObjectId().getId())) {
						final DEREncodable enc = av.getParameters();
						final DERUTF8String str = DERUTF8String.getInstance(enc);
						ret = str.getString();
						if (log.isDebugEnabled()) {
							log.debug("Found a request password in CRMF request regCtrl_regToken");
						}
					}
				}
				i++;
			} while ( (av != null) && (ret == null) );
		}		
		if (ret == null) {
			// If there is "Registration Token Control" in the CertRequest controls containing a password, we can use that
			// Note, this is the correct way to use the regToken according to RFC4211, section "6.1.  Registration Token Control"
			AttributeTypeAndValue av = null;
			int i = 0;
			do {
				av = getReq().getCertReq().getControls(i);
				if (av != null) {
					if (StringUtils.equals(CRMFObjectIdentifiers.regCtrl_regToken.getId(), av.getObjectId().getId())) {
						final DEREncodable enc = av.getParameters();
						final DERUTF8String str = DERUTF8String.getInstance(enc);
						ret = str.getString();
						if (log.isDebugEnabled()) {
							log.debug("Found a request password in CRMF request regCtrl_regToken");
						}
					}
				}
				i++;
			} while ( (av != null) && (ret == null) );
		}
		return ret;
	}

    /** force a username, i.e. ignore the DN/username in the request
     */
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
                log.error("No component "+component+" in DN: "+getRequestDN());
            } else {
            	ret = name;
            }
        }
		if (log.isDebugEnabled()) {
			log.debug("Username is: "+ret);
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
		final X509Name name = templ.getIssuer();
		if (name != null) {
			ret = CertTools.stringToBCDNString(name.toString());
		} else {
			ret = defaultCADN;
		}
		if (log.isDebugEnabled()) {
			log.debug("Issuer DN is: "+ret);
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
		final DERInteger serno = templ.getSerialNumber();
		if (serno != null) {
			ret = serno.getValue();			
		}
		return ret;
	}

	@Override
	public String getRequestDN() {
		String ret = null;
		final X509Name name = getRequestX509Name();
		if (name != null) {
			ret = CertTools.stringToBCDNString(name.toString());
		}
		if (log.isDebugEnabled()) {
			log.debug("Request DN is: "+ret);
		}
		return ret;
	}


	@Override
	public X509Name getRequestX509Name() {
		final CertTemplate templ = getReq().getCertReq().getCertTemplate();
		final X509Name name = templ.getSubject();
		if (log.isDebugEnabled()) {
			log.debug("Request X509Name is: "+name);
		}
		return name;
	}

	@Override
	public String getRequestAltNames() {
    	String ret = null;
    	final CertTemplate templ = getReq().getCertReq().getCertTemplate();
    	final X509Extensions exts = templ.getExtensions();
		if (exts != null) {
			final X509Extension ext = exts.getExtension(X509Extensions.SubjectAlternativeName);
			if (ext != null) {
				ret = CertTools.getAltNameStringFromExtension(ext);
			}
		}
		if (log.isDebugEnabled()) {
			log.debug("Request altName is: "+ret);
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
			log.debug("Request validity notBefore is: "+(ret == null ? "null" : ret.toString()));
		}
		return ret;
	}
	
	@Override
	public Date getRequestValidityNotAfter() {
		Date ret = null;
		final CertTemplate templ = getReq().getCertReq().getCertTemplate();
		final OptionalValidity val = templ.getValidity();
		if (val != null) {
			Time time = val.getNotAfter();
			if (time != null) {
				ret = time.getDate();
			}
		}
		if (log.isDebugEnabled()) {
			log.debug("Request validity notAfter is: "+(ret == null ? "null" : ret.toString()));
		}
		return ret;
	}

	@Override
	public X509Extensions getRequestExtensions() {
		final CertTemplate templ = getReq().getCertReq().getCertTemplate();
		final X509Extensions exts = templ.getExtensions();
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
		final ProofOfPossession pop = getReq().getPop();
		if (log.isDebugEnabled()) {
			log.debug("allowRaVerifyPopo: "+allowRaVerifyPopo);
			log.debug("pop.getRaVerified(): "+(pop.getRaVerified() != null));
			log.debug("pop.getSignature(): "+(pop.getSignature() != null));
		}
		if ( allowRaVerifyPopo && (pop.getRaVerified() != null)) {
			ret = true;
		} else if (pop.getSignature() != null) {
			try {
				final POPOSigningKey sk = pop.getSignature();
				final POPOSigningKeyInput pski = sk.getPoposkInput();
				Object protObject = pski;
				// Use of POPOSigningKeyInput or not, as described in RFC4211, section 4.1.
				if (pski == null) {
					if (log.isDebugEnabled()) {
						log.debug("Using CertRequest as POPO input.");
					}
					protObject = getReq().getCertReq();
				} else {
					// Assume POPOSigningKeyInput with the public key and name, MUST be the same as in the request according to RFC4211
					if (log.isDebugEnabled()) {
						log.debug("Using POPOSigningKeyInput as POPO input.");
					}
					final CertRequest req = getReq().getCertReq();
					// If subject is present in cert template it must be the same as in POPOSigningKeyInput
					final X509Name subject = req.getCertTemplate().getSubject();
					if (subject != null && !subject.toString().equals(pski.getSender().getName().toString())) {
						log.info("Subject '"+subject.toString()+"̈́', is not equal to '"+pski.getSender().toString()+"'.");
						protObject = null;	// pski is not a valid protection object
					}
					// If public key is present in cert template it must be the same as in POPOSigningKeyInput
					final SubjectPublicKeyInfo pk = req.getCertTemplate().getPublicKey();
					if (pk != null && !Arrays.areEqual(pk.getEncoded(), pski.getPublicKey().getEncoded())) {
						log.info("Subject key in cert template, is not equal to subject key in POPOSigningKeyInput.");
						protObject = null;	// pski is not a valid protection object
					}
				}
				// If a protectObject is present we extract the bytes and verify it
				if (protObject != null) {
					final ByteArrayOutputStream bao = new ByteArrayOutputStream();
					new DEROutputStream(bao).writeObject(protObject);
					final byte[] protBytes = bao.toByteArray();
					final AlgorithmIdentifier algId = sk.getAlgorithmIdentifier();
					if (log.isDebugEnabled()) {
						log.debug("POP protection bytes length: "+protBytes != null ? protBytes.length : "null");
						log.debug("POP algorithm identifier is: "+algId.getObjectId().getId());
					}
					final Signature sig = Signature.getInstance(algId.getObjectId().getId(), "BC");
					sig.initVerify(getRequestPublicKey());
					sig.update(protBytes);
					final DERBitString bs = sk.getSignature();
					ret = sig.verify(bs.getBytes());					
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
		final X509Name name = templ.getSubject();
		if (name != null) {
			ret = CertTools.stringToBCDNString(name.toString());
		}
		return ret;
	}

	private CertReqMessages getCertReqFromTag(final PKIBody body, final int tag) {
		CertReqMessages msgs = null;
		switch (tag) {
		case 0:
			msgs = body.getIr();
			break;
		case 2:
			msgs = body.getCr();
			break;
		case 7:
			msgs = body.getKur();
			break;
		case 9:
			msgs = body.getKrr();
			break;
		case 13:
			msgs = body.getCcr();
			break;
		default:
			break;
		}
		return msgs;
	}

	@Override
	public IResponseMessage createResponseMessage(final Class responseClass, final IRequestMessage req, final Certificate cert, final PrivateKey signPriv, final String provider) {
    	return RequestMessageUtils.createResponseMessage(responseClass, req, cert, signPriv, provider);
    }
}
