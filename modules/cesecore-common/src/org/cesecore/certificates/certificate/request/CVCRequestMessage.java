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

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.cesecore.util.CertTools;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;


/**
 * Class to handle CVC request messages sent to the CA.
 */
public class CVCRequestMessage implements RequestMessage {
    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
    static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(CVCRequestMessage.class);

    /** Raw form of the CVC message */
    protected byte[] cvcmsg;

    /** manually set password */
    protected String password = null;

    /** manually set username */
    protected String username = null;

    /** Overriding the notAfter in the request */
    protected Date notAfter = null;

    /** The cvc request message, not serialized. */
    protected transient CVCertificate cvcert = null;

    private List<Certificate> additionalCaCertificates = new ArrayList<>();
  
    private List<Certificate> additionalExtraCertsCertificates = new ArrayList<>();
    
    /**
     * Constructs a new empty message handler object.
     */
    public CVCRequestMessage() {
    	// No constructor
    }

    /**
     * Constructs a new message handler object.
     *
     * @param msg The DER encoded request.
     */
    public CVCRequestMessage(byte[] msg) {
        this.cvcmsg = msg;
        init();
    }

    private void init() {
		try {
			CVCObject parsedObject;
			parsedObject = CertificateParser.parseCVCObject(cvcmsg);
			if (parsedObject == null) {
			    final String msg = "Error in init for CVC request, data parses to null.";
	            log.info(msg);
	            throw new IllegalArgumentException(msg);
			}
			if (parsedObject instanceof CVCertificate) {
				cvcert = (CVCertificate) parsedObject;
			} else if (parsedObject instanceof CVCAuthenticatedRequest) {
				CVCAuthenticatedRequest authreq = (CVCAuthenticatedRequest)parsedObject;
				cvcert = authreq.getRequest();
			}
		} catch (ParseException | ConstructionException | NoSuchFieldException e) {
            log.info("Error in init for CVC request: ", e);
            throw new IllegalArgumentException(e);
		}
    }

    @Override
    public PublicKey getRequestPublicKey()
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
    	try {
    		if (cvcert == null) {
    			init();
    		}
        } catch (IllegalArgumentException e) {
            log.error("CVC not inited!");
            return null;
        }

        PublicKey pk;
		try {
			pk = cvcert.getCertificateBody().getPublicKey();
		} catch (NoSuchFieldException e) {
			throw new InvalidKeyException(e);
		}
        return pk;
    }

    @Override
    public void setPassword(String pwd) {
        this.password = pwd;
    }

    @Override
    public String getPassword() {
    	return password;
    }

    @Override
    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public String getUsername() {
        if (username != null) {
            return username;
        }
        String subject = null;
		try {
			HolderReferenceField hr = cvcert.getCertificateBody().getHolderReference();
			subject = hr.getMnemonic()+hr.getCountry();
		} catch (NoSuchFieldException e) {
			log.error(e);
		}
        return subject;
    }

    @Override
    public String getIssuerDN() {
    	CardVerifiableCertificate cc = getCardVerifiableCertificate();
        return CertTools.getIssuerDN(cc);
    }

    /**
     * Could get the sequence (of CVC cert). For CVC certificate this does not combine well with getIssuerDN to identify
     * the CA-certificate of the CA the request is targeted for, so it always return null. 
     * When key sequence is needed from CVC requests, use {@link #getCASequence()}
     *
     * @return null.
     */
    @Override
    public BigInteger getSerialNo() {
    	return null;
    }

    @Override
    public String getCASequence() {
        CardVerifiableCertificate cc = getCardVerifiableCertificate();
        try {
            return cc.getCVCertificate().getCertificateBody().getAuthorityReference().getSequence();
        } catch (NoSuchFieldException e) {
            log.error("getSerialNumber: NoSuchFieldException: ", e);
            return null;
        }
    }

    @Override
    public String getCRLIssuerDN() {
        return null;
    }

    @Override
    public BigInteger getCRLSerialNo() {
        return null;
    }

    @Override
    public String getRequestDN() {
    	CardVerifiableCertificate cc = getCardVerifiableCertificate();
        return CertTools.getSubjectDN(cc);
    }

    @Override
    public X500Name getRequestX500Name() {
    	String dn = getRequestDN();
    	return new X500Name(dn);
    }

    @Override
    public String getRequestAltNames() {
    	return null;
    }

    @Override
	public Date getRequestValidityNotBefore() {
    	CardVerifiableCertificate cc = getCardVerifiableCertificate();
        return CertTools.getNotBefore(cc);
	}
	
    @Override
	public Date getRequestValidityNotAfter() {
        if (notAfter == null) {
            CardVerifiableCertificate cc = getCardVerifiableCertificate();
            return CertTools.getNotAfter(cc);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Overriding Request validity notAfter with explicitly set: " + notAfter.toString());
            }
            return notAfter;
        }
	}
	
    @Override
    public void setRequestValidityNotAfter(Date notAfter) {
        this.notAfter = notAfter;
    }

    @Override
	public Extensions getRequestExtensions() {
		return null;
	}
	
    @Override
    public boolean verify()
    throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        return verify(null);
    }
    private boolean verify(PublicKey pubKey)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        log.trace(">verify()");

        boolean ret = false;

        try {
        	CardVerifiableCertificate cc = getCardVerifiableCertificate();
        	if (cc != null) {
                if (pubKey == null) {
                	cc.verify(cvcert.getCertificateBody().getPublicKey());
                	ret = true; // If we came here verification was successful
                } else {
                    cc.verify(pubKey);
                	ret = true; // If we came here verification was successful
                }        		
        	}
        } catch (NoSuchFieldException e) {
            log.error("CVC error!", e);
        } catch (InvalidKeyException e) {
            log.error("Error in CVC request:", e);
            throw e;
        } catch (CertificateException e) {
            log.error("Error in CVC certificate:", e);
        } catch (SignatureException e) {
            log.error("Error in CVC signature:", e);
        }

        log.trace("<verify()");

        return ret;
    }

    @Override
    public boolean requireKeyInfo() {
        return false;
    }

    @Override
    public void setKeyInfo(Certificate cert, PrivateKey key, String provider) {
    }

    @Override
    public int getErrorNo() {
        return 0;
    }

    @Override
    public String getErrorText() {
        return "";
    }

    @Override
    public String getSenderNonce() {
        return null;
    }

    @Override
    public String getTransactionId() {
        return null;
    }

    @Override
    public byte[] getRequestKeyInfo() {
    	byte[] ret = null;
    	try {
        	String seq = cvcert.getCertificateBody().getHolderReference().getSequence();
        	ret = seq.getBytes();
    	} catch (NoSuchFieldException e) {
            log.error("CVC error!", e);
    	}
        return ret;
    }
    
    @Override
    public String getPreferredDigestAlg() {
    	// Not used
    	return CMSSignedGenerator.DIGEST_SHA256;
    }

    @Override
    public boolean includeCACert() {
    	return false;
    }

    @Override
    public int getRequestType() {
    	return 0;
    }
    
    @Override
    public int getRequestId() {
    	return 0;
    }
    
    @Override
    public void setResponseKeyInfo(PrivateKey key, String provider) {
        // NOOP
    }
    
    @Override
    public List<Certificate> getAdditionalCaCertificates() {
        return additionalCaCertificates;
    }

    @Override
    public void setAdditionalCaCertificates(final List<Certificate> certificates) {
        this.additionalCaCertificates = certificates;
    }
    
    @Override
    public List<Certificate> getAdditionalExtraCertsCertificates() {
        return additionalExtraCertsCertificates;
    }

    @Override
    public void setAdditionalExtraCertsCertificates(List<Certificate> additionalExtraCertsCertificates) {
        this.additionalExtraCertsCertificates = additionalExtraCertsCertificates;
    }

    /** Specific to CVC request messages, EAC requests contains a sequence.
     * This is the sequence of the Holder Reference in the CVC request */
    public String getKeySequence() {
    	String ret = null;
    	try {
			if (cvcert.getCertificateBody().getHolderReference() != null) {
				ret = cvcert.getCertificateBody().getHolderReference().getSequence();    		
			}
		} catch (NoSuchFieldException e) {
			// No sequence found...
		}
    	return ret;
    }
    
    private CardVerifiableCertificate getCardVerifiableCertificate() {
    	try {
    		if (cvcert == null) {
    			init();
    		}
        } catch (IllegalArgumentException e) {
            log.error("CVC not inited!", e);
            return null;
        }
    	return new CardVerifiableCertificate(cvcert);
    }

} // CVCRequestMessage
