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

package org.ejbca.core.model.ca.caadmin;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.SignRequestSignatureException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.catoken.CATokenContainer;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.catoken.ICAToken;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.cvc.AccessRightEnum;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.RequestMessageUtils;




/**
 * CVCCA is a implementation of a CA and holds data specific for Certificate and CRL generation 
 * according to the CVC (Card Verifiable Certificate) standard used in EU EAC electronic passports.  
 *
 * @version $Id$
 */
public class CVCCA extends CA implements Serializable {

	private static final long serialVersionUID = 3L;

	private static final Logger log = Logger.getLogger(CVCCA.class);

	/** Internal localization of logs and errors */
	private static final InternalResources intres = InternalResources.getInstance();

	/** Version of this class, if this is increased the upgrade() method will be called automatically */
	public static final float LATEST_VERSION = 3;

    // protected fields for properties specific to this type of CA.

	// Public Methods
	/** Creates a new instance of CA, this constructor should be used when a new CA is created */
	public CVCCA(CVCCAInfo cainfo) {
		super(cainfo);  

		data.put(CA.CATYPE, new Integer(CAInfo.CATYPE_CVC));
		data.put(VERSION, new Float(LATEST_VERSION));   
	}

	/** Constructor used when retrieving existing CVCCA from database. 
	 * @throws IllegalKeyStoreException */
	public CVCCA(HashMap data, int caId, String subjectDN, String name, int status, Date updateTime) throws IllegalKeyStoreException{
		super(data);
		ArrayList externalcaserviceinfos = new ArrayList();
		Iterator iter = getExternalCAServiceTypes().iterator(); 	
		while(iter.hasNext()){
			ExtendedCAServiceInfo info = this.getExtendedCAServiceInfo(((Integer) iter.next()).intValue());
			if (info != null) {
				externalcaserviceinfos.add(info);  	    			
			}
		}
		CAInfo info = new CVCCAInfo(subjectDN, name, status, updateTime, getCertificateProfileId(),  
				getValidity(), getExpireTime(), getCAType(), getSignedBy(), getCertificateChain(),
				getCAToken(caId).getCATokenInfo(), getDescription(), getRevokationReason(), getRevokationDate(), getCRLPeriod(), getCRLIssueInterval(), getCRLOverlapTime(), getDeltaCRLPeriod(), 
				getCRLPublishers(), getFinishUser(), externalcaserviceinfos, 
				getApprovalSettings(), getNumOfRequiredApprovals(),
				getIncludeInHealthCheck(), isDoEnforceUniquePublicKeys(), isDoEnforceUniqueDistinguishedName());
		super.setCAInfo(info);
	}

    public void updateCA(CAInfo cainfo) throws Exception{
    	super.updateCA(cainfo); 
    	//CVCCAInfo info = (CVCCAInfo) cainfo;
    	// do something with this if needed
    }


	public byte[] createPKCS7(Certificate cert, boolean includeChain) throws SignRequestSignatureException {
    	String msg = intres.getLocalizedMessage("cvc.info.nocvcpkcs7");
		log.info(msg);
		return null;
	}    

	/**
	 * @see CA#createRequest(Collection, String, Certificate, int)
	 */
	public byte[] createRequest(Collection attributes, String signAlg, Certificate cacert, int signatureKeyPurpose) throws CATokenOfflineException {
		log.trace(">createRequest: "+signAlg+", "+CertTools.getSubjectDN(cacert)+", "+signatureKeyPurpose);
		byte[] ret = null;
		// Create a CVC request. 
		// No outer signature on this self signed request
		KeyPair keyPair;
		try {
			CATokenContainer catoken = getCAToken();
			keyPair = new KeyPair(catoken.getPublicKey(signatureKeyPurpose), catoken.getPrivateKey(signatureKeyPurpose));
			if (keyPair == null) {
				throw new IllegalArgumentException("Keys for key purpose "+signatureKeyPurpose+" does not exist.");
			}
			String subject = getCAInfo().getSubjectDN();
			String country = CertTools.getPartFromDN(subject, "C");
			String mnemonic = CertTools.getPartFromDN(subject, "CN");
			String seq = getCAToken().getCATokenInfo().getKeySequence(); 
			if (signatureKeyPurpose == SecConst.CAKEYPURPOSE_CERTSIGN_NEXT) {
				// See if we have a next sequence to put in the holder reference instead of the current one, 
				// since we are using the next key we should use the next sequence
				String propdata = catoken.getCATokenInfo().getProperties();
				Properties prop = new Properties();
				if (propdata != null) {
					prop.load(new ByteArrayInputStream(propdata.getBytes()));					
				}
				String nextSequence = (String)prop.get(ICAToken.NEXT_SEQUENCE_PROPERTY);
				// Only use next sequence if we also use previous key
				if (nextSequence != null) {
					seq = nextSequence;
					log.debug("Using next sequence in holderRef: "+seq);
				} else {
					log.debug("Using current sequence in holderRef, although we are using the next key...no next sequence was found: "+seq);				
				}
			}
			if (seq == null) {
				log.info("No sequence found in ca token info, using random 5 number sequence.");
				seq = RandomStringUtils.randomNumeric(5);
			}
			if (seq.length() > 5) {
				log.info("Sequence "+seq+" is too long, only using first 5.");
				seq = seq.substring(0, 4);
			}
			if (seq.length() < 5) {
				log.info("Sequence "+seq+" is too short, padding with zeroes.");
				for (int i = seq.length(); i < 5; i++) {
					seq = "0"+seq;					
				}
			}
			HolderReferenceField holderRef = new HolderReferenceField(country, mnemonic, seq);
			CAReferenceField caRef = null;
			if (cacert != null) {
				if (cacert instanceof CardVerifiableCertificate) {
					CardVerifiableCertificate cvcacert = (CardVerifiableCertificate) cacert;
					try {
						HolderReferenceField href = cvcacert.getCVCertificate().getCertificateBody().getHolderReference();
						caRef = new CAReferenceField(href.getCountry(), href.getMnemonic(), href.getSequence());
					} catch (NoSuchFieldException e) {
						log.debug("CA certificate does not contain a Holder reference to use as CARef in request.");
					}
					
				}
			} else {
				caRef = new CAReferenceField(holderRef.getCountry(), holderRef.getMnemonic(), holderRef.getSequence());				
			}
			log.debug("Creating request with signature alg: "+signAlg+", using provider "+catoken.getProvider());
			CVCertificate request = CertificateGenerator.createRequest(keyPair, signAlg, caRef, holderRef, catoken.getProvider());
			ret = request.getDEREncoded();
		} catch (IllegalKeyStoreException e) {
            throw new RuntimeException(e);
		} catch (InvalidKeyException e) {
            throw new RuntimeException(e);
		} catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
		} catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
		} catch (SignatureException e) {
            throw new RuntimeException(e);
		} catch (IOException e) {
            throw new RuntimeException(e);
		} catch (ConstructionException e) {
            throw new RuntimeException(e);
		}
		log.trace("<createRequest");
		return ret;
	}

	/** If the request is a CVC request, this method adds an outer signature to the request.
	 * If this request is a CVCA certificate and this is the same CVCA, this method creates a CVCA link certificate.
	 * If not creating a link certificate this means that an authenticated request, CVCAuthenticatedRequest is created.
	 * 
	 * @see CA#signRequest(byte[], boolean, boolean)
	 */
	public byte[] signRequest(byte[] request, boolean usepreviouskey, boolean createlinkcert) throws CATokenOfflineException {
		if (log.isTraceEnabled()) {
			log.trace(">signRequest: usepreviouskey="+usepreviouskey+", createlinkcert="+createlinkcert);
		}
		byte[] ret = request;
		try {
			CardVerifiableCertificate cacert = (CardVerifiableCertificate)getCACertificate();
			if (cacert == null) {
				// if we don't have a CA certificate, we can't sign any request, just return it
				return request;
			}
			CATokenContainer catoken = getCAToken();
			// Get either the current or the previous signing key for signing this request
			int key = SecConst.CAKEYPURPOSE_CERTSIGN;
			if (usepreviouskey) {
				log.debug("Using previous CertSign key to sign request");
				key = SecConst.CAKEYPURPOSE_CERTSIGN_PREVIOUS;
			} else {
				log.debug("Using current CertSign key to sign request");
			}
			KeyPair keyPair = new KeyPair(catoken.getPublicKey(key), catoken.getPrivateKey(key));
			String signAlg = getCAToken().getCATokenInfo().getSignatureAlgorithm();
			// Create the CA reference, should be from signing certificates holder field
			HolderReferenceField caHolder = cacert.getCVCertificate().getCertificateBody().getHolderReference();
			String sequence = caHolder.getSequence();
			// See if we have a previous sequence to put in the CA reference instead of the same as we have from the request
			String propdata = catoken.getCATokenInfo().getProperties();
			Properties prop = new Properties();
			if (propdata != null) {
				prop.load(new ByteArrayInputStream(propdata.getBytes()));					
			}
			String previousSequence = (String)prop.get(ICAToken.PREVIOUS_SEQUENCE_PROPERTY);
			// Only use previous sequence if we also use previous key
			if ( (previousSequence != null) && (usepreviouskey) ) {
				sequence = previousSequence;
				log.debug("Using previous sequence in caRef: "+sequence);
			} else {
				log.debug("Using current sequence in caRef: "+sequence);				
			}
			// Set the CA reference field for the authentication signature
			CAReferenceField caRef = new CAReferenceField(caHolder.getCountry(), caHolder.getMnemonic(), sequence);

			CVCertificate cvcert = null;
			try {
				byte[] binbytes = request;
				try {
					// We don't know if this is a PEM or binary certificate or request request so we first try to 
					// decode it as a PEM certificate, and if it's not we try it as a PEM request and finally as a binary request 
					Collection col = CertTools.getCertsFromPEM(new ByteArrayInputStream(request));
					Certificate cert = (Certificate)col.iterator().next();
					if (cert != null) {
						binbytes = cert.getEncoded();
					}
				} catch (Exception e) {
					log.debug("This is not a PEM certificate?: "+e.getMessage());
					try {
						binbytes = RequestMessageUtils.getRequestBytes(request);
					} catch (Exception e2) {
						log.debug("This is not a PEM request?: "+e2.getMessage());						
					}
				}
				// This can be either a CV certificate, a CV certificate request, or an authenticated request that we should re-sign
				CVCObject parsedObject;
				parsedObject = CertificateParser.parseCVCObject(binbytes);
				if (parsedObject instanceof CVCertificate) {
					cvcert = (CVCertificate) parsedObject;
					log.debug("This is a reqular CV request, or cert.");					
				} else if (parsedObject instanceof CVCAuthenticatedRequest) {
					CVCAuthenticatedRequest authreq = (CVCAuthenticatedRequest)parsedObject;
					cvcert = authreq.getRequest();
					log.debug("This is an authenticated CV request, we will overwrite the old authentication with a new.");					
				}
			} catch (ParseException e) {
            	String msg = intres.getLocalizedMessage("cvc.error.notcvcrequest");
				log.info(msg, e);
				return request;
			} catch (ClassCastException e) {
            	String msg = intres.getLocalizedMessage("cvc.error.notcvcrequest");
				log.info(msg, e);
				return request;
			}
			// Check if the input was a CVCA certificate, which is the same CVCA as this. If all is true we should create a CVCA link certificate
			// instead of an authenticated request
			CardVerifiableCertificate cvccert = new CardVerifiableCertificate(cvcert);
			HolderReferenceField cvccertholder = cvccert.getCVCertificate().getCertificateBody().getHolderReference();
			AuthorizationRoleEnum authRole = null;
			AccessRightEnum rights = null;
			try {
				authRole = cvccert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole();					
 				rights = cvccert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getAccessRight();
			} catch (NoSuchFieldException e) {
				log.debug("No AuthorizationRoleEnum or AccessRightEnum, this is not a CV certificate so we can't make a link certificate: "+e.getMessage());
				
			}
			if (createlinkcert && (authRole != null) && (rights != null)) {
				log.debug("We will create a link certificate.");
				String msg = intres.getLocalizedMessage("cvc.info.createlinkcert", cvccertholder.getConcatenated(), caRef.getConcatenated());
				log.info(msg);
				PublicKey pk = cvccert.getPublicKey();
				Date validFrom = cvccert.getCVCertificate().getCertificateBody().getValidFrom();
				Date validTo = cvccert.getCVCertificate().getCertificateBody().getValidTo();
				// Generate a new certificate with the same contents as the passed in certificate, but with new caRef and signature
				CVCertificate retcert = CertificateGenerator.createCertificate(pk, keyPair.getPrivate(), signAlg, caRef, cvccertholder, authRole, rights, validFrom, validTo, catoken.getProvider());
				ret = retcert.getDEREncoded();
				log.debug("Signed a CardVerifiableCertificate CardVerifiableCertificate.");
			} else {
				log.debug("Creating authenticated request with signature alg: "+signAlg+", using provider "+catoken.getProvider());
				CVCAuthenticatedRequest authreq = CertificateGenerator.createAuthenticatedRequest(cvcert, keyPair, signAlg, caRef, catoken.getProvider());
				ret = authreq.getDEREncoded();				
				log.debug("Signed a CardVerifiableCertificate request and returned a CVCAuthenticatedRequest.");
			}
		} catch (IllegalKeyStoreException e) {
			throw new RuntimeException(e);
		} catch (InvalidKeyException e) {
			throw new RuntimeException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (NoSuchProviderException e) {
			throw new RuntimeException(e);
		} catch (SignatureException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		} catch (ConstructionException e) {
			throw new RuntimeException(e);
		} catch (NoSuchFieldException e) {
			throw new RuntimeException(e);
		}
		if (log.isTraceEnabled()) {
			log.trace("<signRequest");
		}
		return ret;
	}
	
	/**
     * @param sequence an optional requested sequence number (serial number) for the certificate. If null a random sequence will be generated.
     * requestX509Name is never used.
	 */
	public Certificate generateCertificate(UserDataVO subject, 
    		X509Name requestX509Name,
            PublicKey publicKey, 
			int keyusage, 
			Date notBefore,
			Date notAfter,
			CertificateProfile certProfile,
			X509Extensions extensions,
			String sequence) throws Exception{
		if (log.isTraceEnabled()) {
			log.trace(">generateCertificate("+notBefore+", "+notAfter+")");
		}
		// Get the fields for the Holder Reference fields
		// country is taken from C in a DN string, mnemonic from CN in a DN string and seq from SERIALNUMBER in a DN string
		String country = CertTools.getPartFromDN(subject.getDN(), "C");
		String mnemonic = CertTools.getPartFromDN(subject.getDN(), "CN");
		String seq = sequence;
		if (seq == null) {
			log.info("No sequence in request, using random 5 number sequence.");
			seq = RandomStringUtils.randomNumeric(5);
		}
		if (seq.length() > 5) {
			log.info("Sequence "+seq+" is too long, only using first 5.");
			seq = seq.substring(0, 4);
		}
		if (seq.length() < 5) {
			log.info("Sequence "+seq+" is too short, padding with zeroes.");
			for (int i = seq.length(); i < 5; i++) {
				seq = "0"+seq;					
			}
		}
		// The DN 'CN=00111,O=CVCA-RPS,C=SE' will make the following reference
        //HolderReferenceField holderRef = new HolderReferenceField("SE","CVCA-RPS","00111");		
        HolderReferenceField holderRef = new HolderReferenceField(country, mnemonic, seq);

        // Check if this is a root CA we are creating
        boolean isRootCA = false;
        if (certProfile.getType() == CertificateProfile.TYPE_ROOTCA) {
        	isRootCA = true;
        }
        
        // Get CA reference
        CardVerifiableCertificate cacert = (CardVerifiableCertificate)getCACertificate();
        // Get certificate validity time notBefore and notAfter
        CertificateValidity val = new CertificateValidity(subject, certProfile, notBefore, notAfter, cacert, isRootCA);

        // We must take the issuer DN directly from the CA-certificate, if we are not creating a new Root CA
        CAReferenceField caRef = null;
        AuthorizationRoleEnum authRole = AuthorizationRoleEnum.IS;
        if (isRootCA) {
        	// This will be an initial root CA, since no CA-certificate exists
        	if (log.isDebugEnabled()) {
        		log.debug("Using Holder Ref also as CA Ref, because it is a root CA");
        	}
            caRef = new CAReferenceField(holderRef.getCountry(), holderRef.getMnemonic(), holderRef.getSequence());
            log.debug("Using AuthorizationRoleEnum.CVCA");
            authRole = AuthorizationRoleEnum.CVCA;
        } else {
        	if (log.isDebugEnabled()) {
        		log.debug("Using CA Ref directly from the CA certificates Holder Ref");
        	}
            HolderReferenceField hr = cacert.getCVCertificate().getCertificateBody().getHolderReference();
            caRef = new CAReferenceField(hr.getCountry(), hr.getMnemonic(), hr.getSequence());
            if (certProfile.getType() == CertificateProfile.TYPE_SUBCA) {
            	// If the holder DV's country and the CA's country is the same, this is a domestic DV
            	// If the holder DV's country is something else, it is a foreign DV
            	if (StringUtils.equals(caRef.getCountry(), holderRef.getCountry())) {
                	authRole = AuthorizationRoleEnum.DV_D;            		
                    log.debug("Using AuthorizationRoleEnum.DV_D");
            	} else {
                	authRole = AuthorizationRoleEnum.DV_F;	            		
                    log.debug("Using AuthorizationRoleEnum.DV_F");
            	}
            }
        }

        AccessRightEnum accessRights = AccessRightEnum.READ_ACCESS_NONE;
        int rights = certProfile.getCVCAccessRights();
        log.debug("Access rights in certificate profile: "+rights);
        switch (rights) {
	        case CertificateProfile.CVC_ACCESS_DG3: accessRights = AccessRightEnum.READ_ACCESS_DG3; break;
	        case CertificateProfile.CVC_ACCESS_DG4: accessRights = AccessRightEnum.READ_ACCESS_DG4; break;
	        case CertificateProfile.CVC_ACCESS_DG3DG4: accessRights = AccessRightEnum.READ_ACCESS_DG3_AND_DG4; break;
	        case CertificateProfile.CVC_ACCESS_NONE: accessRights = AccessRightEnum.READ_ACCESS_NONE; break;
        }
        // Generate the CVC certificate using Keijos library
        CATokenContainer catoken = getCAToken();
        String sigAlg = catoken.getCATokenInfo().getSignatureAlgorithm();
        log.debug("Creating CV certificate with algorithm "+sigAlg+", using provider "+catoken.getProvider()+", public key algorithm from CVC request must match this algorithm.");
        log.debug("CARef: "+caRef.getConcatenated()+"; holderRef: "+holderRef.getConcatenated());
        CVCertificate cvc = CertificateGenerator.createCertificate(publicKey, catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), 
        		sigAlg, caRef, holderRef, authRole, accessRights, val.getNotBefore(), val.getNotAfter(), catoken.getProvider());

        if (log.isDebugEnabled()) {
            log.debug("Certificate: "+cvc.toString());
            log.debug("Certificate bytes: "+new String(Base64.encode(cvc.getDEREncoded())));        	
        }
        
        CardVerifiableCertificate retCert = new CardVerifiableCertificate(cvc);
        // Verify certificate before returning
        retCert.verify(getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN));
        
		log.trace("<generateCertificate()");
		return retCert;                                                                                        
	}


	public CRL generateCRL(Collection certs, int crlnumber) 
	throws CATokenOfflineException, IllegalKeyStoreException, IOException, SignatureException, NoSuchProviderException, InvalidKeyException, CRLException, NoSuchAlgorithmException {
        String msg = intres.getLocalizedMessage("signsession.nocrlcreate", "CVC");
        log.info(msg);
		return null;        
	}

	public CRL generateDeltaCRL(Collection certs, int crlnumber, int basecrlnumber)
	throws CATokenOfflineException, IllegalKeyStoreException, IOException, SignatureException, NoSuchProviderException, InvalidKeyException, CRLException, NoSuchAlgorithmException {
        String msg = intres.getLocalizedMessage("signsession.nocrlcreate", "CVC");
        log.info(msg);
		return null;        
	}

	/** Implementation of UpgradableDataHashMap function getLatestVersion */
	public float getLatestVersion(){
		return LATEST_VERSION;
	}

	/** Implementation of UpgradableDataHashMap function upgrade. 
	 */
	public void upgrade(){
		if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
			// New version of the class, upgrade
            log.info("Upgrading CVCCA with version "+getVersion());

			// Put upgrade code here...
            
            // v1->v2 is only an upgrade in order to upgrade CA token
            // v2->v3 is a upgrade of X509CA that has to be adjusted here two, due to the common heritage
            if (data.get(CRLPERIOD) instanceof Integer) {
            	setCRLPeriod(0L);
            }
            if (data.get(CRLISSUEINTERVAL) instanceof Integer) {
            	setCRLIssueInterval(0L);
            }
            if (data.get(CRLOVERLAPTIME) instanceof Integer) {
            	setCRLOverlapTime(0L);
            }
            if (data.get(DELTACRLPERIOD) instanceof Integer) {
            	setDeltaCRLPeriod(0L);
            }

			data.put(VERSION, new Float(LATEST_VERSION));
		}  
	}

	/**
	 * Method to upgrade new (or existing external caservices)
	 * This method needs to be called outside the regular upgrade
	 * since the CA isn't instansiated in the regular upgrade.
	 *
	 */
	public boolean upgradeExtendedCAServices() {
		// Nothing to upgrade yet
		return false;
	}


	public byte[] decryptData(byte[] data, int cAKeyPurpose) throws Exception {
		throw new IllegalArgumentException("decryptData not implemented for CVC CA");
	}

	public byte[] encryptData(byte[] data, int keyPurpose) throws Exception {
		throw new IllegalArgumentException("encryptData not implemented for CVC CA");
	}

}
