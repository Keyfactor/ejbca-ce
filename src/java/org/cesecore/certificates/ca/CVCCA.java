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
package org.cesecore.certificates.ca;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CRLHolder;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
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

	/** Creates a new instance of CA, this constructor should be used when a new CA is created */
	public CVCCA(CVCCAInfo cainfo) {
		super(cainfo);  
		data.put(CA.CATYPE, Integer.valueOf(CAInfo.CATYPE_CVC));
		data.put(VERSION, new Float(LATEST_VERSION));   
	}

	/** Constructor used when retrieving existing CVCCA from database. */
	public CVCCA(HashMap<Object, Object> data, int caId, String subjectDN, String name, int status, Date updateTime) {
		super(data);
		final List<ExtendedCAServiceInfo> externalcaserviceinfos = new ArrayList<ExtendedCAServiceInfo>();
		for (final Integer externalCAServiceType : getExternalCAServiceTypes()) {
			final ExtendedCAServiceInfo info = this.getExtendedCAServiceInfo(externalCAServiceType.intValue());
			if (info != null) {
				externalcaserviceinfos.add(info);  	    			
			}
		}
		final CAInfo info = new CVCCAInfo(subjectDN, name, status, updateTime, getCertificateProfileId(),  
				getValidity(), getExpireTime(), getCAType(), getSignedBy(), getCertificateChain(),
				getCAToken(), getDescription(), getRevocationReason(), getRevocationDate(), getCRLPeriod(), getCRLIssueInterval(), getCRLOverlapTime(), getDeltaCRLPeriod(), 
				getCRLPublishers(), getFinishUser(), externalcaserviceinfos, 
				getApprovalSettings(), getNumOfRequiredApprovals(),
				getIncludeInHealthCheck(), isDoEnforceUniquePublicKeys(), isDoEnforceUniqueDistinguishedName(), isDoEnforceUniqueSubjectDNSerialnumber(),
				isUseCertReqHistory(), isUseUserStorage(), isUseCertificateStorage());
		super.setCAInfo(info);
        setCAId(caId);
	}

	@Override
	public byte[] createPKCS7(CryptoToken cryptoToken, Certificate cert, boolean includeChain) throws SignRequestSignatureException {
		log.info(intres.getLocalizedMessage("cvc.info.nocvcpkcs7"));
		return null;
	}    

	/** @see CA#createRequest(Collection, String, Certificate, int) */
	public byte[] createRequest(CryptoToken cryptoToken, Collection<ASN1Encodable> attributes, String signAlg, Certificate cacert, int signatureKeyPurpose) throws CryptoTokenOfflineException {
		if (log.isTraceEnabled()) {
			log.trace(">createRequest: "+signAlg+", "+CertTools.getSubjectDN(cacert)+", "+signatureKeyPurpose);
		}
		byte[] ret = null;
		// Create a CVC request. 
		// No outer signature on this self signed request
		KeyPair keyPair;
		try {
			CAToken catoken = getCAToken();
			final String alias = catoken.getAliasFromPurpose(signatureKeyPurpose);
			keyPair = new KeyPair(cryptoToken.getPublicKey(alias), cryptoToken.getPrivateKey(alias));
			String subject = getCAInfo().getSubjectDN();
			String country = CertTools.getPartFromDN(subject, "C");
			String mnemonic = CertTools.getPartFromDN(subject, "CN");
			String seq = getCAToken().getKeySequence(); 
			if (signatureKeyPurpose == CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT) {
				// See if we have a next sequence to put in the holder reference instead of the current one, 
				// since we are using the next key we should use the next sequence
				final Properties caTokenProperties = catoken.getProperties();
				final String nextSequence = (String)caTokenProperties.get(CATokenConstants.NEXT_SEQUENCE_PROPERTY);
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
						log.debug("Using caRef from the CA certificate: "+caRef.getConcatenated());					
					} catch (NoSuchFieldException e) {
						log.debug("CA certificate does not contain a Holder reference to use as CARef in request.");
					}					
				} else {
					log.debug("CA certificate is not a CardVerifiableCertificate.");					
				}
			} else {
				caRef = new CAReferenceField(holderRef.getCountry(), holderRef.getMnemonic(), holderRef.getSequence());				
				log.debug("No CA cert, using caRef from the holder itself: "+caRef.getConcatenated());					
			}
			log.debug("Creating request with signature alg: "+signAlg+", using provider "+cryptoToken.getSignProviderName());
			CVCertificate request = CertificateGenerator.createRequest(keyPair, signAlg, caRef, holderRef, cryptoToken.getSignProviderName());
			ret = request.getDEREncoded();
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
	 *  This means that an authenticated request, CVCAuthenticatedRequest is created.
	 */
	@Override
    public byte[] createAuthCertSignRequest(CryptoToken cryptoToken, byte[] request) throws CryptoTokenOfflineException {
	    byte[] ret = null;
	    try {
	        CardVerifiableCertificate cacert = (CardVerifiableCertificate)getCACertificate();
	        if (cacert == null) {
	            // if we don't have a CA certificate, we can't sign any request
	            return null;
	        }
	        CAToken catoken = getCAToken();
	        final String alias = catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
	        KeyPair keyPair = new KeyPair(cryptoToken.getPublicKey(alias), cryptoToken.getPrivateKey(alias));
	        String signAlg = getCAToken().getSignatureAlgorithm();
	        // Create the CA reference, should be from signing certificates holder field
	        HolderReferenceField caHolder = cacert.getCVCertificate().getCertificateBody().getHolderReference();
	        // Set the CA reference field for the authentication signature
	        CAReferenceField caRef = new CAReferenceField(caHolder.getCountry(), caHolder.getMnemonic(), caHolder.getSequence());
	        byte[] binbytes = request;
	        try {
	            // We don't know if this is a PEM or binary certificate or request request so we first try to 
	            // decode it as a PEM certificate, and if it's not we try it as a PEM request and finally as a binary request 
	            binbytes = CertTools.getCertsFromPEM(new ByteArrayInputStream(request)).get(0).getEncoded();
	        } catch (Exception e) {
	            log.debug("This is not a PEM certificate?: "+e.getMessage());
	            try {
	                binbytes = RequestMessageUtils.getRequestBytes(request);
	            } catch (Exception e2) {
	                log.debug("This is not a PEM request?: "+e2.getMessage());                      
	            }
	        }
	        // This can be either a CV certificate, a CV certificate request, or an authenticated request that we should re-sign
	        final CVCObject parsedObject = CertificateParser.parseCVCObject(binbytes);
            CVCertificate cvcert = null;
	        if (parsedObject instanceof CVCertificate) {
	            cvcert = (CVCertificate) parsedObject;
	            log.debug("This is a reqular CV request, or cert.");                    
	        } else if (parsedObject instanceof CVCAuthenticatedRequest) {
	            cvcert = ((CVCAuthenticatedRequest)parsedObject).getRequest();
	            log.debug("This is an authenticated CV request, we will overwrite the old authentication with a new.");                 
	        }
	        log.debug("Creating authenticated request with signature alg: "+signAlg+", using provider "+cryptoToken.getSignProviderName());
	        ret = CertificateGenerator.createAuthenticatedRequest(cvcert, keyPair, signAlg, caRef, cryptoToken.getSignProviderName()).getDEREncoded();
	        log.debug("Signed a CardVerifiableCertificate request and returned a CVCAuthenticatedRequest.");
	    } catch (ParseException e) {
	        log.info(intres.getLocalizedMessage("cvc.error.notcvcrequest"), e);
	    } catch (ClassCastException e) {
	        log.info(intres.getLocalizedMessage("cvc.error.notcvcrequest"), e);
	    } catch (Exception e) {
	        throw new RuntimeException(e);
	    }
	    return ret;
    }

	@Override
	public void createOrRemoveLinkCertificate(final CryptoToken cryptoToken, final boolean createLinkCertificate, final CertificateProfile certProfile) throws CryptoTokenOfflineException {
	    byte[] ret = null;
	    if (createLinkCertificate) {
	        try {
	            final CardVerifiableCertificate caCertificate = (CardVerifiableCertificate)getCACertificate();
	            final CAToken caToken = getCAToken();
	            final String previousSignKeyAlias = caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
	            final KeyPair previousSignKeyPair = new KeyPair(cryptoToken.getPublicKey(previousSignKeyAlias), cryptoToken.getPrivateKey(previousSignKeyAlias));
	            final String caSigningAlgorithm = caToken.getSignatureAlgorithm();
	            final HolderReferenceField caHolder = caCertificate.getCVCertificate().getCertificateBody().getHolderReference();
	            final Properties caTokenProperties = caToken.getProperties();
	            final String previousKeySequence = (String)caTokenProperties.get(CATokenConstants.PREVIOUS_SEQUENCE_PROPERTY);
	            final CAReferenceField caRef = new CAReferenceField(caHolder.getCountry(), caHolder.getMnemonic(), previousKeySequence);
	            final HolderReferenceField cvccertholder = caCertificate.getCVCertificate().getCertificateBody().getHolderReference();
	            final AuthorizationRoleEnum authRole = caCertificate.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole();                    
	            final AccessRightEnum rights = caCertificate.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getAccessRight();
	            final PublicKey publicKey = caCertificate.getPublicKey();
	            final Date validFrom = caCertificate.getCVCertificate().getCertificateBody().getValidFrom();
	            final Date validTo = caCertificate.getCVCertificate().getCertificateBody().getValidTo();
	            // Generate a new certificate with the same contents as the passed in certificate, but with new caRef and signature
	            final CVCertificate retcert = CertificateGenerator.createCertificate(publicKey, previousSignKeyPair.getPrivate(), caSigningAlgorithm, caRef, cvccertholder, authRole, rights, validFrom, validTo, cryptoToken.getSignProviderName());
	            ret = retcert.getDEREncoded();
	            log.info(intres.getLocalizedMessage("cvc.info.createlinkcert", cvccertholder.getConcatenated(), caRef.getConcatenated()));
	        } catch (CryptoTokenOfflineException e) {
	            throw e;
	        } catch (Exception e) {
	            throw new RuntimeException("Bad CV CA certificate.", e);
	        }
	    }
	    updateLatestLinkCertificate(ret);
	}
	
	/**
     * @param sequence an optional requested sequence number (serial number) for the certificate. If null a random sequence will be generated.
     * requestX500Name is never used.
	 */
	public Certificate generateCertificate(CryptoToken cryptoToken, EndEntityInformation subject, 
    		X500Name requestX500Name,
            PublicKey publicKey, 
			int keyusage, 
			Date notBefore,
			Date notAfter,
			CertificateProfile certProfile,
			Extensions extensions,
			String sequence) throws Exception{
		if (log.isTraceEnabled()) {
			log.trace(">generateCertificate("+notBefore+", "+notAfter+")");
		}
		// Get the fields for the Holder Reference fields
		// country is taken from C in a DN string, mnemonic from CN in a DN string and seq from SERIALNUMBER in a DN string
		final String subjectDn = subject.getCertificateDN();
		final String country = CertTools.getPartFromDN(subjectDn, "C");
		if(country == null) {
	        final String msg = intres.getLocalizedMessage("cvc.error.missingdnfield", subjectDn, "Country");
            throw new InvalidParameterException(msg);
		}
		final String mnemonic = CertTools.getPartFromDN(subjectDn, "CN");
        if(mnemonic == null) {
            final String msg = intres.getLocalizedMessage("cvc.error.missingdnfield", subjectDn, "Common Name");
            throw new InvalidParameterException(msg);
        }
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
		// The DN 'SERIALNUMBER=00111,CN=CVCA-RPS,C=SE' will make the following reference
        //HolderReferenceField holderRef = new HolderReferenceField("SE","CVCA-RPS","00111");		
        HolderReferenceField holderRef = new HolderReferenceField(country, mnemonic, seq);

        // Check if this is a root CA we are creating
        boolean isRootCA = false;
        if (certProfile.getType() == CertificateConstants.CERTTYPE_ROOTCA) {
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
            if (certProfile.getType() == CertificateConstants.CERTTYPE_SUBCA) {
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
        CAToken catoken = getCAToken();
        String sigAlg = catoken.getSignatureAlgorithm();
        log.debug("Creating CV certificate with algorithm "+sigAlg+", using provider "+cryptoToken.getSignProviderName()+", public key algorithm from CVC request must match this algorithm.");
        log.debug("CARef: "+caRef.getConcatenated()+"; holderRef: "+holderRef.getConcatenated());
        final String alias = getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        CVCertificate cvc = CertificateGenerator.createCertificate(publicKey, cryptoToken.getPrivateKey(alias), 
        		sigAlg, caRef, holderRef, authRole, accessRights, val.getNotBefore(), val.getNotAfter(), cryptoToken.getSignProviderName());

        if (log.isDebugEnabled()) {
            log.debug("Certificate: "+cvc.toString());
            log.debug("Certificate bytes: "+new String(Base64.encode(cvc.getDEREncoded())));        	
        }
        
        CardVerifiableCertificate retCert = new CardVerifiableCertificate(cvc);
        // Verify certificate before returning
        retCert.verify(cryptoToken.getPublicKey(alias));
        if (log.isTraceEnabled()) {
        	log.trace("<generateCertificate()");
        }
		return retCert;                                                                                        
	}

    @Override
    public X509CRLHolder generateCRL(CryptoToken cryptoToken, Collection<RevokedCertInfo> certs, int crlnumber) {
        String msg = intres.getLocalizedMessage("createcrl.nocrlcreate", "CVC");
        log.info(msg);
        return null;
    }

    @Override
    public X509CRLHolder generateDeltaCRL(CryptoToken cryptoToken, Collection<RevokedCertInfo> certs, int crlnumber, int basecrlnumber) {
        String msg = intres.getLocalizedMessage("createcrl.nocrlcreate", "CVC");
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
	 * since the CA isn't instantiated in the regular upgrade.
	 */
	public boolean upgradeExtendedCAServices() {
		// Nothing to upgrade yet
		return false;
	}

	@Override
	public byte[] decryptData(CryptoToken cryptoToken, byte[] data, int cAKeyPurpose) throws Exception {
		throw new IllegalArgumentException("decryptData not implemented for CVC CA");
	}

    @Override
	public byte[] encryptData(CryptoToken cryptoToken, byte[] data, int keyPurpose) throws Exception {
		throw new IllegalArgumentException("encryptData not implemented for CVC CA");
	}
}
