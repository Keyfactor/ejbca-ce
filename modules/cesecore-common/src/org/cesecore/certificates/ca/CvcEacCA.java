/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ca;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Properties;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.Extensions;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.ca.internal.RequestAndPublicKeySelector;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionLocation;
import org.cesecore.certificates.certificate.certextensions.CustomCVCertificateExtension;
import org.cesecore.certificates.certificate.certextensions.CustomCertificateExtension;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.cvc.AccessRightAuthTerm;
import org.ejbca.cvc.AccessRightEnum;
import org.ejbca.cvc.AccessRightSignTermEnum;
import org.ejbca.cvc.AccessRights;
import org.ejbca.cvc.AuthorizationRole;
import org.ejbca.cvc.AuthorizationRoleAuthTermEnum;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.AuthorizationRoleSignTermEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCDiscretionaryDataTemplate;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;


/**
 * CvcEacCA is an implementation of a CVC CA for EAC 1.11 and holds data specific for Certificate generation
 * according to the CVC (Card Verifiable Certificate) standard used in EU EAC electronic passports.  
 *
 * @version $Id$
 */
public class CvcEacCA extends CvcCA implements CvcPlugin {

	private static final long serialVersionUID = 3L;
	private static final Logger log = Logger.getLogger(CvcEacCA.class);

	/** Internal localization of logs and errors */
	private static final InternalResources intres = InternalResources.getInstance();

	
	@Override
	public void init(CVCCAInfo cainfo) {
	    super.init(cainfo);
	}

	@Override
	public void init(HashMap<Object, Object> data, int caId, String subjectDN, String name, int status, Date updateTime, Date expireTime) {
	    super.init(data, caId, subjectDN, name, status, updateTime, expireTime);
	}

    @Override
	public byte[] createRequest(final CryptoToken cryptoToken, final Collection<ASN1Encodable> attributes, final String signAlg, final Certificate cacert,
	        final int signatureKeyPurpose, final CertificateProfile certificateProfile, final AvailableCustomCertificateExtensionsConfiguration cceConfig)
	                throws CryptoTokenOfflineException, CertificateExtensionException {
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
			final Collection<CVCDiscretionaryDataTemplate> certExtensions =
                buildCustomCertificateExtension(null, certificateProfile, keyPair.getPublic(), null, null, cceConfig, CertificateExtensionLocation.CERT);
			log.debug("Creating request with signature alg: "+signAlg+", using provider "+cryptoToken.getSignProviderName());
			CVCertificate request = CertificateGenerator.createRequest(keyPair, signAlg, caRef, holderRef, certExtensions, cryptoToken.getSignProviderName());
			ret = request.getDEREncoded();
		} catch (InvalidKeyException e) {
            throw new IllegalStateException(e);
		} catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
		} catch (NoSuchProviderException e) {
            throw new IllegalStateException(e);
		} catch (SignatureException e) {
            throw new IllegalStateException(e);
		} catch (IOException e) {
            throw new IllegalStateException(e);
		} catch (ConstructionException e) {
            throw new IllegalStateException(e);
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
	            binbytes = CertTools.getCertsFromPEM(new ByteArrayInputStream(request), Certificate.class).get(0).getEncoded();
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
	public void createOrRemoveLinkCertificate(final CryptoToken cryptoToken, final boolean createLinkCertificate, final CertificateProfile certProfile, 
	        final AvailableCustomCertificateExtensionsConfiguration cceConfig, Certificate oldCaCert) throws CryptoTokenOfflineException {
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
	            final AuthorizationRole authRole = caCertificate.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getAuthRole();                    
	            final AccessRights rights = caCertificate.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getAccessRights();
	            final PublicKey publicKey = caCertificate.getPublicKey();
	            final Date validFrom = caCertificate.getCVCertificate().getCertificateBody().getValidFrom();
	            // When we create a link certificate, we want to have an expire date based on the old ca, not the renewed ca
	            final Date validTo = ((CardVerifiableCertificate) oldCaCert).getCVCertificate().getCertificateBody().getValidTo();
	            // Build certificate extensions
	            final Collection<CVCDiscretionaryDataTemplate> certExtensions =
	                    buildCustomCertificateExtension(null, certProfile, publicKey, previousSignKeyPair.getPublic(), null, cceConfig, CertificateExtensionLocation.LINKCERT);
	            // Generate a new certificate with the same contents as the passed in certificate, but with new caRef and signature
	            final CVCertificate retcert = CertificateGenerator.createCertificate(publicKey, previousSignKeyPair.getPrivate(), caSigningAlgorithm, caRef, cvccertholder, authRole, rights, validFrom, validTo, certExtensions, cryptoToken.getSignProviderName());
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
     * @param providedRequestMessage provided request message containing optional information, and will be set with the signing key and provider. 
     * If the certificate profile allows subject DN override this value will be used instead of the value from subject.getDN. Its public key is going to be used if 
     * providedPublicKey == null && subject.extendedInformation.certificateRequest == null. Can be null.
     * @param providedPublicKey provided public key which will have precedence over public key from providedRequestMessage but not over subject.extendedInformation.certificateRequest
     * @param subject end entity information. If it contains certificateRequest under extendedInformation, it will be used instead of providedRequestMessage and providedPublicKey
     */
    @Override
    public Certificate generateCertificate(CryptoToken cryptoToken, EndEntityInformation subject, RequestMessage providedRequestMessage, PublicKey providedPublicKey,
            int keyusage, Date notBefore, Date notAfter, CertificateProfile certProfile, Extensions extensions, String sequence, 
            CertificateGenerationParams certGenParams, final AvailableCustomCertificateExtensionsConfiguration cceConfig)
            throws IllegalValidityException, CryptoTokenOfflineException, CertificateCreateException, CertificateExtensionException, SignatureException, IllegalKeyException {
        if (log.isTraceEnabled()) {
			log.trace(">generateCertificate("+notBefore+", "+notAfter+")");
		}
        
        // Which public key and request shall we use?
        final ExtendedInformation ei = subject.getExtendedInformation();
        final RequestAndPublicKeySelector pkSelector = new RequestAndPublicKeySelector(providedRequestMessage, providedPublicKey, ei);
        final PublicKey publicKey = pkSelector.getPublicKey();
        final RequestMessage request = pkSelector.getRequestMessage();
        
        certProfile.verifyKey(publicKey);
        
		// Get the fields for the Holder Reference fields
		// country is taken from C in a DN string, mnemonic from CN in a DN string and seq from the sequence passed as parameter
        String subjectDn = subject.getCertificateDN();
        if (certProfile.getAllowDNOverride() && (request != null) && (request.getRequestDN() != null)) {
            subjectDn = request.getRequestDN();
            if (log.isDebugEnabled()) {
                log.debug("Using Certificate Holder Reference from certificate request instead of the pre-registered End Entity value.");
            }
        }
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
        final HolderReferenceField holderRef = new HolderReferenceField(country, mnemonic, seq);

        // Check if this is a root CA we are creating
        final boolean isRootCA = (certProfile.getType() == CertificateConstants.CERTTYPE_ROOTCA);
        
        // Get CA reference
        final CardVerifiableCertificate cacert = (CardVerifiableCertificate)getCACertificate();
        // Get certificate validity time notBefore and notAfter
        CertificateValidity val = new CertificateValidity(subject, certProfile, notBefore, notAfter, cacert, isRootCA, /*isLinkCertificate*/ false);
        final CAReferenceField caRef;
        if (isRootCA) {
           // This will be an initial root CA, since no CA-certificate exists
            if (log.isDebugEnabled()) {
                log.debug("Using Holder Ref also as CA Ref, because it is a root CA");
                log.debug("Using AuthorizationRoleEnum.CVCA");
            }
            caRef = new CAReferenceField(holderRef.getCountry(), holderRef.getMnemonic(), holderRef.getSequence());
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Using CA Ref directly from the CA certificates Holder Ref");
            }
            HolderReferenceField hr;
            try {
                hr = cacert.getCVCertificate().getCertificateBody().getHolderReference();
            } catch (NoSuchFieldException e) {
                throw new IllegalStateException("Field was unknown", e);
            }
            caRef = new CAReferenceField(hr.getCountry(), hr.getMnemonic(), hr.getSequence());
        }
        
        final AuthorizationRole authRole = getAuthorizationRole(certProfile, caRef, holderRef);
        final AccessRights accessRights = getAccessRights(certProfile);
        
        // Get key from crypto token
        final CAToken catoken = getCAToken();
        final String sigAlg = catoken.getSignatureAlgorithm();
        final String provider = cryptoToken.getSignProviderName();
        final String alias = getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        final PublicKey caPublicKey = cryptoToken.getPublicKey(alias);
        
        // Build custom certificate extensions
        final Collection<CVCDiscretionaryDataTemplate> certExtensions =
                buildCustomCertificateExtension(subject, certProfile, publicKey, caPublicKey, val, cceConfig, CertificateExtensionLocation.CERT);
        
        // Generate the CVC certificate using Keijos library
        final PrivateKey caPrivateKey = cryptoToken.getPrivateKey(alias);
        if (log.isDebugEnabled()) {
            log.debug("Creating CV certificate with algorithm "+sigAlg+", using provider "+provider+", public key algorithm from CVC request must match this algorithm.");
            log.debug("CARef: "+caRef.getConcatenated()+"; holderRef: "+holderRef.getConcatenated());
        }
        CVCertificate cvc;
        try {
            cvc = CertificateGenerator.createCertificate(publicKey, caPrivateKey, sigAlg, caRef, holderRef, authRole, accessRights,
                    val.getNotBefore(), val.getNotAfter(), certExtensions, provider);
            if (log.isDebugEnabled()) {
                log.debug("Certificate: " + cvc.toString());
                try {
                    log.debug("Certificate bytes: " + new String(Base64.encode(cvc.getDEREncoded())));
                } catch (IOException e) {
                    throw new IllegalStateException("Unexpected IOException was caught.", e);
                }
            }
            CardVerifiableCertificate retCert = new CardVerifiableCertificate(cvc);
            // Verify certificate before returning
            retCert.verify(cryptoToken.getPublicKey(alias));
         // Before returning from this method, we will set the private key and provider in the request message, in case the response  message needs to be signed
            if (request != null) {
                request.setResponseKeyInfo(caPrivateKey, provider);
            }
            if (log.isTraceEnabled()) {
                log.trace("<generateCertificate()");
            }
            return retCert;
        } catch (InvalidKeyException e) {
            throw new CertificateCreateException("CA's public key was invalid,", e);
        } catch (NoSuchAlgorithmException e) {
            throw new CertificateCreateException(e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Provider was unknown", e);
        } catch (CertificateException e) {
            throw new CertificateCreateException(e);
        } catch (ConstructionException e) {
            throw new IllegalStateException("Certificate couldn't be constructed for unknown reason.", e);
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected IOException was caught.", e);
        }
                                                                                         
	}

    private Collection<CVCDiscretionaryDataTemplate> buildCustomCertificateExtension(final EndEntityInformation subject, final CertificateProfile certProfile, final PublicKey publicKey,
            final PublicKey caPublicKey, final CertificateValidity validity, final AvailableCustomCertificateExtensionsConfiguration cceConfig,
            final CertificateExtensionLocation certExtLocation) throws CertificateExtensionException {
        Collection<CVCDiscretionaryDataTemplate> certExtensions = null;
        for (final Integer certExtId : certProfile.getUsedCertificateExtensions()) {
            final CustomCertificateExtension certExt = cceConfig.getCustomCertificateExtension(certExtId);
            if (certExt instanceof CustomCVCertificateExtension) {
                final CustomCVCertificateExtension cvcExt = (CustomCVCertificateExtension) certExt;
                switch (certExtLocation) {
                case CERT:
                    if (!cvcExt.isIncludedInCertificates()) continue;
                    break;
                case CSR:
                    if (!cvcExt.isIncludedInCSR()) continue;
                    break;
                case LINKCERT:
                    if (!cvcExt.isIncludedInLinkCertificates()) continue;
                    break;
                }
                
                if (certExtensions == null) {
                    certExtensions = new ArrayList<>();
                }
                if (log.isDebugEnabled()) {
                    log.debug("Adding CV Certificate Extension to " + certExtLocation.toString().toLowerCase(Locale.ROOT) + ": " + cvcExt.getDisplayName());
                }
                final CVCDiscretionaryDataTemplate ddt =
                            cvcExt.getValueCVC(subject, this, certProfile, publicKey, caPublicKey, validity, certExtLocation);
                certExtensions.add(ddt);
            }
        }
        return certExtensions;
    }

    @Override
    public String getCvcType() {
        return "EAC";
    }
    
    private AuthorizationRole getAuthorizationRole(final CertificateProfile certProfile,
            CAReferenceField caRef, HolderReferenceField holderRef) {
        
        // Determine which set of roles to use
        final AuthorizationRole roleRootCA, roleDSubCA, roleFSubCA, roleEndEntity;
        switch (certProfile.getCVCTerminalType()) {
        case CertificateProfile.CVC_TERMTYPE_IS:
            roleRootCA = AuthorizationRoleEnum.CVCA;
            roleDSubCA = AuthorizationRoleEnum.DV_D;
            roleFSubCA = AuthorizationRoleEnum.DV_F;
            roleEndEntity = AuthorizationRoleEnum.IS;
            break;
        case CertificateProfile.CVC_TERMTYPE_AT:
            roleRootCA = AuthorizationRoleAuthTermEnum.CVCA;
            roleDSubCA = AuthorizationRoleAuthTermEnum.DV_D;
            roleFSubCA = AuthorizationRoleAuthTermEnum.DV_F;
            roleEndEntity = AuthorizationRoleAuthTermEnum.AUTHTERM;
            break;
        case CertificateProfile.CVC_TERMTYPE_ST:
            roleRootCA = AuthorizationRoleSignTermEnum.CVCA;
            if (certProfile.getCVCSignTermDVType() == CertificateProfile.CVC_SIGNTERM_DV_AB) {
                roleDSubCA = AuthorizationRoleSignTermEnum.DV_AB;
                roleFSubCA = AuthorizationRoleSignTermEnum.DV_AB;
            } else {
                roleDSubCA = AuthorizationRoleSignTermEnum.DV_CSP;
                roleFSubCA = AuthorizationRoleSignTermEnum.DV_CSP;
            }
            roleEndEntity = AuthorizationRoleSignTermEnum.SIGNTERM;
            break;
        default:
            throw new IllegalStateException("Value of terminal type was not handled in switch");
        }
        
        // We must take the issuer DN directly from the CA-certificate, if we are not creating a new Root CA
        final AuthorizationRole authRole;
        if (certProfile.getType() == CertificateConstants.CERTTYPE_ROOTCA) {
            authRole = roleRootCA;
        } else if (certProfile.getType() == CertificateConstants.CERTTYPE_SUBCA) {
            // If the holder DV's country and the CA's country is the same, this is a domestic DV
            // If the holder DV's country is something else, it is a foreign DV
            if (StringUtils.equals(caRef.getCountry(), holderRef.getCountry())) {
                authRole = roleDSubCA;
            } else {
                authRole = roleFSubCA;
            }
        } else {
            authRole = roleEndEntity;
        }
        
        if (log.isDebugEnabled()) {
            log.debug("Using authorization role "+authRole);
        }
        return authRole;
    }
    
    private AccessRights getAccessRights(final CertificateProfile certProfile) {
        AccessRights accessRights = AccessRightEnum.READ_ACCESS_NONE;
        
        switch (certProfile.getCVCTerminalType()) {
        case CertificateProfile.CVC_TERMTYPE_IS: {
            int rightsValue = certProfile.getCVCAccessRights();
            switch (rightsValue) {
            case CertificateProfile.CVC_ACCESS_NONE: accessRights = AccessRightEnum.READ_ACCESS_NONE; break;
            case CertificateProfile.CVC_ACCESS_DG3: accessRights = AccessRightEnum.READ_ACCESS_DG3; break;
            case CertificateProfile.CVC_ACCESS_DG4: accessRights = AccessRightEnum.READ_ACCESS_DG4; break;
            case CertificateProfile.CVC_ACCESS_DG3DG4: accessRights = AccessRightEnum.READ_ACCESS_DG3_AND_DG4; break;
            default: throw new IllegalStateException();
            }
            break; }
        case CertificateProfile.CVC_TERMTYPE_AT: {
            byte[] rightsValue = certProfile.getCVCLongAccessRights();
            accessRights = new AccessRightAuthTerm(rightsValue);
            break; }
        case CertificateProfile.CVC_TERMTYPE_ST: {
            int rightsValue = certProfile.getCVCAccessRights();
            switch (rightsValue) {
            case CertificateProfile.CVC_ACCESS_NONE: accessRights = AccessRightSignTermEnum.ACCESS_NONE; break;
            case CertificateProfile.CVC_ACCESS_SIGN: accessRights = AccessRightSignTermEnum.ACCESS_SIGN; break;
            case CertificateProfile.CVC_ACCESS_QUALSIGN: accessRights = AccessRightSignTermEnum.ACCESS_QUALSIGN; break;
            case CertificateProfile.CVC_ACCESS_SIGN_AND_QUALSIGN: accessRights = AccessRightSignTermEnum.ACCESS_SIGN_AND_QUALSIGN; break;
            default: throw new IllegalStateException();
            }
            break; }
        default:
            throw new IllegalStateException();
        }
        
        if (log.isDebugEnabled()) {
            log.debug("Using access rights "+accessRights);
        }
        return accessRights;
    }

}
