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

package org.ejbca.core.ejb.ca.sign;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.ObjectNotFoundException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateCreateSessionBean;
import org.cesecore.certificates.certificate.CertificateCreateSessionLocal;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.CustomCertSerialNumberException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.store.CertReqHistorySessionLocal;
import org.ejbca.core.ejb.ra.UserAdminSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;

/**
 * Creates and signs certificates.
 *
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "SignSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class RSASignSessionBean implements SignSessionLocal, SignSessionRemote {

    private static final Logger log = Logger.getLogger(RSASignSessionBean.class);
    
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CertReqHistorySessionLocal certreqHistorySession;
    @EJB
    private CertificateCreateSessionLocal certificateCreateSession;
    @EJB
    private EndEntityAuthenticationSessionLocal authenticationSession;
    @EJB
    private UserAdminSessionLocal userAdminSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private CrlStoreSessionLocal crlStoreSession;

    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    /** Default create for SessionBean without any creation Arguments. */
	@PostConstruct
    public void ejbCreate() {
    	if (log.isTraceEnabled()) {
    		log.trace(">ejbCreate()");
    	}
        try {
            // Install BouncyCastle provider
        	CryptoProviderTools.installBCProviderIfNotAvailable();
        } catch (Exception e) {
            log.debug("Caught exception in ejbCreate(): ", e);
            throw new EJBException(e);
        }
    	if (log.isTraceEnabled()) {
    		log.trace("<ejbCreate()");
    	}
    }

	@TransactionAttribute(TransactionAttributeType.SUPPORTS)
	@Override
    public Collection<Certificate> getCertificateChain(AuthenticationToken admin, int caid) throws AuthorizationDeniedException {
    	try {
    		return caSession.getCA(admin, caid).getCertificateChain();
    	} catch (CADoesntExistsException e) {
    		throw new EJBException(e);
    	}
    }

	@Override
    public byte[] createPKCS7(AuthenticationToken admin, Certificate cert, boolean includeChain) throws CADoesntExistsException, SignRequestSignatureException, AuthorizationDeniedException {
        Integer caid = Integer.valueOf(CertTools.getIssuerDN(cert).hashCode());
        return createPKCS7(admin, caid.intValue(), cert, includeChain);
    }

	@Override
    public byte[] createPKCS7(AuthenticationToken admin, int caId, boolean includeChain) throws CADoesntExistsException, AuthorizationDeniedException {
        try {
            return createPKCS7(admin, caId, null, includeChain);
        } catch (SignRequestSignatureException e) {
        	String msg = intres.getLocalizedMessage("error.unknown");
            log.error(msg, e);
            throw new EJBException(e);
        }
    }

    /**
     * Internal helper method
     *
     * @param admin Information about the administrator or admin performing the event.
     * @param caId  CA for which we want a PKCS7 certificate chain.
     * @param cert  client certificate which we want encapsulated in a PKCS7 together with
     *              certificate chain, or null
     * @return The DER-encoded PKCS7 message.
     * @throws CADoesntExistsException if the CA does not exist or is expired, or has an invalid certificate
     * @throws AuthorizationDeniedException 
     */
    private byte[] createPKCS7(AuthenticationToken admin, int caId, Certificate cert, boolean includeChain) throws CADoesntExistsException, SignRequestSignatureException, AuthorizationDeniedException {
    	if (log.isTraceEnabled()) {
            log.trace(">createPKCS7(" + caId + ", " + CertTools.getIssuerDN(cert) + ")");
    	}
        CA ca = caSession.getCA(admin, caId);
        byte[] returnval = ca.createPKCS7(cert, includeChain);
    	if (log.isTraceEnabled()) {
    		log.trace("<createPKCS7()");
    	}
        return returnval;
    }

    @Override
    public Certificate createCertificate(AuthenticationToken admin, String username, String password, PublicKey pk) throws EjbcaException, ObjectNotFoundException, AuthorizationDeniedException, CesecoreException {
        // Default key usage is defined in certificate profiles
        return createCertificate(admin, username, password, pk, -1, null, null, CertificateProfileConstants.CERTPROFILE_NO_PROFILE, SecConst.CAID_USEUSERDEFINED);
    }

    @Override
    public Certificate createCertificate(AuthenticationToken admin, String username, String password, PublicKey pk, int keyusage, Date notBefore, Date notAfter) throws ObjectNotFoundException, AuthorizationDeniedException, EjbcaException, CesecoreException {
        return createCertificate(admin, username, password, pk, keyusage, notBefore, notAfter, CertificateProfileConstants.CERTPROFILE_NO_PROFILE, SecConst.CAID_USEUSERDEFINED);
    }

    @Override
    public Certificate createCertificate(AuthenticationToken admin, String username, String password, Certificate incert) throws CesecoreException, ObjectNotFoundException, AuthorizationDeniedException, EjbcaException {
        if (log.isTraceEnabled()) {
        	log.trace(">createCertificate(cert)");
        }
        X509Certificate cert = (X509Certificate) incert;
        try {
            // Convert the certificate to a BC certificate. SUN does not handle verifying RSASha256WithMGF1 for example 
            Certificate bccert = CertTools.getCertfromByteArray(incert.getEncoded());
            bccert.verify(cert.getPublicKey());
        } catch (Exception e) {
        	log.debug("Exception verify POPO: ", e);
        	String msg = intres.getLocalizedMessage("signsession.popverificationfailed");
            throw new SignRequestSignatureException(msg);
        }
        Certificate ret = createCertificate(admin, username, password, cert.getPublicKey(), CertTools.sunKeyUsageToBC(cert.getKeyUsage()), null, null);
        if (log.isTraceEnabled()) {
        	log.trace("<createCertificate(cert)");
        }
        return ret;
    }

    @Override
    public ResponseMessage createCertificate(AuthenticationToken admin, RequestMessage req, Class responseClass, EndEntityInformation suppliedUserData) throws EjbcaException, CesecoreException, AuthorizationDeniedException {
    	if (log.isTraceEnabled()) {
    		log.trace(">createCertificate(IRequestMessage)");
    	}
        // Get CA that will receive request
    	EndEntityInformation data = null;
        ResponseMessage ret = null;
        CA ca;
        if (suppliedUserData == null) {
        	ca = getCAFromRequest(admin, req);
        } else {
        	ca = caSession.getCA(admin, suppliedUserData.getCAId()); // Take the CAId from the supplied userdata, if any
        }
        try {            
            if (ca.isUseUserStorage() && req.getUsername() == null) {
            	String msg = intres.getLocalizedMessage("signsession.nouserinrequest", req.getRequestDN());
                throw new SignRequestException(msg);
            } else if (ca.isUseUserStorage() && req.getPassword() == null) {
            	String msg = intres.getLocalizedMessage("signsession.nopasswordinrequest");
                throw new SignRequestException(msg);
            } else {        
            	try {
    				// If we haven't done so yet, authenticate user. (Only if we store UserData for this CA.)
            		if (ca.isUseUserStorage()) {
                		data = authUser(admin, req.getUsername(), req.getPassword());
            		} else {
            			data = suppliedUserData;
            		}
                    // We need to make sure we use the users registered CA here
                    if (data.getCAId() != ca.getCAId()) {
                    	final String failText = intres.getLocalizedMessage("signsession.wrongauthority", Integer.valueOf(ca.getCAId()), Integer.valueOf(data.getCAId()));
                		log.info(failText);
                		ret = createRequestFailedResponse(admin, req, responseClass, FailInfo.WRONG_AUTHORITY, failText);
                    } else {

                    	// Issue the certificate from the request
                    	ret = certificateCreateSession.createCertificate(admin, data, req, responseClass);
                    }
            	} catch (ObjectNotFoundException oe) {
            		// If we didn't find the entity return error message
                	final String failText = intres.getLocalizedMessage("signsession.nosuchuser", req.getUsername());
            		log.info(failText, oe);
            		ret = createRequestFailedResponse(admin, req, responseClass, FailInfo.INCORRECT_DATA, failText);
            	}
            }
            ret.create();
            // Call authentication session and tell that we are finished with this user. (Only if we store UserData for this CA.)
            if (ca.isUseUserStorage() && data!=null) {
        		finishUser(ca, data);
            }            	
        } catch (CustomCertSerialNumberException e) {
    		cleanUserCertDataSN(data);
    		throw e;
        } catch (IllegalKeyException ke) {
            log.error("Key is of unknown type: ", ke);
            throw ke;
        } catch (CryptoTokenOfflineException ctoe) {
        	String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getSubjectDN());
        	CryptoTokenOfflineException ex = new CryptoTokenOfflineException(msg);
        	ex.initCause(ctoe);
        	throw ex;
        } catch (EjbcaException e) {
            throw e;
        } catch (NoSuchProviderException e) {
            log.error("NoSuchProvider provider: ", e);
        } catch (InvalidKeyException e) {
            log.error("Invalid key in request: ", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("No such algorithm: ", e);
        } catch (IOException e) {
            log.error("Cannot create response message: ", e);
        }
    	if (log.isTraceEnabled()) {
    		log.trace("<createCertificate(IRequestMessage)");
    	}
        return ret;
    }
    
    @Override
	public Certificate createCertificate(AuthenticationToken admin, String username, String password, PublicKey pk, int keyusage, Date notBefore, Date notAfter, int certificateprofileid, int caid) throws ObjectNotFoundException, CADoesntExistsException, AuthorizationDeniedException, EjbcaException, CesecoreException {
		if (log.isTraceEnabled()) {
			log.trace(">createCertificate(pk, ku, date)");
		}
	    // Authorize user and get DN
		final EndEntityInformation data = authUser(admin, username, password);
		if (log.isDebugEnabled()) {
			log.debug("Authorized user " + username + " with DN='" + data.getDN() + "'." + " with CA=" + data.getCAId());
		}
	    if (certificateprofileid != CertificateProfileConstants.CERTPROFILE_NO_PROFILE) {
	    	if (log.isDebugEnabled()) {
	    		log.debug("Overriding user certificate profile with :" + certificateprofileid);
	    	}
	    	data.setCertificateProfileId(certificateprofileid);
	    }
	    // Check if we should override the CAId
	    if (caid != SecConst.CAID_USEUSERDEFINED) {
	    	if (log.isDebugEnabled()) {
	        	log.debug("Overriding user caid with :" + caid);
	    	}
	    	data.setCAId(caid);
	    }
		if (log.isDebugEnabled()) {
	        log.debug("User type=" + data.getType());
		}
	    // Get CA object and make sure it's active
	    CA ca = caSession.getCA(admin, data.getCAId());
	    if (ca.getStatus() != SecConst.CA_ACTIVE) {
	    	String msg = intres.getLocalizedMessage("signsession.canotactive", ca.getSubjectDN());
	    	throw new EJBException(msg);
	    }
	    Certificate cert;
	    try {
	    	// Now finally after all these checks, get the certificate, we don't have any sequence number or extensions available here
	    	cert = createCertificate(admin, data, null, ca, pk, keyusage, notBefore, notAfter, null, null);
	    	// Call authentication session and tell that we are finished with this user
			finishUser(ca, data);
	    } catch (CustomCertSerialNumberException e) {
	    	cleanUserCertDataSN(data);
	    	throw e;
	    }
		if (log.isTraceEnabled()) {
			log.trace("<createCertificate(pk, ku, date)");
		}
	    return cert;
	}

    @Override
    public ResponseMessage createRequestFailedResponse(AuthenticationToken admin, RequestMessage req,  Class responseClass, FailInfo failInfo, String failText) throws  AuthLoginException, AuthStatusException, IllegalKeyException, CADoesntExistsException, SignRequestSignatureException, SignRequestException, CryptoTokenOfflineException, AuthorizationDeniedException {
    	if (log.isTraceEnabled()) {
    		log.trace(">createRequestFailedResponse(IRequestMessage)");
    	}
        ResponseMessage ret = null;            
        CA ca = getCAFromRequest(admin, req);
        try {
            CAToken catoken = ca.getCAToken();
            // See if we need some key material to decrypt request
            if (req.requireKeyInfo()) {
                // You go figure...scep encrypts message with the public CA-cert
                req.setKeyInfo(ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getCryptoToken().getSignProviderName());
            }
            // Verify the request
            if (req.verify() == false) {
            	String msg = intres.getLocalizedMessage("signsession.popverificationfailed");
                throw new SignRequestSignatureException(msg);
            }
            //Create the response message with all nonces and checks etc
            ret = req.createResponseMessage(responseClass, req, ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getCryptoToken().getSignProviderName());
            ret.setStatus(ResponseStatus.FAILURE);
            ret.setFailInfo(failInfo); 
            ret.setFailText(failText);
            ret.create();
        } catch (IllegalCryptoTokenException e) {
            throw new IllegalKeyException(e);
        } catch (NoSuchProviderException e) {
            log.error("NoSuchProvider provider: ", e);
        } catch (InvalidKeyException e) {
            log.error("Invalid key in request: ", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("No such algorithm: ", e);
        } catch (IOException e) {
            log.error("Cannot create response message: ", e);
        } catch (CryptoTokenOfflineException ctoe) {
        	String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getSubjectDN());
            log.warn(msg, ctoe);
            throw ctoe;
        }
        if (log.isTraceEnabled()) {
        	log.trace("<createRequestFailedResponse(IRequestMessage)");
        }
        return ret;
    }

    @Override
    public RequestMessage decryptAndVerifyRequest(AuthenticationToken admin, RequestMessage req) throws ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException, CryptoTokenOfflineException, AuthorizationDeniedException {
    	if (log.isTraceEnabled()) {
    		log.trace(">decryptAndVerifyRequest(IRequestMessage)");
    	}
        // Get CA that will receive request
        CA ca = getCAFromRequest(admin, req);
        try {
            CAToken catoken = ca.getCAToken();
            // See if we need some key material to decrypt request
            if (req.requireKeyInfo()) {
                // You go figure...scep encrypts message with the public CA-cert
                req.setKeyInfo(ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getCryptoToken().getSignProviderName());
            }
            // Verify the request
            if (req.verify() == false) {
            	String msg = intres.getLocalizedMessage("signsession.popverificationfailed");
                throw new SignRequestSignatureException(msg);
            }
        } catch (IllegalCryptoTokenException e) {
            throw new IllegalKeyException(e);
        } catch (NoSuchProviderException e) {
            log.error("NoSuchProvider provider: ", e);
        } catch (InvalidKeyException e) {
            log.error("Invalid key in request: ", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("No such algorithm: ", e);
        }  catch (CryptoTokenOfflineException ctoe) {
        	String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getSubjectDN());
            log.error(msg, ctoe);
            throw ctoe;
        }
        if (log.isTraceEnabled()) {
        	log.trace("<decryptAndVerifyRequest(IRequestMessage)");
        }
        return req;
    }
    
    @Override
    public ResponseMessage getCRL(AuthenticationToken admin, RequestMessage req, Class responseClass) throws AuthStatusException, AuthLoginException, IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException, UnsupportedEncodingException, CryptoTokenOfflineException, AuthorizationDeniedException {
    	if (log.isTraceEnabled()) {
    		log.trace(">getCRL(IRequestMessage)");
    	}
        ResponseMessage ret = null;
        // Get CA that will receive request
        CA ca = getCAFromRequest(admin, req);
        try {
            CAToken catoken = ca.getCAToken();
            if (ca.getStatus() != SecConst.CA_ACTIVE) {
            	String msg = intres.getLocalizedMessage("signsession.canotactive", ca.getSubjectDN());
                throw new EJBException(msg);
            }
            // See if we need some key material to decrypt request
            if (req.requireKeyInfo()) {
                // You go figure...scep encrypts message with the public CA-cert
                req.setKeyInfo(ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getCryptoToken().getSignProviderName());
            }
            //Create the response message with all nonces and checks etc
            ret = req.createResponseMessage(responseClass, req, ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getCryptoToken().getSignProviderName());
            
            // Get the Full CRL, don't even bother digging into the encrypted CRLIssuerDN...since we already
            // know that we are the CA (SCEP is soooo stupid!)
            final String certSubjectDN = CertTools.getSubjectDN(ca.getCACertificate());
            byte[] crl = crlStoreSession.getLastCRL(certSubjectDN, false);
            if (crl != null) {
                ret.setCrl(CertTools.getCRLfromByteArray(crl));
                ret.setStatus(ResponseStatus.SUCCESS);
            } else {
                ret.setStatus(ResponseStatus.FAILURE);
                ret.setFailInfo(FailInfo.BAD_REQUEST);
            }
            ret.create();
            // TODO: handle returning errors as response message,
            // javax.ejb.ObjectNotFoundException and the others thrown...
        } catch (IllegalCryptoTokenException e) {
            throw new IllegalKeyException(e);
        } catch (NoSuchProviderException e) {
            log.error("NoSuchProvider provider: ", e);
        } catch (InvalidKeyException e) {
            log.error("Invalid key in request: ", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("No such algorithm: ", e);
        } catch (CRLException e) {
            log.error("Cannot create response message: ", e);
        } catch (IOException e) {
            log.error("Cannot create response message: ", e);
        } catch (CryptoTokenOfflineException ctoe) {
        	String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getSubjectDN());
        	log.error(msg, ctoe);
            throw ctoe;
        }
    	if (log.isTraceEnabled()) {
    		log.trace("<getCRL(IRequestMessage)");
    	}
        return ret;
    }
    
    /** Help Method that extracts the CA specified in the request. 
     * @throws AuthorizationDeniedException */
    private CA getCAFromRequest(AuthenticationToken admin, RequestMessage req) throws AuthStatusException, AuthLoginException, CADoesntExistsException, AuthorizationDeniedException {
        CA ca = null;
        try {
            // See if we can get issuerDN directly from request
            if (req.getIssuerDN() != null) {
                String dn = CertificateCreateSessionBean.getCADnFromRequest(req, certificateStoreSession);
            	try {
            		ca = caSession.getCA(admin, dn.hashCode());
            		if (log.isDebugEnabled()) {
            			log.debug("Using CA (from issuerDN) with id: " + ca.getCAId() + " and DN: " + ca.getSubjectDN());
            		}
            	} catch (CADoesntExistsException e) {
            		// We could not find a CA from that DN, so it might not be a CA. Try to get from username instead
            		if (req.getUsername() != null) {
            			ca = getCAFromUsername(admin, req);
                    	if (log.isDebugEnabled()) {
                    		log.debug("Using CA from username: "+req.getUsername());
                    	}
                    } else {
                        String msg = intres.getLocalizedMessage("signsession.canotfoundissuerusername", dn, "null");        	
                        throw new CADoesntExistsException(msg);
                    }
            	}
            } else if (req.getUsername() != null) {
                ca = getCAFromUsername(admin, req);
            	if (log.isDebugEnabled()) {
            		log.debug("Using CA from username: "+req.getUsername());
            	}
            } else {
                throw new CADoesntExistsException(intres.getLocalizedMessage("signsession.canotfoundissuerusername", req.getIssuerDN(), req.getUsername()));
            }
        } catch (ObjectNotFoundException e) {
            throw new CADoesntExistsException(intres.getLocalizedMessage("signsession.canotfoundissuerusername", req.getIssuerDN(), req.getUsername()));
		}
        
        if (ca.getStatus() != SecConst.CA_ACTIVE) {
        	String msg = intres.getLocalizedMessage("signsession.canotactive", ca.getSubjectDN());
        	throw new EJBException(msg);
        }
        return ca;
    }

	private CA getCAFromUsername(AuthenticationToken admin, RequestMessage req)
			throws ObjectNotFoundException, AuthStatusException, AuthLoginException, CADoesntExistsException, AuthorizationDeniedException {
		// See if we can get username and password directly from request
		String username = req.getUsername();
		String password = req.getPassword();
		EndEntityInformation data = authUser(admin, username, password);
		CA ca = caSession.getCA(admin, data.getCAId());
		if (log.isDebugEnabled()) {
			log.debug("Using CA (from username) with id: " + ca.getCAId() + " and DN: " + ca.getSubjectDN());
		}
		return ca;
	}

    private EndEntityInformation authUser(AuthenticationToken admin, String username, String password) throws ObjectNotFoundException, AuthStatusException, AuthLoginException {
    	// Authorize user and get DN
    	return authenticationSession.authenticateUser(admin, username, password);
    }

    /** Finishes user, i.e. set status to generated, if it should do so.
     * The authentication session is responsible for determining if this should be done or not */ 
	private void finishUser(CA ca, EndEntityInformation data) {
		if ( data==null ) {
			return;
		}
		if ( !ca.getCAInfo().getFinishUser()  ) {
			cleanUserCertDataSN(data);
			return;
		}
        try {
            authenticationSession.finishUser(data);
        } catch (ObjectNotFoundException e) {
            String msg = intres.getLocalizedMessage("signsession.finishnouser", data.getUsername());
        	log.info(msg);
        }
    }

	/**
	 * Clean the custom certificate serial number of user from database
	 * @param data of user
	 */
	private void cleanUserCertDataSN(EndEntityInformation data) {
		if ( data==null || data.getExtendedinformation()==null ||
				data.getExtendedinformation().certificateSerialNumber()==null ) {
			return;
		}
		try {
			userAdminSession.cleanUserCertDataSN(data);
		} catch (ObjectNotFoundException e) {
			String msg = intres.getLocalizedMessage("signsession.finishnouser", data.getUsername());
			log.info(msg);
		}
	}

    /**
     * Creates the certificate, uses the cesecore method with the same signature but in addition to that calls certreqsession and publishers
     * @throws CesecoreException 
     * @throws AuthorizationDeniedException 
     * @throws CertificateCreateException 
     * @throws IllegalKeyException 
     * @see org.cesecore.certificates.certificate.CertificateCreateSessionLocal#createCertificate(AuthenticationToken, EndEntityInformation, CA, X509Name, PublicKey, int, Date, Date, X509Extensions, String)
     */
    private Certificate createCertificate(AuthenticationToken admin, EndEntityInformation data, X509Name requestX509Name, CA ca, PublicKey pk, int keyusage, Date notBefore, Date notAfter, X509Extensions extensions, String sequence) throws IllegalKeyException, CertificateCreateException, AuthorizationDeniedException, CesecoreException {
    	if (log.isTraceEnabled()) {
    		log.trace(">createCertificate(pk, ku, notAfter)");
    	}

    	Certificate cert = certificateCreateSession.createCertificate(admin, data, ca, requestX509Name, pk, keyusage, notBefore, notAfter, extensions, sequence);

    	// Store the request data in history table.
    	if (ca.isUseCertReqHistory()) {
    		certreqHistorySession.addCertReqHistoryData(admin,cert,data);
    	}

    	// Store certificate in certificate profiles publishers.
    	// But check if the certificate was revoked directly on issuance, the revocation was then handled by CertificateCreateSession, but that session does not know about
    	// publishers to we need to manage it here with unfortunately a little duplicated code. We could just look up certificate info to see what the result was, but that
    	// would be very slow since it probably would cause an extra database lookup. Therefore we do it here similarly to what we do in CertificateCreateSession.
        final int certProfileId = data.getCertificateProfileId();
        CertificateProfile certProfile = certificateProfileSession.getCertificateProfile(certProfileId);
    	final Collection<Integer> publishers = certProfile.getPublisherList();
    	if (!publishers.isEmpty()) {
        	final String username = data.getUsername();
            final Certificate cacert = ca.getCACertificate();
            final String cafingerprint = CertTools.getFingerprintAsString(cacert);
            String tag = null;
    		final long updateTime = System.currentTimeMillis();
    		
            int revreason = RevokedCertInfo.NOT_REVOKED;
            long revocationDate = System.currentTimeMillis(); // This might not be in the millisecond exact, but it's rounded to seconds anyhow
            int certstatus = CertificateConstants.CERT_ACTIVE;
            ExtendedInformation ei = data.getExtendedinformation();
            if (ei != null) {
            	revreason = ei.getIssuanceRevocationReason();
            }
            publisherSession.storeCertificate(admin, publishers, cert, username, data.getPassword(), data.getDN(), cafingerprint, certstatus, certProfile.getType(), revocationDate, revreason, tag, certProfileId, updateTime, data.getExtendedinformation());
    	}
    	if (log.isTraceEnabled()) {
    		log.trace("<createCertificate(pk, ku, notAfter)");
    	}
    	return cert;
    }

}
