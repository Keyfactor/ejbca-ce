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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.ObjectNotFoundException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.cesecore.core.ejb.ca.crl.CrlSessionLocal;
import org.cesecore.core.ejb.ca.store.CertificateProfileSessionLocal;
import org.cesecore.core.ejb.log.LogSessionLocal;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ErrorCode;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.ca.auth.AuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CaSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionLocal;
import org.ejbca.core.ejb.ra.UserAdminSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ca.IllegalKeyException;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ca.SignRequestSignatureException;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.IllegalKeyStoreException;
import org.ejbca.core.model.ca.catoken.CATokenContainer;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.core.protocol.IRequestMessage;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.ResponseStatus;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.keystore.KeyTools;

/**
 * Creates and signs certificates.
 *
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "SignSessionRemote")
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
    private AuthenticationSessionLocal authenticationSession;
    @EJB
    private UserAdminSessionLocal userAdminSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private CrlSessionLocal crlSession;
    @EJB
    private LogSessionLocal logSession;

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /** Default create for SessionBean without any creation Arguments. */
	@PostConstruct
    public void ejbCreate() {
    	if (log.isTraceEnabled()) {
    		log.trace(">ejbCreate()");
    	}
        try {
            // Install BouncyCastle provider
        	CryptoProviderTools.installBCProvider();

            // Set up the serial number generator for Certificate Serial numbers
            // The serial number generator is a Singleton, so it can be initialized here and 
            // used by X509CA
            SernoGenerator.instance().setAlgorithm(EjbcaConfiguration.getRNGAlgorithm());
            SernoGenerator.instance().setSernoOctetSize(EjbcaConfiguration.getCaSerialNumberOctetSize());
            UniqueSernoHelper.testUniqueCertificateSerialNumberIndex(certificateStoreSession);
        } catch (Exception e) {
            log.debug("Caught exception in ejbCreate(): ", e);
            throw new EJBException(e);
        }
    	if (log.isTraceEnabled()) {
    		log.trace("<ejbCreate()");
    	}
    }

	@Override
    public boolean isUniqueCertificateSerialNumberIndex() {
    	return UniqueSernoHelper.isUniqueCertificateSerialNumberIndex();
    }

	@TransactionAttribute(TransactionAttributeType.SUPPORTS)
	@Override
    public Collection<Certificate> getCertificateChain(Admin admin, int caid) {
    	try {
    		return caSession.getCA(admin, caid).getCertificateChain();
    	} catch (CADoesntExistsException e) {
    		throw new EJBException(e);
    	}
    }

	@Override
    public byte[] createPKCS7(Admin admin, Certificate cert, boolean includeChain) throws CADoesntExistsException, SignRequestSignatureException {
        Integer caid = Integer.valueOf(CertTools.getIssuerDN(cert).hashCode());
        return createPKCS7(caid.intValue(), cert, includeChain);
    }

	@Override
    public byte[] createPKCS7(Admin admin, int caId, boolean includeChain) throws CADoesntExistsException {
        try {
            return createPKCS7(caId, null, includeChain);
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
     */
    private byte[] createPKCS7(int caId, Certificate cert, boolean includeChain) throws CADoesntExistsException, SignRequestSignatureException {
    	if (log.isTraceEnabled()) {
            log.trace(">createPKCS7(" + caId + ", " + CertTools.getIssuerDN(cert) + ")");
    	}
        CA ca = caSession.getCA(new Admin(Admin.TYPE_INTERNALUSER), caId);
        byte[] returnval = ca.createPKCS7(cert, includeChain);
    	if (log.isTraceEnabled()) {
    		log.trace("<createPKCS7()");
    	}
        return returnval;
    }

    @Override
    public Certificate createCertificate(Admin admin, String username, String password, PublicKey pk) throws EjbcaException, ObjectNotFoundException {
        // Default key usage is defined in certificate profiles
        return createCertificate(admin, username, password, pk, -1, null, null, SecConst.PROFILE_NO_PROFILE, SecConst.CAID_USEUSERDEFINED);
    }

    @Override
    public Certificate createCertificate(Admin admin, String username, String password, PublicKey pk, int keyusage, Date notBefore, Date notAfter) throws EjbcaException, ObjectNotFoundException {
        return createCertificate(admin, username, password, pk, keyusage, notBefore, notAfter, SecConst.PROFILE_NO_PROFILE, SecConst.CAID_USEUSERDEFINED);
    }

    @Override
    public Certificate createCertificate(Admin admin, String username, String password, Certificate incert) throws EjbcaException, ObjectNotFoundException {
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
    public IResponseMessage createCertificate(Admin admin, IRequestMessage req, Class responseClass, UserDataVO suppliedUserData) throws EjbcaException {
    	if (log.isTraceEnabled()) {
    		log.trace(">createCertificate(IRequestMessage)");
    	}
        // Get CA that will receive request
        UserDataVO data = null;
        IResponseMessage ret = null;
        CA ca;
        if (suppliedUserData == null) {
        	ca = getCAFromRequest(admin, req);
        } else {
        	ca = caSession.getCA(admin, suppliedUserData.getCAId()); // Take the CAId from the supplied userdata, if any
        }
        try {
            CATokenContainer catoken = ca.getCAToken();
            
            // See if we need some key material to decrypt request
            if (req.requireKeyInfo()) {
                // You go figure...scep encrypts message with the public CA-cert
                req.setKeyInfo(ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getJCEProvider());
            }
            // Verify the request
            if (req.verify() == false) {
            	String msg = intres.getLocalizedMessage("signsession.popverificationfailed");
            	logSession.log(admin, ca.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg);
                throw new SignRequestSignatureException(msg);
            }
            
            if (ca.isUseUserStorage() && req.getUsername() == null) {
            	String msg = intres.getLocalizedMessage("signsession.nouserinrequest", req.getRequestDN());
            	logSession.log(admin, ca.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg);
                throw new SignRequestException(msg);
                //ret.setFailInfo(FailInfo.BAD_REQUEST);
                //ret.setStatus(ResponseStatus.FAILURE);
            } else if (ca.isUseUserStorage() && req.getPassword() == null) {
            	String msg = intres.getLocalizedMessage("signsession.nopasswordinrequest");
                logSession.log(admin, ca.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg);
                throw new SignRequestException(msg);
            } else {        
            	ResponseStatus status = ResponseStatus.SUCCESS;
            	FailInfo failInfo = null;
            	String failText = null;
                Certificate cert = null;
            	try {
    				// If we haven't done so yet, authenticate user. (Only if we store UserData for this CA.)
            		if (ca.isUseUserStorage()) {
                		data = authUser(admin, req.getUsername(), req.getPassword());
            		} else {
            			data = suppliedUserData;
            		}
                    PublicKey reqpk = req.getRequestPublicKey();
                    if (reqpk == null) {
                        logSession.log(admin, ca.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, intres.getLocalizedMessage("signsession.nokeyinrequest"));
                        throw new InvalidKeyException("Key is null!");
                    }
                    // We need to make sure we use the users registered CA here
                    if (data.getCAId() != ca.getCAId()) {
                    	failText = intres.getLocalizedMessage("signsession.wrongauthority", Integer.valueOf(ca.getCAId()), Integer.valueOf(data.getCAId()));
                        status = ResponseStatus.FAILURE;
                        failInfo = FailInfo.WRONG_AUTHORITY;
                        logSession.log(admin, ca.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, failText);
                    }

                    if (status.equals(ResponseStatus.SUCCESS)) {
                    	Date notBefore = req.getRequestValidityNotBefore(); // Optionally requested validity
                    	Date notAfter = req.getRequestValidityNotAfter(); // Optionally requested validity
                    	X509Extensions exts = req.getRequestExtensions(); // Optionally requested extensions
                    	int keyusage = -1;
                    	if (exts != null) {
                        	if (log.isDebugEnabled()) {
                        		log.debug("we have extensions, see if we can override KeyUsage by looking for a KeyUsage extension in request");
                        	}
                    		X509Extension ext = exts.getExtension(X509Extensions.KeyUsage);
                    		if (ext != null) {
                    			ASN1OctetString os = ext.getValue();
                    			ByteArrayInputStream bIs = new ByteArrayInputStream(os.getOctets());
                    			ASN1InputStream dIs = new ASN1InputStream(bIs);
                    			DERObject dob = dIs.readObject();
                    			DERBitString bs = DERBitString.getInstance(dob);
                    			keyusage = bs.intValue();                        		                            		
                    			if (log.isDebugEnabled()) {
                    				log.debug("We have a key usage request extension: "+keyusage);
                    			}
                    		}
                    	}
    					String sequence = null;
    					byte[] ki = req.getRequestKeyInfo();
    					if ( (ki != null) && (ki.length > 0) ) {
        					sequence = new String(ki);    						
    					}
                    	cert = createCertificate(admin, data, req.getRequestX509Name(), ca, reqpk, keyusage, notBefore, notAfter, exts, sequence);
                    }
            	} catch (ObjectNotFoundException oe) {
            		// If we didn't find the entity return error message
            		log.error("User not found: ", oe);
                	failText = intres.getLocalizedMessage("signsession.nosuchuser", req.getUsername());
                    status = ResponseStatus.FAILURE;
                    failInfo = FailInfo.INCORRECT_DATA;
                    logSession.log(admin, ca.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, failText);
            	}
                
                //Create the response message with all nonces and checks etc
                ret = req.createResponseMessage(responseClass, req, ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getProvider());
				
				if ( (cert == null) && (status == ResponseStatus.SUCCESS) ) {
					status = ResponseStatus.FAILURE;
					failInfo = FailInfo.BAD_REQUEST;
                } else {
                    ret.setCertificate(cert);
                }
                ret.setStatus(status);
                if (failInfo != null) {
                    ret.setFailInfo(failInfo); 
                    ret.setFailText(failText);
                }
            }
            ret.create();
            // Call authentication session and tell that we are finished with this user. (Only if we store UserData for this CA.)
            if (ca.isUseUserStorage() && data!=null) {
        		finishUser(ca, data);
            }            	
        } catch (NoUniqueCertSerialNumberIndexException e) {
    		cleanUserCertDataSN(data);
            throw e.ejbcaException;
        } catch (IllegalKeyException ke) {
            log.error("Key is of unknown type: ", ke);
            throw ke;
        } catch (CATokenOfflineException ctoe) {
        	String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getSubjectDN());
        	CATokenOfflineException ex = new CATokenOfflineException(msg);
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
	public Certificate createCertificate(Admin admin, String username, String password, PublicKey pk, int keyusage, Date notBefore, Date notAfter, int certificateprofileid, int caid) throws EjbcaException, ObjectNotFoundException {
		if (log.isTraceEnabled()) {
			log.trace(">createCertificate(pk, ku, date)");
		}
	    // Authorize user and get DN
		final UserDataVO data = authUser(admin, username, password);
		if (log.isDebugEnabled()) {
			log.debug("Authorized user " + username + " with DN='" + data.getDN() + "'." + " with CA=" + data.getCAId());
		}
	    if (certificateprofileid != SecConst.PROFILE_NO_PROFILE) {
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
	    	logSession.log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg);
	    	throw new EJBException(msg);
	    }
	    Certificate cert;
	    try {
	    	// Now finally after all these checks, get the certificate, we don't have any sequence number or extensions available here
	    	cert = createCertificate(admin, data, null, ca, pk, keyusage, notBefore, notAfter, null, null);
	    	// Call authentication session and tell that we are finished with this user
			finishUser(ca, data);
	    } catch (NoUniqueCertSerialNumberIndexException e) {
	    	cleanUserCertDataSN(data);
	    	throw e.ejbcaException;
	    }
		if (log.isTraceEnabled()) {
			log.trace("<createCertificate(pk, ku, date)");
		}
	    return cert;
	}

    @Override
    public IResponseMessage createRequestFailedResponse(Admin admin, IRequestMessage req,  Class responseClass) throws  AuthLoginException, AuthStatusException, IllegalKeyException, CADoesntExistsException, SignRequestSignatureException, SignRequestException, CATokenOfflineException {
    	log.trace(">createRequestFailedResponse(IRequestMessage)");
        IResponseMessage ret = null;            
        CA ca = getCAFromRequest(admin, req);
        try {
            CATokenContainer catoken = ca.getCAToken();
            // See if we need some key material to decrypt request
            if (req.requireKeyInfo()) {
                // You go figure...scep encrypts message with the public CA-cert
                req.setKeyInfo(ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getProvider());
            }
            // Verify the request
            if (req.verify() == false) {
            	String msg = intres.getLocalizedMessage("signsession.popverificationfailed");
            	logSession.log(admin, ca.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, intres.getLocalizedMessage("signsession.popverificationfailed"));
                throw new SignRequestSignatureException(msg);
            }
            //Create the response message with all nonces and checks etc
            ret = req.createResponseMessage(responseClass, req, ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getProvider());
            ret.setStatus(ResponseStatus.FAILURE);
            ret.setFailInfo(FailInfo.BAD_REQUEST);
            ret.create();
        } catch (IllegalKeyStoreException e) {
            throw new IllegalKeyException(e);
        } catch (NotFoundException e) {
        	// This can actually not happen here?
            throw new CADoesntExistsException(e);
        } catch (NoSuchProviderException e) {
            log.error("NoSuchProvider provider: ", e);
        } catch (InvalidKeyException e) {
            log.error("Invalid key in request: ", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("No such algorithm: ", e);
        } catch (IOException e) {
            log.error("Cannot create response message: ", e);
        } catch (CATokenOfflineException ctoe) {
        	String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getSubjectDN());
            log.warn(msg, ctoe);
            logSession.log(admin, ca.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg, ctoe);
            throw ctoe;
        }
        log.trace("<createRequestFailedResponse(IRequestMessage)");
        return ret;
    }

    @Override
    public IRequestMessage decryptAndVerifyRequest(Admin admin, IRequestMessage req) throws ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException {
    	log.trace(">decryptAndVerifyRequest(IRequestMessage)");
        // Get CA that will receive request
        CA ca = getCAFromRequest(admin, req);
        try {
            CATokenContainer catoken = ca.getCAToken();
            // See if we need some key material to decrypt request
            if (req.requireKeyInfo()) {
                // You go figure...scep encrypts message with the public CA-cert
                req.setKeyInfo(ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getProvider());
            }
            // Verify the request
            if (req.verify() == false) {
            	String msg = intres.getLocalizedMessage("signsession.popverificationfailed");
            	logSession.log(admin, ca.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), req.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg);
                throw new SignRequestSignatureException(msg);
            }
        } catch (IllegalKeyStoreException e) {
            throw new IllegalKeyException(e);
        } catch (NoSuchProviderException e) {
            log.error("NoSuchProvider provider: ", e);
        } catch (InvalidKeyException e) {
            log.error("Invalid key in request: ", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("No such algorithm: ", e);
        }  catch (CATokenOfflineException ctoe) {
        	String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getSubjectDN());
            log.error(msg, ctoe);
            logSession.log(admin, ca.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg, ctoe);
            throw new CADoesntExistsException(msg);
        }
        log.trace("<decryptAndVerifyRequest(IRequestMessage)");
        return req;
    }
    
    @Override
    public IResponseMessage getCRL(Admin admin, IRequestMessage req, Class responseClass) throws AuthStatusException, AuthLoginException, IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException, UnsupportedEncodingException {
        log.trace(">getCRL(IRequestMessage)");
        IResponseMessage ret = null;
        // Get CA that will receive request
        CA ca = getCAFromRequest(admin, req);
        try {
            CATokenContainer catoken = ca.getCAToken();
            if (ca.getStatus() != SecConst.CA_ACTIVE) {
            	String msg = intres.getLocalizedMessage("signsession.canotactive", ca.getSubjectDN());
            	logSession.log(admin, ca.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_GETLASTCRL, msg);
                throw new EJBException(msg);
            }
            // See if we need some key material to decrypt request
            if (req.requireKeyInfo()) {
                // You go figure...scep encrypts message with the public CA-cert
                req.setKeyInfo(ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getProvider());
            }
            //Create the response message with all nonces and checks etc
            ret = req.createResponseMessage(responseClass, req, ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getProvider());
            
            // Get the Full CRL, don't even bother digging into the encrypted CRLIssuerDN...since we already
            // know that we are the CA (SCEP is soooo stupid!)
            final String certSubjectDN = CertTools.getSubjectDN(ca.getCACertificate());
            byte[] crl = crlSession.getLastCRL(admin, certSubjectDN, false);
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
        } catch (NotFoundException e) {
        	// This actually can not happen here
            throw new CADoesntExistsException(e);
        } catch (IllegalKeyStoreException e) {
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
        } catch (CATokenOfflineException ctoe) {
        	String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getSubjectDN());
        	log.error(msg, ctoe);
            logSession.log(admin, ca.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_GETLASTCRL, msg, ctoe);
            throw new CADoesntExistsException(msg);
        }
        log.trace("<getCRL(IRequestMessage)");
        return ret;
    }
    
    /** Help Method that extracts the CA specified in the request. */
    private CA getCAFromRequest(Admin admin, IRequestMessage req) throws AuthStatusException, AuthLoginException, CADoesntExistsException {
        CA ca = null;
        try {
            // See if we can get issuerDN directly from request
            if (req.getIssuerDN() != null) {
            	String dn = req.getIssuerDN();
            	if (log.isDebugEnabled()) {
            		log.debug("Got an issuerDN: "+dn);
            	}
            	// If we have issuer and serialNo, we must find the CA certificate, to get the CAs subject name
            	// If we don't have a serialNumber, we take a chance that it was actually the subjectDN (for example a RootCA)
            	BigInteger serno = req.getSerialNo();
            	if (serno != null) {
            		if (log.isDebugEnabled()) {
            			log.debug("Got a serialNumber: "+serno.toString(16));
            		}
                   
            		Certificate cert = certificateStoreSession.findCertificateByIssuerAndSerno(admin, dn, serno);
            		if (cert != null) {
            			dn = CertTools.getSubjectDN(cert);
            		}
            	}
            	if (log.isDebugEnabled()) {
            		log.debug("Using DN: "+dn);
            	}
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
        	logSession.log(admin, ca.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg);
        	throw new EJBException(msg);
        }
        return ca;
    }

	private CA getCAFromUsername(Admin admin, IRequestMessage req)
			throws ObjectNotFoundException, AuthStatusException, AuthLoginException, CADoesntExistsException {
		// See if we can get username and password directly from request
		String username = req.getUsername();
		String password = req.getPassword();
		UserDataVO data = authUser(admin, username, password);
		CA ca = caSession.getCA(admin, data.getCAId());
		if (log.isDebugEnabled()) {
			log.debug("Using CA (from username) with id: " + ca.getCAId() + " and DN: " + ca.getSubjectDN());
		}
		return ca;
	}

    private UserDataVO authUser(Admin admin, String username, String password) throws ObjectNotFoundException, AuthStatusException, AuthLoginException {
    	// Authorize user and get DN
    	return authenticationSession.authenticateUser(admin, username, password);
    }

    /** Finishes user, i.e. set status to generated, if it should do so.
     * The authentication session is responsible for determining if this should be done or not */ 
	private void finishUser(CA ca, UserDataVO data) {
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
	private void cleanUserCertDataSN(UserDataVO data) {
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

    private String listUsers(Set<String> users) {
        Iterator<String> i = users.iterator();
        String s = "";
        while ( i.hasNext() ) {
        	if (s.length()>0 ) {
        		s += " ";
        	}
            s += "'"+i.next()+"'";
        }
        return s;
    }

    /** Private exception used in order to catch this specific error to be able to clear the custom certificate serial number from the user object.
     * This is only used internally in this class. 
     */
    private class NoUniqueCertSerialNumberIndexException extends Exception {
		private static final long serialVersionUID = 1L;
		final EjbcaException ejbcaException;
    	public NoUniqueCertSerialNumberIndexException( EjbcaException e ) {
    		this.ejbcaException = e;
    	}
    }

    /**
     * Creates the certificate, does NOT check any authorization on user, profiles or CA!
     * This must be done earlier
     *
     * @param admin    administrator performing this task
     * @param data     auth data for user to get the certificate
     * @param ca       the CA that will sign the certificate
     * @param pk       the users public key to be put in the certificate
     * @param keyusage requested key usage for the certificate, may be ignored by the CA
     * @param notBefore an optional validity to set in the created certificate, if the profile allows validity override, null if the profiles default validity should be used.
     * @param notAfter an optional validity to set in the created certificate, if the profile allows validity override, null if the profiles default validity should be used.
     * @param extensions an optional set of extensions to set in the created certificate, if the profile allows extension override, null if the profile default extensions should be used.
     * @param sequence an optional requested sequence number (serial number) for the certificate, may or may not be used by the CA. Currently used by CVC CAs for sequence field. Can be set to null.
     * @return Certificate that has been generated and signed by the CA
	 * @throws NoUniqueCertSerialNumberIndexException if custom serial number is registered for user, but it is not allowed to be used (either missing unique index in database, or certifciate profile does not allow it
     * @throws EjbcaException if the public key given is invalid
     */
    private Certificate createCertificate(Admin admin, UserDataVO data, X509Name requestX509Name, CA ca, PublicKey pk, int keyusage, Date notBefore, Date notAfter, X509Extensions extensions, String sequence) throws NoUniqueCertSerialNumberIndexException, EjbcaException {
    	if (log.isTraceEnabled()) {
    		log.trace(">createCertificate(pk, ku, notAfter)");
    	}
        try {
            logSession.log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), data.getUsername(), null, LogConstants.EVENT_INFO_REQUESTCERTIFICATE, intres.getLocalizedMessage("signsession.requestcert", data.getUsername(), Integer.valueOf(data.getCAId()), Integer.valueOf(data.getCertificateProfileId())));
            // If the user is of type USER_INVALID, it cannot have any other type (in the mask)
            if (data.getType() == SecConst.USER_INVALID) {
            	String msg = intres.getLocalizedMessage("signsession.usertypeinvalid", data.getUsername());
            	logSession.log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), data.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg);
            	if (log.isTraceEnabled()) {
            		log.trace("<createCertificate(pk, ku, notAfter)");
            	}
                throw new EJBException(msg);
            }
            final Certificate cacert = ca.getCACertificate();
            final String caSubjectDN = CertTools.getSubjectDN(cacert);
            if ( ca.isDoEnforceUniqueDistinguishedName() ){
            	if (ca.isUseCertificateStorage()) {
            		final Set<String> users = certificateStoreSession.findUsernamesByIssuerDNAndSubjectDN(admin, caSubjectDN, data.getDN());
            		if ( users.size()>0 && !users.contains(data.getUsername()) ) {
            			String msg = intres.getLocalizedMessage("signsession.subjectdn_exists_for_another_user", "'"+data.getUsername()+"'", listUsers(users));
            			log.info(msg);
            			throw new EjbcaException(ErrorCode.CERTIFICATE_WITH_THIS_SUBJECTDN_ALLREADY_EXISTS_FOR_ANOTHER_USER, msg);
            		}
            	} else {
            		log.warn("CA configured to enforce unique SubjectDN, but not to store issued certificates. Check will be ignored. Please verify your configuration.");
            	}
            }
            if ( ca.isDoEnforceUniquePublicKeys() ){
            	if (ca.isUseCertificateStorage()) {
            		final Set<String> users = certificateStoreSession.findUsernamesByIssuerDNAndSubjectKeyId(admin, caSubjectDN, KeyTools.createSubjectKeyId(pk).getKeyIdentifier());
            		if ( users.size()>0 && !users.contains(data.getUsername()) ) {
            			String msg = intres.getLocalizedMessage("signsession.key_exists_for_another_user", "'"+data.getUsername()+"'", listUsers(users));
            			log.info(msg);
            			throw new EjbcaException(ErrorCode.CERTIFICATE_FOR_THIS_KEY_ALLREADY_EXISTS_FOR_ANOTHER_USER, msg);
            		}
            	} else {
            		log.warn("CA configured to enforce unique entity keys, but not to store issued certificates. Check will be ignored. Please verify your configuration.");
            	}
            }
            // Retrieve the certificate profile this user should have
			final int certProfileId;
			final CertificateProfile certProfile;
			{
				final int tmpCertProfileId = data.getCertificateProfileId();
				final CertificateProfile tmpCertProfile = certificateProfileSession.getCertificateProfile(admin, tmpCertProfileId);
				// What if certProfile == null?
				if (tmpCertProfile != null) {
					certProfileId = tmpCertProfileId;
					certProfile = tmpCertProfile;
				} else {
					certProfileId = SecConst.CERTPROFILE_FIXED_ENDUSER;
					certProfile = certificateProfileSession.getCertificateProfile(admin, certProfileId);
				}
			}
        	if (log.isDebugEnabled()) {
        		log.debug("Using certificate profile with id " + certProfileId);
        	}

            // Check that CAid is among available CAs
            boolean caauthorized = false;
            Iterator<Integer> iter = certProfile.getAvailableCAs().iterator();
            while (iter.hasNext()) {
                int next = iter.next().intValue();
                if (next == data.getCAId() || next == CertificateProfile.ANYCA) {
                    caauthorized = true;
                }
            }
            if (!caauthorized) {
                String msg = intres.getLocalizedMessage("signsession.errorcertprofilenotauthorized", Integer.valueOf(data.getCAId()), Integer.valueOf(certProfile.getType()));
                logSession.log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), data.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg);
                throw new EJBException(msg);
            }

            // Sign Session bean is only able to issue certificates with a End Entity or SubCA type certificate profile.
            if ( (certProfile.getType() != CertificateProfile.TYPE_ENDENTITY) && (certProfile.getType() != CertificateProfile.TYPE_SUBCA) ) {
                String msg = intres.getLocalizedMessage("signsession.errorcertprofiletype", Integer.valueOf(certProfile.getType()));
                logSession.log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), data.getUsername(), null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg);
                throw new EJBException(msg);
            }

            int keyLength = KeyTools.getKeyLength(pk);
        	if (log.isDebugEnabled()) {
        		log.debug("Keylength = " + keyLength);
        	}
            if (keyLength == -1) {
                String text = intres.getLocalizedMessage("signsession.unsupportedkeytype", pk.getClass().getName()); 
                logSession.log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), data.getUsername(), null, LogConstants.EVENT_INFO_CREATECERTIFICATE, text);
                throw new IllegalKeyException(text);
            }
            if ((keyLength < (certProfile.getMinimumAvailableBitLength() - 1))
                    || (keyLength > (certProfile.getMaximumAvailableBitLength()))) {
                String text = intres.getLocalizedMessage("signsession.illegalkeylength", Integer.valueOf(keyLength)); 
                logSession.log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), data.getUsername(), null, LogConstants.EVENT_INFO_CREATECERTIFICATE, text);
                throw new IllegalKeyException(text);
            }

            // Below we have a small loop if it would happen that we generate the same serial number twice
			Exception storeEx = null; // this will not be null if stored == false after the below passage
            Certificate cert = null;
            String cafingerprint = null;
            String serialNo = "unknown";
			final long updateTime = new Date().getTime();
            String tag = null;
			final boolean useCustomSN;
			{
				final ExtendedInformation ei = data.getExtendedinformation();
				useCustomSN = ei!=null && ei.certificateSerialNumber()!=null;
			}
			final int maxRetrys;
			if ( useCustomSN ) {
				if (ca.isUseCertificateStorage() && !isUniqueCertificateSerialNumberIndex()) {
					final String msg = intres.getLocalizedMessage("signsession.not_unique_certserialnumberindex");
					log.error(msg);
					throw new NoUniqueCertSerialNumberIndexException(new EjbcaException(msg));
				}
				if ( !certProfile.getAllowCertSerialNumberOverride() ) {
					final String msg = intres.getLocalizedMessage("signsession.certprof_not_allowing_cert_sn_override", Integer.valueOf(certProfileId));
					log.info(msg);
					throw new NoUniqueCertSerialNumberIndexException(new EjbcaException(msg));
				}
				maxRetrys = 1;
			} else {
				maxRetrys = 5;
			}
            for ( int retrycounter=0; retrycounter<maxRetrys; retrycounter++ ) {
                cert = ca.generateCertificate(data, requestX509Name, pk, keyusage, notBefore, notAfter, certProfile, extensions, sequence);
                serialNo = CertTools.getSerialNumberAsString(cert);
                cafingerprint = CertTools.getFingerprintAsString(cacert);
                // Store certificate in the database, if this CA is configured to do so.
                if (!ca.isUseCertificateStorage()) {
                	break;  // We have our cert and we don't need to store it.. Move on..
                }
                try {
                    certificateStoreSession.storeCertificate(admin, cert, data.getUsername(), cafingerprint, SecConst.CERT_ACTIVE, certProfile.getType(), certProfileId, tag, updateTime);                        
					storeEx = null;
					break;
                } catch (Exception e) {
                    // If we have created a unique index on (issuerDN,serialNumber) on table CertificateData we can 
                    // get a CreateException here if we would happen to generate a certificate with the same serialNumber
                    // as one already existing certificate.
					if ( retrycounter+1<maxRetrys ) {
						log.info("Can not store certificate with serNo ("+serialNo+"), will retry (retrycounter="+retrycounter+") with a new certificate with new serialNo: "+e.getMessage());
					}
                    storeEx = e;
                }
            }
			if ( storeEx!=null ) {
				if ( useCustomSN ) {
					final String msg = intres.getLocalizedMessage("signsession.cert_serial_number_allready_in_database", serialNo);
					log.info(msg);
					throw new NoUniqueCertSerialNumberIndexException(new EjbcaException(msg));
				}
				log.error("Can not store certificate in database in 5 tries, aborting: ", storeEx);
				throw storeEx;
			}

            logSession.log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), data.getUsername(), cert, LogConstants.EVENT_INFO_CREATECERTIFICATE, intres.getLocalizedMessage("signsession.certificateissued", data.getUsername()));
            if (log.isDebugEnabled()) {
                log.debug("Generated certificate with SerialNumber '" + serialNo + "' for user '" + data.getUsername() + "'.");
                log.debug(cert.toString());                	
            }

            // Store the request data in history table.
            if (ca.isUseCertReqHistory()) {
                certificateStoreSession.addCertReqHistoryData(admin,cert,data);
            }
            // Store certificate in certificate profiles publishers.
            Collection<Integer> publishers = certProfile.getPublisherList();
            if (publishers != null) {
                publisherSession.storeCertificate(admin, publishers, cert, data.getUsername(), data.getPassword(), data.getDN(), cafingerprint, SecConst.CERT_ACTIVE, certProfile.getType(), -1, RevokedCertInfo.NOT_REVOKED, tag, certProfileId, updateTime, data.getExtendedinformation());
            }
            // Finally we check if this certificate should not be issued as active, but revoked directly upon issuance 
            int revreason = getIssuanceRevocationReason(data);
            if (revreason != RevokedCertInfo.NOT_REVOKED) {
            	// If we don't store the certificate in the database, we wont support revocation/reactivation so issuing revoked certificates would be really strange. 
            	if (ca.isUseCertificateStorage()) {
                    certificateStoreSession.revokeCertificate(admin, cert, publishers, revreason, data.getDN());
            	} else {
            		log.warn("CA configured to revoke issued certificates directly, but not to store issued the certificates. Revocation will be ignored. Please verify your configuration.");
            	}
            }                
        	if (log.isTraceEnabled()) {
        		log.trace("<createCertificate(pk, ku, notAfter)");
        	}
            return cert;
        } catch (CATokenOfflineException ctoe) {
        	String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getSubjectDN());
            logSession.log(admin, ca.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg, ctoe);
            throw ctoe;
        } catch (EjbcaException ke) {
            throw ke;
        } catch( NoUniqueCertSerialNumberIndexException e ) {
        	throw e;
        } catch (Exception e) {
            log.error(e);
            throw new EJBException(e);
        }
    }

    /**
     * Returns the issuance revocation code configured on the end entity extended information.
     *
     * @param data user data
     * @return issuance revocation code configured on the end entity extended information, a constant from RevokedCertInfo. Default RevokedCertInfo.NOT_REVOKED. 
     */
    private int getIssuanceRevocationReason(UserDataVO data) {
    	int ret = RevokedCertInfo.NOT_REVOKED;
    	ExtendedInformation ei = data.getExtendedinformation();
        if ( ei != null ) {
            String revocationReason = ei.getCustomData(ExtendedInformation.CUSTOM_REVOCATIONREASON);
            if (revocationReason != null) {
                ret = Integer.valueOf(revocationReason);            	
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("User revocation reason: "+ret);        	
        }
        return ret;
    }
}
