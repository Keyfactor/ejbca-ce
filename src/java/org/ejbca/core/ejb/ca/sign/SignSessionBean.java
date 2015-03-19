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

package org.ejbca.core.ejb.ca.sign;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.ObjectNotFoundException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.Extensions;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.CertificateGenerationParams;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateCreateSessionLocal;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.ResponseMessageUtils;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.certificatetransparency.CTLogInfo;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.store.CertReqHistorySessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;

/**
 * Creates and signs certificates.
 *
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "SignSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class SignSessionBean implements SignSessionLocal, SignSessionRemote {

    private static final Logger log = Logger.getLogger(SignSessionBean.class);

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

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
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private EndEntityAuthenticationSessionLocal endEntityAuthenticationSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private CrlStoreSessionLocal crlStoreSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

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
    public byte[] createPKCS7(AuthenticationToken admin, Certificate cert, boolean includeChain) throws CADoesntExistsException,
            SignRequestSignatureException, AuthorizationDeniedException {
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
     * @throws AuthorizationDeniedException if the authentication token wasn't authorized to the CA
     * @throws SignRequestSignatureException if the certificate wasn't issued by the CA defined by caid
     */
    private byte[] createPKCS7(AuthenticationToken admin, int caId, Certificate cert, boolean includeChain) throws CADoesntExistsException,
            SignRequestSignatureException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">createPKCS7(" + caId + ", " + CertTools.getIssuerDN(cert) + ")");
        }
        CA ca = caSession.getCA(admin, caId);
        final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
        byte[] returnval = ca.createPKCS7(cryptoToken, cert, includeChain);
        if (log.isTraceEnabled()) {
            log.trace("<createPKCS7()");
        }
        return returnval;
    }

    @Override
    public Certificate createCertificate(final AuthenticationToken admin, final String username, final String password, final PublicKey pk)
            throws ObjectNotFoundException, AuthorizationDeniedException, CADoesntExistsException, AuthStatusException, AuthLoginException,
            IllegalKeyException, CertificateCreateException, IllegalNameException, CertificateRevokeException, CertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            CustomCertificateSerialNumberException {
        // Default key usage is defined in certificate profiles
        return createCertificate(admin, username, password, pk, -1, null, null, CertificateProfileConstants.CERTPROFILE_NO_PROFILE,
                SecConst.CAID_USEUSERDEFINED);
    }
    
    @Override
    public Certificate createCertificate(AuthenticationToken admin, String username, String password, PublicKeyWrapper pk)
            throws ObjectNotFoundException, CADoesntExistsException, AuthorizationDeniedException, IllegalKeyException, CertificateCreateException,
            IllegalNameException, CertificateRevokeException, CertificateSerialNumberException, CryptoTokenOfflineException,
            IllegalValidityException, CAOfflineException, InvalidAlgorithmException, CustomCertificateSerialNumberException, AuthStatusException,
            AuthLoginException {
        return createCertificate(admin, username, password, pk.getPublicKey());
    }

    @Override
    public Certificate createCertificate(final AuthenticationToken admin, final String username, final String password, final PublicKey pk,
            final int keyusage, final Date notBefore, final Date notAfter) throws ObjectNotFoundException, AuthorizationDeniedException,
            CADoesntExistsException, AuthStatusException, AuthLoginException, IllegalKeyException, CertificateCreateException, IllegalNameException,
            CertificateRevokeException, CertificateSerialNumberException, CryptoTokenOfflineException, IllegalValidityException, CAOfflineException,
            InvalidAlgorithmException, CustomCertificateSerialNumberException {
        return createCertificate(admin, username, password, pk, keyusage, notBefore, notAfter, CertificateProfileConstants.CERTPROFILE_NO_PROFILE,
                SecConst.CAID_USEUSERDEFINED);
    }
    
    @Override
    public Certificate createCertificate(final AuthenticationToken admin, final String username, final String password, final PublicKeyWrapper pk,
            final int keyusage, final Date notBefore, final Date notAfter) throws ObjectNotFoundException, AuthorizationDeniedException,
            CADoesntExistsException, AuthStatusException, AuthLoginException, IllegalKeyException, CertificateCreateException, IllegalNameException,
            CertificateRevokeException, CertificateSerialNumberException, CryptoTokenOfflineException, IllegalValidityException, CAOfflineException,
            InvalidAlgorithmException, CustomCertificateSerialNumberException {
        return createCertificate(admin, username, password, pk.getPublicKey(), keyusage, notBefore, notAfter, CertificateProfileConstants.CERTPROFILE_NO_PROFILE,
                SecConst.CAID_USEUSERDEFINED);
    }

    @Override
    public Certificate createCertificate(final AuthenticationToken admin, final String username, final String password, final Certificate incert)
            throws ObjectNotFoundException, AuthorizationDeniedException, SignRequestSignatureException, CADoesntExistsException,
            AuthStatusException, AuthLoginException, IllegalKeyException, CertificateCreateException, IllegalNameException,
            CertificateRevokeException, CertificateSerialNumberException, CryptoTokenOfflineException, IllegalValidityException, CAOfflineException,
            InvalidAlgorithmException, CustomCertificateSerialNumberException {

        // Convert the certificate to a BC certificate. SUN does not handle verifying RSASha256WithMGF1 for example 
            Certificate bccert;
            try {
                bccert = CertTools.getCertfromByteArray(incert.getEncoded());
                bccert.verify(incert.getPublicKey());
            } catch (CertificateParsingException e) {
                log.debug("CertificateParsingException verify POPO: ", e);
                final String msg = intres.getLocalizedMessage("createcert.popverificationfailed");
                throw new SignRequestSignatureException(msg, e);
            } catch (CertificateEncodingException e) {
                log.debug("CertificateEncodingException verify POPO: ", e);
                final String msg = intres.getLocalizedMessage("createcert.popverificationfailed");
                throw new SignRequestSignatureException(msg);
            } catch (InvalidKeyException e) {
                log.debug("InvalidKeyException verify POPO: ", e);
                final String msg = intres.getLocalizedMessage("createcert.popverificationfailed");
                throw new SignRequestSignatureException(msg, e);
            } catch (CertificateException e) {
                log.debug("CertificateException verify POPO: ", e);
                final String msg = intres.getLocalizedMessage("createcert.popverificationfailed");
                throw new SignRequestSignatureException(msg, e);
            } catch (NoSuchAlgorithmException e) {
                log.debug("NoSuchAlgorithmException verify POPO: ", e);
                final String msg = intres.getLocalizedMessage("createcert.popverificationfailed");
                throw new SignRequestSignatureException(msg, e);
            } catch (NoSuchProviderException e) {
                log.debug("NoSuchProviderException verify POPO: ", e);
                final String msg = intres.getLocalizedMessage("createcert.popverificationfailed");
                throw new SignRequestSignatureException(msg, e);
            } catch (SignatureException e) {
                log.debug("SignatureException verify POPO: ", e);
                final String msg = intres.getLocalizedMessage("createcert.popverificationfailed");
                throw new SignRequestSignatureException(msg, e);
            }
           
        return createCertificate(admin, username, password, incert.getPublicKey(),
                CertTools.sunKeyUsageToBC(((X509Certificate) incert).getKeyUsage()), null, null);
    }
    
    @Override
    public ResponseMessage createCertificateIgnoreStatus(final AuthenticationToken admin, final RequestMessage req,
            Class<? extends CertificateResponseMessage> responseClass) throws AuthorizationDeniedException, NoSuchEndEntityException,
            CertificateCreateException, CertificateRevokeException, InvalidAlgorithmException, ApprovalException, WaitingForApprovalException {
        final String username = req.getUsername();
        EndEntityInformation retrievedUser = endEntityAccessSession.findUser(admin, username);
        if (retrievedUser.getStatus() == EndEntityConstants.STATUS_GENERATED) {
            try {
                endEntityManagementSession.setUserStatus(admin, username, EndEntityConstants.STATUS_NEW);
            } catch (FinderException e) {
                throw new NoSuchEndEntityException("End entity with username " + username + " not found.", e);
            }
        }
        try {
            return createCertificate(admin, req, responseClass, null);
        } catch (CryptoTokenOfflineException e) {
            throw new CertificateCreateException("Error during certificate creation, rolling back.", e);
        } catch (IllegalKeyException e) {
            throw new CertificateCreateException("Error during certificate creation, rolling back.", e);
        } catch (CADoesntExistsException e) {
            throw new CertificateCreateException("Error during certificate creation, rolling back.", e);
        } catch (SignRequestException e) {
            throw new CertificateCreateException("Error during certificate creation, rolling back.", e);
        } catch (SignRequestSignatureException e) {
            throw new CertificateCreateException("Error during certificate creation, rolling back.", e);
        } catch (AuthStatusException e) {
            throw new CertificateCreateException("Error during certificate creation, rolling back.", e);
        } catch (AuthLoginException e) {
            throw new CertificateCreateException("Error during certificate creation, rolling back.", e);
        } catch (CertificateExtensionException e) {
            throw new CertificateCreateException("Error during certificate creation, rolling back.", e);
        } catch (CustomCertificateSerialNumberException e) {
            throw new CertificateCreateException("Error during certificate creation, rolling back.", e);
        } catch (IllegalNameException e) {
            throw new CertificateCreateException("Error during certificate creation, rolling back.", e);
        } catch (CertificateSerialNumberException e) {
            throw new CertificateCreateException("Error during certificate creation, rolling back.", e);
        } catch (IllegalValidityException e) {
            throw new CertificateCreateException("Error during certificate creation, rolling back.", e);
        } catch (CAOfflineException e) {
            throw new CertificateCreateException("Error during certificate creation, rolling back.", e);
        }

    }


    @Override
    public ResponseMessage createCertificate(final AuthenticationToken admin, final RequestMessage req,
            Class<? extends CertificateResponseMessage> responseClass, final EndEntityInformation suppliedUserData) throws AuthorizationDeniedException,
            CertificateExtensionException, NoSuchEndEntityException, CustomCertificateSerialNumberException, CryptoTokenOfflineException,
            IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException, AuthStatusException,
            AuthLoginException, IllegalNameException, CertificateCreateException, CertificateRevokeException, CertificateSerialNumberException,
            IllegalValidityException, CAOfflineException, InvalidAlgorithmException {
        if (log.isTraceEnabled()) {
            log.trace(">createCertificate(RequestMessage)");
        }
        // Get CA that will receive request
        EndEntityInformation data = null;
        CertificateResponseMessage ret = null;
        // Get CA object and make sure it is active
        // Do not log access control to the CA here, that is logged later on when we use the CA to issue a certificate (if we get that far).
        final CA ca;
        if (suppliedUserData == null) {
            ca = getCAFromRequest(admin, req, false);
        } else {
            ca = caSession.getCANoLog(admin, suppliedUserData.getCAId()); // Take the CAId from the supplied userdata, if any
        }
        if (ca.getStatus() != CAConstants.CA_ACTIVE) {
            final String msg = intres.getLocalizedMessage("signsession.canotactive", ca.getSubjectDN());
            throw new EJBException(msg);
        }
        try {
            // See if we need some key material to decrypt request
            final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
            decryptAndVerify(cryptoToken, req, ca);
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
                        final String failText = intres.getLocalizedMessage("signsession.wrongauthority", Integer.valueOf(ca.getCAId()),
                                Integer.valueOf(data.getCAId()));
                        log.info(failText);
                        ret = createRequestFailedResponse(admin, req, responseClass, FailInfo.WRONG_AUTHORITY, failText);
                    } else {
                        final long updateTime = System.currentTimeMillis();
                        // Issue the certificate from the request
                        ret = certificateCreateSession.createCertificate(admin, data, ca, req, responseClass, fetchCertGenParams(), updateTime);
                        postCreateCertificate(admin, data, ca, new CertificateDataWrapper(ret.getCertificate(), ret.getCertificateData(), ret.getBase64CertData()), updateTime);
                    }
                } catch (ObjectNotFoundException e) {
                    // If we didn't find the entity return error message
                    final String failText = intres.getLocalizedMessage("signsession.nosuchuser", req.getUsername());
                    log.info(failText, e);
                    throw new NoSuchEndEntityException(failText, e);
                }
            }
            ret.create();
            // Call authentication session and tell that we are finished with this user. (Only if we store UserData for this CA.)
            if (ca.isUseUserStorage() && data != null) {
                finishUser(ca, data);
            }
        } catch (CustomCertificateSerialNumberException e) {
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
        } catch (NoSuchProviderException e) {
            log.error("NoSuchProvider provider: ", e);
        } catch (InvalidKeyException e) {
            log.error("Invalid key in request: ", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("No such algorithm: ", e);
        } catch (CertificateEncodingException e) {
           log.error("There was a problem extracting the certificate information.", e);
        } catch (CRLException e) {
            log.error("There was a problem extracting the CRL information.", e);
        } 
        if (log.isTraceEnabled()) {
            log.trace("<createCertificate(IRequestMessage)");
        }
        return ret;
    }
    
    @Override
    public Certificate createCertificate(final AuthenticationToken admin, final String username, final String password, final PublicKeyWrapper pk,
            final int keyusage, final Date notBefore, final Date notAfter, final int certificateprofileid, final int caid)
            throws ObjectNotFoundException, CADoesntExistsException, AuthorizationDeniedException, AuthStatusException, AuthLoginException,
            IllegalKeyException, CertificateCreateException, IllegalNameException, CertificateRevokeException, CertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException, CustomCertificateSerialNumberException {
            return createCertificate(admin, username, password, pk.getPublicKey(), keyusage, notBefore, notAfter, certificateprofileid, caid);
    }

    @Override
    public Certificate createCertificate(final AuthenticationToken admin, final String username, final String password, final PublicKey pk,
            final int keyusage, final Date notBefore, final Date notAfter, final int certificateprofileid, final int caid)
            throws ObjectNotFoundException, CADoesntExistsException, AuthorizationDeniedException, AuthStatusException, AuthLoginException,
            IllegalKeyException, CertificateCreateException, IllegalNameException, CertificateRevokeException, CertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException, CustomCertificateSerialNumberException {
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
            log.debug("User type (EndEntityType) = " + data.getType().getHexValue());
        }
        // Get CA object and make sure it is active
        // Do not log access control to the CA here, that is logged later on when we use the CA to issue a certificate (if we get that far).
        final CA ca = caSession.getCANoLog(admin, data.getCAId());
        if (ca.getStatus() != CAConstants.CA_ACTIVE) {
            final String msg = intres.getLocalizedMessage("createcert.canotactive", ca.getSubjectDN());
            throw new EJBException(msg);
        }
        final Certificate cert;
        try {
            // Now finally after all these checks, get the certificate, we don't have any sequence number or extensions available here
            cert = createCertificate(admin, data, ca, pk, keyusage, notBefore, notAfter, null, null);
            // Call authentication session and tell that we are finished with this user
            finishUser(ca, data);
        } catch (CustomCertificateSerialNumberException e) {
            cleanUserCertDataSN(data);
            throw e;
        } catch (CertificateExtensionException e) {
            throw new IllegalStateException("CertificateExtensionException was thrown, even though no extensions were supplied.", e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<createCertificate(pk, ku, date)");
        }
        return cert;
    }

    @Override
    public CertificateResponseMessage createRequestFailedResponse(final AuthenticationToken admin, final RequestMessage req,
            final Class<? extends ResponseMessage> responseClass, final FailInfo failInfo, final String failText) throws CADoesntExistsException,
            SignRequestSignatureException, CryptoTokenOfflineException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">createRequestFailedResponse(IRequestMessage)");
        }
        CertificateResponseMessage ret = null;
        final CA ca = getCAFromRequest(admin, req, true);
        try {
            final CAToken catoken = ca.getCAToken();
            final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(catoken.getCryptoTokenId());
            decryptAndVerify(cryptoToken, req, ca);
            //Create the response message with all nonces and checks etc
            ret = ResponseMessageUtils.createResponseMessage(responseClass, req, ca.getCertificateChain(),
                            cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
                            cryptoToken.getSignProviderName());
            ret.setStatus(ResponseStatus.FAILURE);
            ret.setFailInfo(failInfo);
            ret.setFailText(failText);
            ret.create();
        } catch (NoSuchProviderException e) {
            log.error("NoSuchProvider provider: ", e);
        } catch (InvalidKeyException e) {
            log.error("Invalid key in request: ", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("No such algorithm: ", e);
        } catch (CryptoTokenOfflineException ctoe) {
            String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getSubjectDN());
            log.warn(msg, ctoe);
            throw ctoe;
        } catch (CertificateEncodingException e) {
            log.error("There was a problem extracting the certificate information.", e);
        } catch (CRLException e) {
            log.error("There was a problem extracting the CRL information.", e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<createRequestFailedResponse(IRequestMessage)");
        }
        return ret;
    }

    @Override
    public RequestMessage decryptAndVerifyRequest(final AuthenticationToken admin, final RequestMessage req) throws AuthStatusException,
            AuthLoginException, IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException,
            CryptoTokenOfflineException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">decryptAndVerifyRequest(IRequestMessage)");
        }
        // Get CA that will receive request
        final CA ca = getCAFromRequest(admin, req, true);
        try {
            // See if we need some key material to decrypt request
            final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
            decryptAndVerify(cryptoToken, req, ca);
        } catch (NoSuchProviderException e) {
            log.error("NoSuchProvider provider: ", e);
        } catch (InvalidKeyException e) {
            log.error("Invalid key in request: ", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("No such algorithm: ", e);
        } catch (CryptoTokenOfflineException ctoe) {
            String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getSubjectDN());
            log.error(msg, ctoe);
            throw ctoe;
        }
        if (log.isTraceEnabled()) {
            log.trace("<decryptAndVerifyRequest(IRequestMessage)");
        }
        return req;
    }

    /**
     * 
     * @param cryptoToken
     * @param req
     * @param ca
     * 
     * @throws CryptoTokenOfflineException if the cryptotoken was unavailable.
     * @throws InvalidKeyException If the key from the request used for verification is invalid.
     * @throws NoSuchAlgorithmException if the signature on the request is done with an unhandled algorithm
     * @throws NoSuchProviderException if there is an error with the Provider defined in the request
     * @throws SignRequestSignatureException the the request couldn't be verified
     */
    private void decryptAndVerify(final CryptoToken cryptoToken, final RequestMessage req, final CA ca) throws CryptoTokenOfflineException,
            InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignRequestSignatureException {
        final CAToken catoken = ca.getCAToken();
        if (req.requireKeyInfo()) {
            // You go figure...scep encrypts message with the public CA-cert
            req.setKeyInfo(ca.getCACertificate(), cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
                    cryptoToken.getSignProviderName());
        }
        // Verify the request
        if (req.verify() == false) {
            String msg = intres.getLocalizedMessage("createcert.popverificationfailed");
            throw new SignRequestSignatureException(msg);
        }
    }

    @Override
    public ResponseMessage getCRL(final AuthenticationToken admin, final RequestMessage req, final Class<? extends ResponseMessage> responseClass)
            throws AuthStatusException, AuthLoginException, IllegalKeyException, CADoesntExistsException, SignRequestException,
            SignRequestSignatureException, UnsupportedEncodingException, CryptoTokenOfflineException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">getCRL(IRequestMessage)");
        }
        ResponseMessage ret = null;
        // Get CA that will receive request
        final CA ca = getCAFromRequest(admin, req, true);
        try {
            final CAToken catoken = ca.getCAToken();
            if (ca.getStatus() != CAConstants.CA_ACTIVE) {
                String msg = intres.getLocalizedMessage("createcert.canotactive", ca.getSubjectDN());
                throw new EJBException(msg);
            }
            // See if we need some key material to decrypt request
            final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(catoken.getCryptoTokenId());
            final String aliasCertSign = catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
            if (req.requireKeyInfo()) {
                // You go figure...scep encrypts message with the public CA-cert
                req.setKeyInfo(ca.getCACertificate(), cryptoToken.getPrivateKey(aliasCertSign), cryptoToken.getSignProviderName());
            }
            //Create the response message with all nonces and checks etc
            ret = ResponseMessageUtils.createResponseMessage(responseClass, req, ca.getCertificateChain(), cryptoToken.getPrivateKey(aliasCertSign),
                    cryptoToken.getSignProviderName());

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
        } catch (NoSuchProviderException e) {
            log.error("NoSuchProvider provider: ", e);
        } catch (InvalidKeyException e) {
            log.error("Invalid key in request: ", e);
        } catch (NoSuchAlgorithmException e) {
            log.error("No such algorithm: ", e);
        } catch (CRLException e) {
            log.error("Cannot create response message: ", e);
        } catch (CryptoTokenOfflineException ctoe) {
            String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getSubjectDN());
            log.error(msg, ctoe);
            throw ctoe;
        } catch (CertificateEncodingException e) {
            log.error("There was a problem extracting the certificate information.", e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<getCRL(IRequestMessage)");
        }
        return ret;
    }

    @Override
    public CA getCAFromRequest(final AuthenticationToken admin, final RequestMessage req, final boolean doLog) throws CADoesntExistsException,
            AuthorizationDeniedException {
        CA ca = null;
        // See if we can get issuerDN directly from request
        if (req.getIssuerDN() != null) {
            String dn = certificateStoreSession.getCADnFromRequest(req);

            try {
                if (doLog) {
                    ca = caSession.getCA(admin, dn.hashCode());
                } else {
                    ca = caSession.getCANoLog(admin, dn.hashCode());
                }
                if (log.isDebugEnabled()) {
                    log.debug("Using CA (from issuerDN) with id: " + ca.getCAId() + " and DN: " + ca.getSubjectDN());
                }
            } catch (CADoesntExistsException e) {
                // We could not find a CA from that DN, so it might not be a CA. Try to get from username instead
                if (req.getUsername() != null) {
                    ca = getCAFromUsername(admin, req, doLog);
                    if (log.isDebugEnabled()) {
                        log.debug("Using CA from username: " + req.getUsername());
                    }
                } else {
                    String msg = intres.getLocalizedMessage("createcert.canotfoundissuerusername", dn, "null");
                    throw new CADoesntExistsException(msg);
                }
            }
        } else if (req.getUsername() != null) {
            ca = getCAFromUsername(admin, req, doLog);
            if (log.isDebugEnabled()) {
                log.debug("Using CA from username: " + req.getUsername());
            }
        } else {
            throw new CADoesntExistsException(intres.getLocalizedMessage("createcert.canotfoundissuerusername", req.getIssuerDN(), req.getUsername()));
        }

        if (ca.getStatus() != CAConstants.CA_ACTIVE) {
            String msg = intres.getLocalizedMessage("createcert.canotactive", ca.getSubjectDN());
            throw new EJBException(msg);
        }
        return ca;
    }

    /**
     * 
     * @param admin
     * @param req
     * @param doLog
     * @return
     * @throws CADoesntExistsException if no end entity could be found, and hence no CA which could have created that end entity
     * @throws AuthorizationDeniedException if the authentication token wasn't authorized to the CA in question
     */
    private CA getCAFromUsername(final AuthenticationToken admin, final RequestMessage req, final boolean doLog) throws CADoesntExistsException,
            AuthorizationDeniedException {
        // See if we can get username and password directly from request
        final String username = req.getUsername();
        final EndEntityInformation data = endEntityAccessSession.findUser(admin, username);
        if (data == null) {
            throw new CADoesntExistsException("Could not find username, and hence no CA for user '" + username + "'.");
        }
        final CA ca;
        if (doLog) {
            ca = caSession.getCA(admin, data.getCAId());
        } else {
            ca = caSession.getCANoLog(admin, data.getCAId());
        }
        if (log.isDebugEnabled()) {
            log.debug("Using CA (from username) with id: " + ca.getCAId() + " and DN: " + ca.getSubjectDN());
        }
        return ca;
    }

    private EndEntityInformation authUser(final AuthenticationToken admin, final String username, final String password)
            throws ObjectNotFoundException, AuthStatusException, AuthLoginException {
        // Authorize user and get DN
        return endEntityAuthenticationSession.authenticateUser(admin, username, password);
    }

    /** Finishes user, i.e. set status to generated, if it should do so.
     * The authentication session is responsible for determining if this should be done or not */
    private void finishUser(final CA ca, final EndEntityInformation data) {
        if (data == null) {
            return;
        }
        if (!ca.getCAInfo().getFinishUser()) {
            cleanUserCertDataSN(data);
            return;
        }
        try {
            endEntityAuthenticationSession.finishUser(data);
        } catch (ObjectNotFoundException e) {
            final String msg = intres.getLocalizedMessage("signsession.finishnouser", data.getUsername());
            log.info(msg);
        }
    }

    /**
     * Clean the custom certificate serial number of user from database
     * @param data of user
     */
    private void cleanUserCertDataSN(final EndEntityInformation data) {
        if (data == null || data.getExtendedinformation() == null || data.getExtendedinformation().certificateSerialNumber() == null) {
            return;
        }
        try {
            endEntityManagementSession.cleanUserCertDataSN(data);
        } catch (ObjectNotFoundException e) {
            final String msg = intres.getLocalizedMessage("signsession.finishnouser", data.getUsername());
            log.info(msg);
        }
    }

    /**
     * Creates the certificate, uses the cesecore method with the same signature but in addition to that calls certreqsession and publishers, and fetches the CT configuration
     * @throws AuthorizationDeniedException (rollback) if admin is not authorized to issue this certificate
     * @throws CertificateCreateException (rollback) if certificate couldn't be created.
     * @throws IllegalKeyException if the public key didn't conform to the constrains of the CA's certificate profile.
     * @throws CertificateExtensionException if any of the extensions were invalid
     * @throws InvalidAlgorithmException if the signing algorithm in the certificate profile (or the CA Token if not found) was invalid.
     * @throws CAOfflineException if the CA was offline
     * @throws IllegalValidityException if the validity defined by notBefore and notAfter was invalid
     * @throws CryptoTokenOfflineException if the crypto token for the CA wasn't found
     * @throws CertificateSerialNumberException if certificate with same subject DN or key already exists for a user, if these limitations are enabled in CA.
     * @throws CertificateRevokeException (rollback) if certificate was meant to be issued revoked, but could not.
     * @throws CustomCertificateSerialNumberException (no rollback) if custom serial number is registered for user, but it is not allowed to be used (either
     *             missing unique index in database, or certificate profile does not allow it
     * @throws IllegalNameException if the certificate request contained an illegal name 
     */
    private Certificate createCertificate(final AuthenticationToken admin, final EndEntityInformation data, final CA ca, final PublicKey pk,
            final int keyusage, final Date notBefore, final Date notAfter, final Extensions extensions, final String sequence)
            throws IllegalKeyException, CertificateCreateException, AuthorizationDeniedException, CertificateExtensionException,
            IllegalNameException, CustomCertificateSerialNumberException, CertificateRevokeException, CertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException {
        if (log.isTraceEnabled()) {
            log.trace(">createCertificate(pk, ku, notAfter)");
        }
        final long updateTime = System.currentTimeMillis();
        // Create the certificate. Does access control checks (with audit log) on the CA and create_certificate.
        final CertificateDataWrapper certWrapper = certificateCreateSession.createCertificate(admin, data, ca, null, pk, keyusage, notBefore, notAfter, extensions,
                sequence, fetchCertGenParams(), updateTime);
        postCreateCertificate(admin, data, ca, certWrapper, updateTime);
        if (log.isTraceEnabled()) {
            log.trace("<createCertificate(pk, ku, notAfter)");
        }
        return certWrapper.getCertificate();
    }
    
    @Override
    public CertificateGenerationParams fetchCertGenParams() {
        // Supply extra info to X509CA for Certificate Transparency
        final GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        final Map<Integer, CTLogInfo> configuredCTLogs = globalConfiguration.getCTLogs();
        
        final CertificateGenerationParams certGenParams = new CertificateGenerationParams();
        certGenParams.setConfiguredCTLogs(configuredCTLogs);
        return certGenParams;
    }

    /**
     * Perform a set of actions post certificate creation
     * 
     * @param authenticationToken the authentication token being used
     * @param endEntity the end entity involved
     * @param ca the relevant CA
     * @param certificate the newly created Certificate
     * @param updateTime the time when this operation takes place
     * @throws AuthorizationDeniedException if access is denied to the CA issuing certificate
     */
    private void postCreateCertificate(final AuthenticationToken authenticationToken, final EndEntityInformation endEntity, final CA ca,
            final CertificateDataWrapper certificateWrapper, final long updateTime) throws AuthorizationDeniedException {
        // Store the request data in history table.
        if (ca.isUseCertReqHistory()) {
            certreqHistorySession.addCertReqHistoryData(certificateWrapper.getCertificate(), endEntity);
        }

        /* Store certificate in certificate profiles publishers. But check if the certificate was revoked directly on issuance, 
         * the revocation was then handled by CertificateCreateSession, but that session does not know about publishers to we need 
         * to manage it here with unfortunately a little duplicated code. We could just look up certificate info to see what the
         * result was, but that would be very slow since it probably would cause an extra database lookup. Therefore we do it here 
         * similarly to what we do in CertificateCreateSession. 
         */
        final int certProfileId = endEntity.getCertificateProfileId();
        final CertificateProfile certProfile = certificateProfileSession.getCertificateProfile(certProfileId);
        final Collection<Integer> publishers = certProfile.getPublisherList();
        if (!publishers.isEmpty()) {
            final String username = endEntity.getUsername();
            final Certificate cacert = ca.getCACertificate();
            final String cafingerprint = CertTools.getFingerprintAsString(cacert);
            final String tag = null; // TODO: this should not be hard coded here, but as of now (2012-02-14) tag is not used, but only there for the future.
            final long revocationDate = System.currentTimeMillis(); // This might not be in the millisecond exact, but it's rounded to seconds anyhow
            int certstatus = CertificateConstants.CERT_ACTIVE;
            int revreason = RevokedCertInfo.NOT_REVOKED;
            final ExtendedInformation ei = endEntity.getExtendedinformation();
            if (ei != null) {          
                revreason = ei.getIssuanceRevocationReason();            
                if (revreason != RevokedCertInfo.NOT_REVOKED) {
                    certstatus = CertificateConstants.CERT_REVOKED;
                }
            }

            publisherSession.storeCertificate(authenticationToken, publishers, certificateWrapper, username, endEntity.getPassword(),
                    endEntity.getCertificateDN(), cafingerprint, certstatus, certProfile.getType(), revocationDate, revreason, tag, certProfileId,
                    updateTime, endEntity.getExtendedinformation());
        }
    }

}
