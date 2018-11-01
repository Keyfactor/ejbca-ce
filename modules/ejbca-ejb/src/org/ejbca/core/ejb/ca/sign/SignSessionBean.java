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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
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
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.ResponseMessageUtils;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.certificatetransparency.CTSubmissionConfigParams;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EJBTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ServiceLocatorException;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.revoke.RevocationSessionLocal;
import org.ejbca.core.ejb.ca.store.CertReqHistorySessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ws.EjbcaWSHelperSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.core.protocol.ws.objects.CertificateResponse;
import org.ejbca.cvc.AlgorithmUtil;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCPublicKey;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.PublicKeyEC;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;
import org.ejbca.util.passgen.AllPrintableCharPasswordGenerator;

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
    private CrlStoreSessionLocal crlStoreSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private EndEntityAuthenticationSessionLocal endEntityAuthenticationSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private RevocationSessionLocal revocationSession;
    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLoggerSession;
    @EJB
    private HardTokenSessionLocal hardTokenSession;
    // Re-factor: Remove Cyclic module dependency.
    @EJB
    private EjbcaWSHelperSessionLocal ejbcaWSHelperSession;
    
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
    public Collection<Certificate> getCertificateChain(int caid) {
        return caSession.getCAInfoInternal(caid).getCertificateChain();
    }

    @Override
    public byte[] createPKCS7(AuthenticationToken admin, X509Certificate cert, boolean includeChain) throws CADoesntExistsException,
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
    private byte[] createPKCS7(AuthenticationToken admin, int caId, X509Certificate cert, boolean includeChain) throws CADoesntExistsException,
            SignRequestSignatureException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">createPKCS7(" + caId + ", " + CertTools.getIssuerDN(cert) + ")");
        }
        final CA ca = caSession.getCA(admin, caId);
        final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
        final byte[] returnval = ca.createPKCS7(cryptoToken, cert, includeChain);
        if (returnval!=null) {
            // Audit log that we used the CA's signing key to create a CMS signature
            final String detailsMsg = intres.getLocalizedMessage("caadmin.signedcms", ca.getName());
            final Map<String, Object> details = new LinkedHashMap<>();
            if (cert!=null) {
                details.put("leafSubject", CertTools.getSubjectDN(cert));
                details.put("leafFingerprint", CertTools.getFingerprintAsString(cert));
            }
            details.put("includeChain", Boolean.toString(includeChain));
            details.put("msg", detailsMsg);
            securityEventsLoggerSession.log(EjbcaEventTypes.CA_SIGNCMS, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(caId), null, null, details);
        }
        if (log.isTraceEnabled()) {
            log.trace("<createPKCS7()");
        }
        return returnval;
    }
    
    @Override
    public byte[] createPKCS7Rollover(AuthenticationToken admin, int caId) throws CADoesntExistsException, AuthorizationDeniedException {
        try {
            if (log.isTraceEnabled()) {
                log.trace(">createPKCS7Rollover(" + caId + ")");
            }
            CA ca = caSession.getCA(admin, caId);
            final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
            byte[] returnval = ca.createPKCS7Rollover(cryptoToken);
            log.trace("<createPKCS7Rollover()");
            return returnval;
        } catch (SignRequestSignatureException e) {
            String msg = intres.getLocalizedMessage("error.unknown");
            log.error(msg, e);
            throw new EJBException(e);
        }
    }

    @Override
    public Certificate createCertificate(final AuthenticationToken admin, final String username, final String password, final PublicKey pk)
            throws NoSuchEndEntityException, AuthorizationDeniedException, CADoesntExistsException, AuthStatusException, AuthLoginException,
            IllegalKeyException, CertificateCreateException, IllegalNameException, CertificateRevokeException, CertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            CustomCertificateSerialNumberException {
        // Default key usage is defined in certificate profiles
        return createCertificate(admin, username, password, pk, -1, null, null, CertificateProfileConstants.CERTPROFILE_NO_PROFILE,
                SecConst.CAID_USEUSERDEFINED);
    }
    
    @Override
    public Certificate createCertificate(AuthenticationToken admin, String username, String password, PublicKeyWrapper pk)
            throws NoSuchEndEntityException, CADoesntExistsException, AuthorizationDeniedException, IllegalKeyException, CertificateCreateException,
            IllegalNameException, CertificateRevokeException, CertificateSerialNumberException, CryptoTokenOfflineException,
            IllegalValidityException, CAOfflineException, InvalidAlgorithmException, CustomCertificateSerialNumberException, AuthStatusException,
            AuthLoginException {
        return createCertificate(admin, username, password, pk.getPublicKey());
    }

    @Override
    public Certificate createCertificate(final AuthenticationToken admin, final String username, final String password, final PublicKey pk,
            final int keyusage, final Date notBefore, final Date notAfter) throws NoSuchEndEntityException, AuthorizationDeniedException,
            CADoesntExistsException, AuthStatusException, AuthLoginException, IllegalKeyException, CertificateCreateException, IllegalNameException,
            CertificateRevokeException, CertificateSerialNumberException, CryptoTokenOfflineException, IllegalValidityException, CAOfflineException,
            InvalidAlgorithmException, CustomCertificateSerialNumberException {
        return createCertificate(admin, username, password, pk, keyusage, notBefore, notAfter, CertificateProfileConstants.CERTPROFILE_NO_PROFILE,
                SecConst.CAID_USEUSERDEFINED);
    }
    
    @Override
    public Certificate createCertificate(final AuthenticationToken admin, final String username, final String password, final PublicKeyWrapper pk,
            final int keyusage, final Date notBefore, final Date notAfter) throws NoSuchEndEntityException, AuthorizationDeniedException,
            CADoesntExistsException, AuthStatusException, AuthLoginException, IllegalKeyException, CertificateCreateException, IllegalNameException,
            CertificateRevokeException, CertificateSerialNumberException, CryptoTokenOfflineException, IllegalValidityException, CAOfflineException,
            InvalidAlgorithmException, CustomCertificateSerialNumberException {
        return createCertificate(admin, username, password, pk.getPublicKey(), keyusage, notBefore, notAfter, CertificateProfileConstants.CERTPROFILE_NO_PROFILE,
                SecConst.CAID_USEUSERDEFINED);
    }

    @Override
    public Certificate createCertificate(final AuthenticationToken admin, final String username, final String password, final Certificate incert)
            throws NoSuchEndEntityException, AuthorizationDeniedException, SignRequestSignatureException, CADoesntExistsException,
            AuthStatusException, AuthLoginException, IllegalKeyException, CertificateCreateException, IllegalNameException,
            CertificateRevokeException, CertificateSerialNumberException, CryptoTokenOfflineException, IllegalValidityException, CAOfflineException,
            InvalidAlgorithmException, CustomCertificateSerialNumberException {

        // Convert the certificate to a BC certificate. SUN does not handle verifying RSASha256WithMGF1 for example 
            Certificate bccert;
            try {
                bccert = CertTools.getCertfromByteArray(incert.getEncoded(), Certificate.class);
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
            Class<? extends CertificateResponseMessage> responseClass, boolean ignorePassword) throws AuthorizationDeniedException, NoSuchEndEntityException,
            CertificateCreateException, CertificateRevokeException, InvalidAlgorithmException, ApprovalException, WaitingForApprovalException {
        final String username = req.getUsername();
        EndEntityInformation retrievedUser = endEntityAccessSession.findUser(admin, username);
        if (retrievedUser.getStatus() == EndEntityConstants.STATUS_GENERATED) {
            endEntityManagementSession.setUserStatus(admin, username, EndEntityConstants.STATUS_NEW);
        }
        if (ignorePassword) {

            try {
                endEntityManagementSession.setPassword(admin, username, req.getPassword());
            } catch (EndEntityProfileValidationException e) {
                //Can be ignored in this case, shouldn't happen.
                throw new IllegalStateException(e);
            }
        }
        
        try {
            return createCertificate(admin, req, responseClass, null);
        } catch (CryptoTokenOfflineException | IllegalKeyException | CADoesntExistsException | SignRequestException | SignRequestSignatureException
                | AuthStatusException | AuthLoginException | CertificateExtensionException | CustomCertificateSerialNumberException
                | IllegalNameException | CertificateSerialNumberException | IllegalValidityException | CAOfflineException e) {
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
        EndEntityInformation endEntityInformation = null;
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
            throw new CAOfflineException(msg);
        }
        try {
            // See if we need some key material to decrypt request
            final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
            setDecryptInfo(cryptoToken, req, ca);    
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
                        endEntityInformation = authUser(admin, req.getUsername(), req.getPassword());
                    } else {
                        endEntityInformation = suppliedUserData;
                    }
                    // We need to make sure we use the users registered CA here
                    if (endEntityInformation.getCAId() != ca.getCAId()) {
                        final String failText = intres.getLocalizedMessage("signsession.wrongauthority", Integer.valueOf(ca.getCAId()),
                                Integer.valueOf(endEntityInformation.getCAId()));
                        log.info(failText);
                        ret = createRequestFailedResponse(admin, req, responseClass, FailInfo.WRONG_AUTHORITY, failText);
                    } else {
                        final long updateTime = System.currentTimeMillis();
                        //Specifically check for the Single Active Certificate Constraint property, which requires that revocation happen in conjunction with renewal. 
                        //We have to perform this check here, in addition to the true check in CertificateCreateSession, in order to be able to perform publishing. 
                        singleActiveCertificateConstraint(admin, endEntityInformation);        
                        // Issue the certificate from the request
                        ret = certificateCreateSession.createCertificate(admin, endEntityInformation, ca, req, responseClass, fetchCertGenParams(), updateTime);
                        postCreateCertificate(admin, endEntityInformation, ca, new CertificateDataWrapper(ret.getCertificate(), ret.getCertificateData(), ret.getBase64CertData()));
                    }
                } catch (NoSuchEndEntityException e) {
                    // If we didn't find the entity return error message
                    final String failText = intres.getLocalizedMessage("signsession.nosuchuser", req.getUsername());
                    log.info(failText, e);
                    throw new NoSuchEndEntityException(failText, e);
                }
            }
            ret.create();
            // Call authentication session and tell that we are finished with this user. (Only if we store UserData for this CA.)
            if (ca.isUseUserStorage() && endEntityInformation != null) {
                finishUser(ca, endEntityInformation);
            }
        } catch (CustomCertificateSerialNumberException e) {
            cleanUserCertDataSN(endEntityInformation);
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
            throw new IllegalStateException(e);
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
            throws NoSuchEndEntityException, CADoesntExistsException, AuthorizationDeniedException, AuthStatusException, AuthLoginException,
            IllegalKeyException, CertificateCreateException, IllegalNameException, CertificateRevokeException, CertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException, CustomCertificateSerialNumberException {
            return createCertificate(admin, username, password, pk.getPublicKey(), keyusage, notBefore, notAfter, certificateprofileid, caid);
    }

    @Override
    public Certificate createCertificate(final AuthenticationToken admin, final String username, final String password, final PublicKey pk,
            final int keyusage, final Date notBefore, final Date notAfter, final int certificateprofileid, final int caid)
            throws CADoesntExistsException, AuthorizationDeniedException, AuthStatusException, AuthLoginException,
            IllegalKeyException, CertificateCreateException, IllegalNameException, CertificateRevokeException, CertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException, CustomCertificateSerialNumberException, NoSuchEndEntityException {
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
    public Collection<CertificateWrapper> createCardVerifiableCertificateWS(final AuthenticationToken authenticationToken, final String username, String password,
            final String cvcreq) throws AuthorizationDeniedException, CADoesntExistsException, UserDoesntFullfillEndEntityProfile, NotFoundException,
            ApprovalException, EjbcaException, WaitingForApprovalException, SignRequestException, CertificateExpiredException, CesecoreException
        {
        // If password is empty we can generate a big random one to use instead.
        if (StringUtils.isEmpty(password)) {
            password = new AllPrintableCharPasswordGenerator().getNewPassword(15, 20);
            log.debug("Using a long random password.");
        }
        // See if this user already exists.
        // We allow renewal of certificates for IS's that are not revoked
        // In that case look for it's last old certificate and try to authenticate the request using an outer signature.
        // If this verification is correct, set status to NEW and continue process the request.
        int oldUserStatus = EndEntityConstants.STATUS_GENERATED;
        final EndEntityInformation user = endEntityAccessSession.findUser(authenticationToken, username);
        try {
            if (user != null) {
                oldUserStatus = user.getStatus();
                // If user is revoked, we can not proceed
                if ((oldUserStatus == EndEntityConstants.STATUS_REVOKED) || (oldUserStatus == EndEntityConstants.STATUS_HISTORICAL)) {
                    throw new AuthorizationDeniedException("User '" + username + "' is revoked.");
                }
                final CVCObject parsedObject = CertificateParser.parseCVCObject(Base64.decode(cvcreq.getBytes()));
                if (parsedObject instanceof CVCAuthenticatedRequest) {
                	if (log.isDebugEnabled()) {
                	    log.debug("Received an authenticated request, could be an initial DV request signed by CVCA or a renewal for DV or IS.");
                	}
                    final CVCAuthenticatedRequest request = (CVCAuthenticatedRequest)parsedObject;
                    final CVCPublicKey publicKey = request.getRequest().getCertificateBody().getPublicKey();
                    final String algorithm = AlgorithmUtil.getAlgorithmName(publicKey.getObjectIdentifier());
                    if (log.isDebugEnabled()) {
                        log.debug("Received request has a public key with algorithm: " + algorithm);
                    }
                    final HolderReferenceField holderReference = request.getRequest().getCertificateBody().getHolderReference();
                    final CAReferenceField caReferenceField = request.getAuthorityReference();
    
                    // Check to see that the inner signature does not also verify using an old certificate
                    // because that means the same keys were used, and that is not allowed according to the EU policy
                    // This must be done whether it is signed by CVCA or a renewal request
                    final Collection<Certificate> oldCertificates = EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(username));
                    if (oldCertificates != null) {
                        if (log.isDebugEnabled()) {
                            log.debug("Found " + oldCertificates.size() + " old certificates for user " + username);
                        }
                        PublicKey oldPublicKey;
                        CVCertificate innerRequest;
                        for (Certificate certificate : oldCertificates) {
                            oldPublicKey = getCVPublicKey(authenticationToken, certificate);
                            innerRequest = request.getRequest();
                            // Throws AuthorizationDeniedException
                            checkInnerCollision(oldPublicKey, innerRequest, holderReference.getConcatenated());
                        }
                    }
                    boolean verifiedOuter = false; // So we can throw an error if we could not verify
                    if (StringUtils.equals(holderReference.getMnemonic(), caReferenceField.getMnemonic()) && StringUtils.equals(holderReference.getCountry(), caReferenceField.getCountry())) {
                        if (log.isDebugEnabled()) {
                            log.debug("Authenticated request is self signed, we will try to verify it using user's old certificate.");
                        }
                        final Collection<Certificate> userCertificates = EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(username));
                        // userCertificates contains certificates ordered with last expire date first. Last expire date should be last issued cert
                        // We have to iterate over available user certificates, because we don't know which on signed the old one
                        // and cv certificates have very coarse grained validity periods so we can't really know which one is the latest one
                        // if 2 certificates are issued the same day.
                        if (userCertificates != null) {
                            if (log.isDebugEnabled()) {
                                log.debug("Found " + userCertificates.size() + " old certificates for user " + username);
                            }
                            for (java.security.cert.Certificate certificate : userCertificates) {
                                try {
                                    // Only allow renewal if the old certificate is valid
                                    final PublicKey pk = getCVPublicKey(authenticationToken, certificate);
                                    if (log.isDebugEnabled()) {
                                        log.debug("Trying to verify the outer signature with an old certificate, fp: "+CertTools.getFingerprintAsString(certificate));
                                    }
                                    request.verify(pk);
                                    if (log.isDebugEnabled()) {
                                        log.debug("Verified outer signature.");
                                    }
                                    // Yes we did it, we can move on to the next step because the outer signature was actually created with some old certificate
                                    verifiedOuter = true;
                                    try {
                                        // Check certificate validity and set end entity status/password.
                                        // This will throw one of several exceptions if the certificate is invalid.
                                        ejbcaWSHelperSession.checkValidityAndSetUserPassword(authenticationToken, certificate, username, password);
                                        break;
                                    } catch (EndEntityProfileValidationException e) {
                                        throw new UserDoesntFullfillEndEntityProfile(e);
                                    }
                                    // If verification of outer signature fails because the signature is invalid we will break and deny the request...with a message
                                } catch (InvalidKeyException e) {
                                    String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderReference.getConcatenated(), e.getMessage());
                                    log.warn(msg, e);
                                } catch (CertificateExpiredException e) { // thrown by checkValidityAndSetUserPassword
                                    // Only log this with DEBUG since it will be a common case that happens, nothing that should cause any alerts.
                                	if (log.isDebugEnabled()) {
                                	    log.debug(intres.getLocalizedMessage("cvc.error.outersignature", holderReference.getConcatenated(), e.getMessage()));
                                	}
                                    // This exception we want to throw on, because we want to give this error if there was a certificate suitable for
                                    // verification, but it had expired. This is thrown by checkValidityAndSetUserPassword after the request has already been
                                    // verified using the public key of the certificate.
                                    throw e;
                                } catch (CertificateException | NoSuchAlgorithmException | NoSuchProviderException e) {
                                    String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderReference.getConcatenated(), e.getMessage());
                                    log.warn(msg, e);
                                } catch (SignatureException e) {
                                    // Failing to verify the outer signature will be normal, since we must try all old certificates
                                    if (log.isDebugEnabled()) {
                                        log.debug(intres.getLocalizedMessage("cvc.error.outersignature", holderReference.getConcatenated(), e.getMessage()));
                                    }
                                }
                            }
                            // If verification failed because the old certificte was not yet valid, continue processing as usual, using the sent in username/password hoping the
                            // status is NEW and password is correct. If old certificate was expired a CertificateExpiredException is thrown above.
                        }
                        // If there are no old certificates, continue processing as usual, using the sent in username/password hoping the
                        // status is NEW and password is correct.
                    } else { // if (StringUtils.equals(holderRef, caRef))
                        // Subject and issuerDN is CN=Mnemonic,C=Country
                        final String dn = "CN=" + caReferenceField.getMnemonic() + ",C=" + caReferenceField.getCountry();
                        if (log.isDebugEnabled()) {
                            log.debug("Authenticated request is not self signed, we will try to verify it using a CVCA certificate: " + dn);
                        }
                        final CAInfo info = caSession.getCAInfo(authenticationToken, CertTools.stringToBCDNString(dn).hashCode());
                        if (info == null) {
                            log.info("No CA found to authenticate request: " + dn);
                            throw new CADoesntExistsException("CA with id " + CertTools.stringToBCDNString(dn).hashCode() + " doesn't exist.");
                        } else {
                            final Collection<Certificate> certificateChain = info.getCertificateChain();
                            if (certificateChain != null) {
                            	if (log.isDebugEnabled()) {
                            	    log.debug("Found " + certificateChain.size() + " certificates in chain for CA with DN: " + dn);
                            	}
                                Iterator<Certificate> iterator = certificateChain.iterator();
                                if (iterator.hasNext()) {
                                    // The CA certificate is first in chain.
                                    final Certificate caCertificate = iterator.next();
                                    if (log.isDebugEnabled()) {
                                        log.debug("Trying to verify the outer signature with a CVCA certificate, fp: "
                                                + CertTools.getFingerprintAsString(caCertificate));
                                    }
                                    try {
                                        // The CVCA certificate always contains the full key parameters, no need to du any EC curve parameter magic here
                                        request.verify(caCertificate.getPublicKey());
                                        if (log.isDebugEnabled()) {
                                            log.debug("Verified outer signature");
                                        }
                                        verifiedOuter = true;
                                        // Yes we did it, we can move on to the next step because the outer signature was actually created with some old certificate
                                        try {
                                            // Check certificate validity and set end entity status/password.
                                            // This will throw one of several exceptions if the certificate is invalid.
                                            ejbcaWSHelperSession.checkValidityAndSetUserPassword(authenticationToken, caCertificate, username, password);
                                        } catch (EndEntityProfileValidationException e) {
                                            throw new UserDoesntFullfillEndEntityProfile(e);
                                        }
                                    } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
                                        log.warn(intres.getLocalizedMessage("cvc.error.outersignature", holderReference.getConcatenated(), e.getMessage()), e);
                                    }
                                }
                            } else {
                                log.info("No CA certificate found to authenticate request: " + dn);
                            }
                        }
                    }
                    // If verification failed because we could not verify the outer signature at all it is an error.
                    if (!verifiedOuter) {
                        final String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderReference.getConcatenated(), "No certificate found that could authenticate request");
                        log.info(msg);
                        throw new AuthorizationDeniedException(msg);
                    }
                } // if (parsedObject instanceof CVCAuthenticatedRequest)
                // If it is not an authenticated request, with an outer signature, continue processing as usual,
                // using the sent in username/password hoping the status is NEW and password is correct.
            } else {
                // If there are no old user, continue processing as usual... it will fail
                log.debug("No existing user with username: "+username);
            }
        } catch (ParseException | ConstructionException | NoSuchFieldException e) {
            ejbcaWSHelperSession.resetUserPasswordAndStatus(authenticationToken, username, oldUserStatus);
            throw new EjbcaException(ErrorCode.INTERNAL_ERROR, e.getMessage());
        }

        // Finally generate the certificate (assuming user status is NEW and the password is correct.
        try {
            final byte[] response = createCertificateWS(authenticationToken, username, password, cvcreq, CertificateConstants.CERT_REQ_TYPE_CVC, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
            final CertificateResponse certificateResponse = new CertificateResponse(CertificateHelper.RESPONSETYPE_CERTIFICATE, response);
            final byte[] b64cert = certificateResponse.getData();
            final CVCertificate certObject = CertificateParser.parseCertificate(Base64.decode(b64cert));
            final ArrayList<Certificate> result = new ArrayList<>();
            result.add(new CardVerifiableCertificate(certObject));
            // Get the certificate chain.
            if (user != null) {
                final int caid = user.getCAId();
                caSession.verifyExistenceOfCA(caid);
                result.addAll(getCertificateChain(caid));
            }
            log.trace("<cvcRequest");
            return EJBTools.wrapCertCollection(result);
        } catch (ServiceLocatorException | NoSuchEndEntityException | ParseException | ConstructionException 
        		| NoSuchFieldException | InvalidKeyException | CertificateException // | CertificateEncodingException
        		| CertificateExtensionException | InvalidKeySpecException | NoSuchAlgorithmException 
        		| NoSuchProviderException | SignatureException | IOException e) {
            ejbcaWSHelperSession.resetUserPasswordAndStatus(authenticationToken, username, oldUserStatus);
            throw new EjbcaException(ErrorCode.INTERNAL_ERROR, e.getMessage());
        }
    }

    /** Method that gets the public key from a CV certificate, possibly enriching it with domain parameters 
     *  from the CVCA certificate if it is an EC public key.
     *
     * @param admin the authentication token.
     * @param certificate the certificate to get the public ket from.
     * @return the certificates public key.
     * @throws CADoesntExistsException if the CA of the certificate does not exist.
     * @throws AuthorizationDeniedException if authorization was denied.
     * @throws NoSuchAlgorithmException if the key algorithm is unknown.
     * @throws NoSuchProviderException if the crypto provider could not be found.
     * @throws InvalidKeySpecException if the keys specification is unknown.
     */
    private PublicKey getCVPublicKey(final AuthenticationToken admin, final Certificate certificate) throws CADoesntExistsException, AuthorizationDeniedException {
        PublicKey publicKey = certificate.getPublicKey();
        if (publicKey instanceof PublicKeyEC) {
            // The public key of IS and DV certificate do not have any EC parameters so we have to do some magic to get a complete EC public key
            // First get to the CVCA certificate that has the parameters
            final CAInfo caInfo = caSession.getCAInfo(admin, CertTools.getIssuerDN(certificate).hashCode());
            if (caInfo == null) {
                throw new CADoesntExistsException("CA with id " + CertTools.getIssuerDN(certificate).hashCode() + " doesn't exist.");
            }
            final List<Certificate> caCertificates = caInfo.getCertificateChain();
            if (caCertificates != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Found CA certificate chain of length: " + caCertificates.size());
                }
                // Get the last certificate in the chain, it is the CVCA certificate.
                if (CollectionUtils.isNotEmpty(caCertificates)) {
                    // Do the magic adding of parameters, if they don't exist in the public key.
                	final Certificate cvcaCertificate = caCertificates.get(caCertificates.size() - 1);
                    try {
                        publicKey = KeyTools.getECPublicKeyWithParams(publicKey, cvcaCertificate.getPublicKey());
                    } catch (InvalidKeySpecException e) {
                        String msg = intres.getLocalizedMessage("cvc.error.outersignature", CertTools.getSubjectDN(certificate), e.getMessage());
                        log.warn(msg, e);
                    }
                }
            }
        }
        return publicKey;
    }
    
    /** 
     * Method called from cvcRequest that simply verifies a CVCertificate with a public key 
     * and throws AuthorizationDeniedException if the verification succeeds.
     * 
     * The method is used to check if a request is sent containing the same public key.
     * this could be replaced by enforcing unique public key on the CA (from EJBCA 3.10) actually...
     *
     * @param publicKey the public key.
     * @param innerRequest the nested request.
     * @param holderReference the holders reference.
     * @throws AuthorizationDeniedException if the authorization was denied.
     */
    private void checkInnerCollision(final PublicKey publicKey, final CVCertificate innerRequest, final String holderReference) throws AuthorizationDeniedException {
        // Check to see that the inner signature does not verify using an old certificate (public key)
        // because that means the same keys were used, and that is not allowed according to the EU policy.
        final CardVerifiableCertificate innerCertificate = new CardVerifiableCertificate(innerRequest);
        try {
            innerCertificate.verify(publicKey);
            String msg = intres.getLocalizedMessage("cvc.error.renewsamekeys", holderReference);
            log.info(msg);
            throw new AuthorizationDeniedException(msg);
        } catch (SignatureException e) {
            // It was good if the verification failed
        } catch (NoSuchProviderException | InvalidKeyException | NoSuchAlgorithmException | CertificateException e) {
            String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderReference, e.getMessage());
            log.warn(msg, e);
            throw new AuthorizationDeniedException(msg); // Re-factor.
        }
    }
    
    @Override
    public byte[] createCertificateWS(final AuthenticationToken authenticationToken, final String username, final String password, final String req, final int reqType,
            final String hardTokenSN, final String responseType)
            throws AuthorizationDeniedException, EjbcaException, CesecoreException, CADoesntExistsException, CertificateExtensionException,
            InvalidKeyException, SignatureException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException,
            IOException, ParseException, ConstructionException, NoSuchFieldException, AuthStatusException, AuthLoginException {
        byte[] result = null;
        // Check user exists.
        final EndEntityInformation endEntity = endEntityAccessSession.findUser(authenticationToken, username);
        if (endEntity == null) {
            log.info(intres.getLocalizedMessage("ra.errorentitynotexist", username));
            String msg = intres.getLocalizedMessage("ra.wrongusernameorpassword"); // Don't leak whether it was the username or the password.
            throw new NotFoundException(msg);
        }
        // Check CA exists and user is authorized to access it.
        final int caId = endEntity.getCAId();
        caSession.verifyExistenceOfCA(caId);
        // Check token type.
        if (endEntity.getTokenType() != SecConst.TOKEN_SOFT_BROWSERGEN) {
            throw new EjbcaException(ErrorCode.BAD_USER_TOKEN_TYPE, "Error: Wrong Token Type of user, must be 'USERGENERATED' for PKCS10/SPKAC/CRMF/CVC requests");
        }
        // Authorization for {StandardRules.CAACCESS.resource() + caid, StandardRules.CREATECERT.resource()} is done in the
        // CertificateCreateSessionBean.createCertificate call which is called in the end
        final RequestMessage requestMessage = RequestMessageUtils.getRequestMessageFromType(username, password, req, reqType);
        if (requestMessage != null) {
            result = getCertResponseFromPublicKeyWS(authenticationToken, requestMessage, hardTokenSN, responseType);
        }
        return result;
    }

    // Tbd re-factor: CertificateHelper from WS package causes cyclic module dependency.
    private byte[] getCertResponseFromPublicKeyWS(final AuthenticationToken admin, final RequestMessage msg, final String hardTokenSN,
            final String responseType) throws AuthorizationDeniedException, CertificateEncodingException, EjbcaException, CesecoreException,
            CertificateExtensionException, CertificateParsingException {
        byte[] result = null;
        final ResponseMessage response = createCertificate(admin, msg, X509ResponseMessage.class, null);
        final Certificate certificate = CertTools.getCertfromByteArray(response.getResponseMessage(), java.security.cert.Certificate.class);
        if (responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_CERTIFICATE)) {
            result = certificate.getEncoded();
        } else if (responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_PKCS7)) {
            result = createPKCS7(admin, (X509Certificate) certificate, false);
        } else if (responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_PKCS7WITHCHAIN)) {
            result = createPKCS7(admin, (X509Certificate) certificate, true);
        }
        if (hardTokenSN != null) {
            hardTokenSession.addHardTokenCertificateMapping(admin, hardTokenSN, certificate);
        }
        return result;
    }

    @Override
    public CertificateResponseMessage createRequestFailedResponse(final AuthenticationToken admin, final RequestMessage req,
            final Class<? extends ResponseMessage> responseClass, final FailInfo failInfo, final String failText)
            throws CADoesntExistsException, CryptoTokenOfflineException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">createRequestFailedResponse(IRequestMessage)");
        }
        CertificateResponseMessage ret = null;
        final CA ca = getCAFromRequest(admin, req, true);
        try {
            final CAToken catoken = ca.getCAToken();
            final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(catoken.getCryptoTokenId());
            setDecryptInfo(cryptoToken, req, ca);
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
    public RequestMessage decryptAndVerifyRequest(final AuthenticationToken admin, final RequestMessage req)
            throws CADoesntExistsException, SignRequestSignatureException, CryptoTokenOfflineException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">decryptAndVerifyRequest(IRequestMessage)");
        }
        // Get CA that will receive request
        final CA ca = getCAFromRequest(admin, req, true);
        try {
            // See if we need some key material to decrypt request
            final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
            setDecryptInfo(cryptoToken, req, ca);
            // Verify the request
            if (req.verify() == false) {
                String msg = intres.getLocalizedMessage("createcert.popverificationfailed");
                throw new SignRequestSignatureException(msg);
            }
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

    /** Sets information needed to decrypt a message, if such information is needed(i.e. CA private key for SCEP messages)
     * 
     * @param cryptoToken
     * @param req
     * @param ca
     * 
     * @throws CryptoTokenOfflineException if the cryptotoken was unavailable.
     * @throws InvalidKeyException If the key from the request used for verification is invalid.
     * @throws NoSuchAlgorithmException if the signature on the request is done with an unhandled algorithm
     * @throws NoSuchProviderException if there is an error with the Provider defined in the request
     */
    private void setDecryptInfo(final CryptoToken cryptoToken, final RequestMessage req, final CA ca) throws CryptoTokenOfflineException,
            InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        final CAToken catoken = ca.getCAToken();
        if (req.requireKeyInfo()) {
            // You go figure...scep encrypts message with the public CA-cert
            if (ca.getUseNextCACert(req)) {
                req.setKeyInfo(ca.getRolloverCertificateChain().get(0),
                        cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT)),
                        cryptoToken.getSignProviderName());
            } else {
                req.setKeyInfo(ca.getCACertificate(),
                        cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
                        cryptoToken.getSignProviderName());
            }
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

            if (doLog) {
                ca = caSession.getCA(admin, dn.hashCode());
            } else {
                ca = caSession.getCANoLog(admin, dn.hashCode());
            }
            if (ca == null) {
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
            if (log.isDebugEnabled()) {
                log.debug("Using CA (from issuerDN) with id: " + ca.getCAId() + " and DN: " + ca.getSubjectDN());
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
            throws NoSuchEndEntityException, AuthStatusException, AuthLoginException {
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
        } catch (NoSuchEndEntityException e) {
            final String msg = intres.getLocalizedMessage("signsession.finishnouser", data.getUsername());
            log.info(msg);
        }
    }

    /**
     * Clean the custom certificate serial number of user from database
     * @param data of user
     */
    private void cleanUserCertDataSN(final EndEntityInformation data) {
        if (data == null || data.getExtendedInformation() == null || data.getExtendedInformation().certificateSerialNumber() == null) {
            return;
        }
        try {
            endEntityManagementSession.cleanUserCertDataSN(data);
        } catch (NoSuchEndEntityException e) {
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
    private Certificate createCertificate(final AuthenticationToken admin, final EndEntityInformation endEntityInformation, final CA ca, final PublicKey pk,
            final int keyusage, final Date notBefore, final Date notAfter, final Extensions extensions, final String sequence)
            throws IllegalKeyException, CertificateCreateException, AuthorizationDeniedException, CertificateExtensionException,
            IllegalNameException, CustomCertificateSerialNumberException, CertificateRevokeException, CertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException {
        if (log.isTraceEnabled()) {
            log.trace(">createCertificate(pk, ku, notAfter)");
        }
        final long updateTime = System.currentTimeMillis();
        //Specifically check for the Single Active Certificate Constraint property, which requires that revocation happen in conjunction with renewal. 
        //We have to perform this check here, in addition to the true check in CertificateCreateSession, in order to be able to perform publishing. 
        singleActiveCertificateConstraint(admin, endEntityInformation);        
        // Create the certificate. Does access control checks (with audit log) on the CA and create_certificate.
        final CertificateDataWrapper certWrapper = certificateCreateSession.createCertificate(admin, endEntityInformation, ca, null, pk, keyusage, notBefore, notAfter, extensions,
                sequence, fetchCertGenParams(), updateTime);
        postCreateCertificate(admin, endEntityInformation, ca, certWrapper);
        if (log.isTraceEnabled()) {
            log.trace("<createCertificate(pk, ku, notAfter)");
        }
        return certWrapper.getCertificate();
    }


    /**Specifically check for the Single Active Certificate Constraint property, which requires that revocation happen in conjunction with renewal. 
    * We have to perform this check here, in addition to the true check in CertificateCreateSession, in order to be able to perform publishing.
    * 
    * @param admin AuthenticationToken used for revoking the certificate
    * @param endEntityInformation EndEntityInformation containing username, DN and certificate profile id
    */ 
    private void singleActiveCertificateConstraint(final AuthenticationToken admin, final EndEntityInformation endEntityInformation)
            throws CertificateRevokeException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">singleActiveCertificateConstraint()");
        }
        final CertificateProfile certProfile = certificateProfileSession.getCertificateProfile(endEntityInformation.getCertificateProfileId());
        if (certProfile.isSingleActiveCertificateConstraint()) {
            // Only get not yet expired certificates with status CERT_ACTIVE, CERT_NOTIFIEDABOUTEXPIRATION, CERT_REVOKED
            final List<CertificateDataWrapper> cdws = certificateStoreSession.getCertificateDataByUsername(endEntityInformation.getUsername(),
                    true, Arrays.asList(CertificateConstants.CERT_ARCHIVED, CertificateConstants.CERT_INACTIVE,
                            CertificateConstants.CERT_ROLLOVERPENDING, CertificateConstants.CERT_UNASSIGNED));
            List<Integer> publishers = certProfile.getPublisherList();
            if (log.isDebugEnabled()) {
                log.debug("SingleActiveCertificateConstraint, found "+cdws.size()+" old (non expired, active) certificates and "+publishers.size()+" publishers.");
            }
            for (final CertificateDataWrapper cdw : cdws) {
                final CertificateData certificateData = cdw.getCertificateData();
                if (certificateData.getStatus() == CertificateConstants.CERT_REVOKED && certificateData.getRevocationReason() != RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD) {
                    continue;
                }          
                //Go directly to RevocationSession and not via EndEntityManagementSession because we don't care about approval checks and so forth, 
                //the certificate must be revoked nonetheless. 
                revocationSession.revokeCertificate(admin, cdw, publishers, new Date(), RevokedCertInfo.REVOCATION_REASON_SUPERSEDED, endEntityInformation.getDN());
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<singleActiveCertificateConstraint()");
        }
    }
    
    @Override
    public CertificateGenerationParams fetchCertGenParams() {
        // Supply extra info to X509CA for Certificate Transparency
        final GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        
        final CertificateGenerationParams certGenParams = new CertificateGenerationParams();
        final CTSubmissionConfigParams ctConfig = new CTSubmissionConfigParams();
        ctConfig.setConfiguredCTLogs(globalConfiguration.getCTLogs());
        ctConfig.setValidityPolicy(globalConfiguration.getGoogleCtPolicy());
        certGenParams.setCTSubmissionConfigParams(ctConfig);
        return certGenParams;
    }

    /**
     * Perform a set of actions post certificate creation
     * 
     * @param authenticationToken the authentication token being used
     * @param endEntity the end entity involved
     * @param ca the relevant CA
     * @param certificateWrapper the newly created Certificate
     * @throws AuthorizationDeniedException if access is denied to the CA issuing certificate
     */
    private void postCreateCertificate(final AuthenticationToken authenticationToken, final EndEntityInformation endEntity, final CA ca, final CertificateDataWrapper certificateWrapper) throws AuthorizationDeniedException {
        // Store the request data in history table.
        if (ca.isUseCertReqHistory()) {
            certreqHistorySession.addCertReqHistoryData(certificateWrapper.getCertificate(), endEntity);
        }
        final int certProfileId = endEntity.getCertificateProfileId();
        final CertificateProfile certProfile = certificateProfileSession.getCertificateProfile(certProfileId);
        final Collection<Integer> publishers = certProfile.getPublisherList();
        if (!publishers.isEmpty()) {
            publisherSession.storeCertificate(authenticationToken, publishers, certificateWrapper, endEntity.getPassword(), endEntity.getCertificateDN(), endEntity.getExtendedInformation());
        }
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public byte[] signPayload(final AuthenticationToken authenticationToken, final byte[] data, final int signingCaId)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, CADoesntExistsException, SignRequestSignatureException {
        CA ca = caSession.getCA(authenticationToken, signingCaId);
        if (ca == null) {
            throw new CADoesntExistsException("CA with ID " + signingCaId + " does not exist.");
        }
        CAToken catoken = ca.getCAToken();
        CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(catoken.getCryptoTokenId());
        PrivateKey privateKey = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        final X509Certificate signerCert;
        try {
            signerCert = (X509Certificate) ca.getCACertificate();
        } catch (ClassCastException e) {
            throw new IllegalStateException("Not possible to sign a payload using a CV CA", e);
        }
        final String provider = cryptoToken.getSignProviderName();
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        String signatureAlgorithmName = AlgorithmTools.getAlgorithmNameFromDigestAndKey(ca.getCAToken().getSignatureAlgorithm(),
                privateKey.getAlgorithm());
        try {
            ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithmName).setProvider(provider).build(privateKey);
            JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME);
            JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(calculatorProviderBuilder.build());
            gen.addSignerInfoGenerator(builder.build(contentSigner, signerCert));
            gen.addCertificates(new CollectionStore<>(CertTools.convertToX509CertificateHolder(Arrays.asList(signerCert))));
            CMSSignedData sigData = gen.generate(new CMSProcessableByteArray(data), true);
            return sigData.getEncoded();
        } catch (CMSException | CertificateEncodingException | IOException | OperatorCreationException e) {
            throw new SignRequestSignatureException("Given payload could not be signed.", e);
        }
    }
}
