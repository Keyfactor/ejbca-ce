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

package org.ejbca.core.ejb.ca.caadmin;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAData;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CVCCA;
import org.cesecore.certificates.ca.CVCCAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceNotActiveException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequest;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequestException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceResponse;
import org.cesecore.certificates.ca.extendedservices.IllegalExtendedCAServiceRequestException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.CrlCreateSessionLocal;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.ocsp.exception.NotSupportedException;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.keys.token.NullCryptoToken;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.StringTools;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.revoke.RevocationSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalExecutorUtil;
import org.ejbca.core.model.approval.ApprovalOveradableClassName;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.approvalrequests.ActivateCATokenApprovalRequest;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceTypes;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceInfo;
import org.ejbca.core.model.ra.ExtendedInformationFields;
import org.ejbca.core.protocol.certificatestore.CertificateCacheFactory;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CardVerifiableCertificate;

/**
 * Administrates and manages CAs in EJBCA system.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CAAdminSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CAAdminSessionBean implements CAAdminSessionLocal, CAAdminSessionRemote {

    private static final Logger log = Logger.getLogger(CAAdminSessionBean.class);

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private AccessControlSessionLocal accessSession;
    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CrlStoreSessionLocal crlStoreSession;
    @EJB
    private RevocationSessionLocal revocationSession;
    @EJB
    private CrlCreateSessionLocal crlCreateSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private ApprovalSessionLocal approvalSession;
    @EJB
    private CryptoTokenSessionLocal cryptoTokenSession;
    @Resource
    private SessionContext sessionContext;

    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @PostConstruct
    public void postConstruct() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Override
    public void initializeAndUpgradeCAs() {
        for (final CAData cadata : CAData.findAll(entityManager)) {
            final String caname = cadata.getName();
            try {
                caSession.getCAInfoInternal(cadata.getCaId());
                log.info("Initialized CA: " + caname + ", with expire time: " + new Date(cadata.getExpireTime()));
            } catch (CADoesntExistsException e) {
                log.error("CADoesntExistsException trying to load CA with name: " + caname, e);
            }
        }
    }
 
    private CA createCAObject(CAInfo cainfo, CAToken catoken, CertificateProfile certprofile) throws InvalidAlgorithmException {
    	CA ca = null;
        // X509 CA is the most normal type of CA
        if (cainfo instanceof X509CAInfo) {
            log.info("Creating an X509 CA");
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            // Create X509CA
            ca = new X509CA(x509cainfo);
            X509CA x509ca = (X509CA) ca;
            ca.setCAToken(catoken);

            // getCertificateProfile
            if ((x509cainfo.getPolicies() != null) && (x509cainfo.getPolicies().size() > 0)) {
                certprofile.setUseCertificatePolicies(true);
                certprofile.setCertificatePolicies(x509cainfo.getPolicies());
            } else if (certprofile.getUseCertificatePolicies()) {
                x509ca.setPolicies(certprofile.getCertificatePolicies());
            }
        } else {
            // CVC CA is a special type of CA for EAC electronic passports
            log.info("Creating a CVC CA");
            CVCCAInfo cvccainfo = (CVCCAInfo) cainfo;
            // Create CVCCA
            ca = new CVCCA(cvccainfo);
            ca.setCAToken(catoken);
        }
        return ca;
    }
    
    @Override
    public void createCA(AuthenticationToken admin, CAInfo cainfo) throws CAExistsException, AuthorizationDeniedException,
            CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidAlgorithmException {
        if (log.isTraceEnabled()) {
            log.trace(">createCA: " + cainfo.getName());
        }
        int castatus = CAConstants.CA_OFFLINE;
        final int caid = cainfo.getCAId();
        // Check that administrator has superadminstrator rights.
        if (!accessSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource())) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.notauthorizedtocreateca", cainfo.getName());
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw new AuthorizationDeniedException(detailsMsg);
        } 
        // Check that CA doesn't already exists
        if (caid >= 0 && caid <= CAInfo.SPECIALCAIDBORDER) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.wrongcaid", Integer.valueOf(caid));
            auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, detailsMsg);
            throw new CAExistsException(detailsMsg);
        }
        if (CAData.findById(entityManager, Integer.valueOf(caid)) != null) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.caexistsid", Integer.valueOf(caid));
            auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, detailsMsg);
            throw new CAExistsException(detailsMsg);
        }
        if (CAData.findByName(entityManager, cainfo.getName()) != null) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.caexistsname", cainfo.getName());
            auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, detailsMsg);
            throw new CAExistsException(detailsMsg);
        }
        // Create CAToken
        final CAToken caToken = cainfo.getCAToken();
        int cryptoTokenId = caToken.getCryptoTokenId();
        final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(cryptoTokenId);
        // The certificate profile used for the CAs certificate
        CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(cainfo.getCertificateProfileId());
        // Create CA
        CA ca = createCAObject(cainfo, caToken, certprofile);
        // AltName is not implemented for all CA types
        String caAltName = null;
        if (cainfo instanceof X509CAInfo) {
            caAltName = ((X509CAInfo)cainfo).getSubjectAltName();
        }
        // See if CA token is OK before storing CA
        try {
            cryptoToken.testKeyPair(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYTEST));
        } catch (InvalidKeyException e1) {
            throw new RuntimeException("The CA's test key alias points to an invalid key.", e1);
        } 
        // Store CA in database, so we can generate keys using the ca token session.
        try {
            caSession.addCA(admin, ca);
        } catch (CAExistsException e) {
            String msg = intres.getLocalizedMessage("caadmin.caexistsid", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (IllegalCryptoTokenException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcreatetoken");
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            details.put("error", e.getMessage());
            auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw new EJBException(e);
        }
        // Create certificate chain
        Collection<Certificate> certificatechain = null;
        String sequence = caToken.getKeySequence(); // get from CAtoken to make sure it is fresh
        final String aliasCertSign = caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        if (cainfo.getSignedBy() == CAInfo.SELFSIGNED) {
            try {
                // create selfsigned certificate
                Certificate cacertificate = null;
                log.debug("CAAdminSessionBean : " + cainfo.getSubjectDN());
                EndEntityInformation cadata = new EndEntityInformation("nobody", cainfo.getSubjectDN(), cainfo.getSubjectDN().hashCode(), caAltName,
                        null, 0, new EndEntityType(EndEntityTypes.INVALID), 0, cainfo.getCertificateProfileId(), null, null, 0, 0, null);
                cacertificate = ca.generateCertificate(cryptoToken, cadata, cryptoToken.getPublicKey(aliasCertSign), -1, null, cainfo.getValidity(),
                        certprofile, sequence);
                log.debug("CAAdminSessionBean : " + CertTools.getSubjectDN(cacertificate));
                // Build Certificate Chain
                certificatechain = new ArrayList<Certificate>();
                certificatechain.add(cacertificate);
                // set status to active
                castatus = CAConstants.CA_ACTIVE;
            } catch (CryptoTokenOfflineException e) {
                final String detailsMsg = intres.getLocalizedMessage("error.catokenoffline", cainfo.getName());
                auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                		String.valueOf(caid), null, null, detailsMsg);
                sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
                throw e;
            } catch (Exception fe) {
                String msg = intres.getLocalizedMessage("caadmin.errorcreateca", cainfo.getName());
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                details.put("error", fe.getMessage());
                auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                		String.valueOf(caid), null, null, details);
                throw new EJBException(fe);
            }
        }
        if (cainfo.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA) {
            certificatechain = new ArrayList<Certificate>();
            // set status to waiting certificate response.
            castatus = CAConstants.CA_WAITING_CERTIFICATE_RESPONSE;
        }
        if (cainfo.getSignedBy() > CAInfo.SPECIALCAIDBORDER || cainfo.getSignedBy() < 0) {
            // Create CA signed by other internal CA.
            try {
                final CA signca = caSession.getCAForEdit(admin, Integer.valueOf(cainfo.getSignedBy()));
                // Check that the signer is valid
                assertSignerValidity(admin, signca);
                // Create CA certificate
                EndEntityInformation cadata = new EndEntityInformation("nobody", cainfo.getSubjectDN(), cainfo.getSubjectDN().hashCode(), caAltName,
                        null, 0, new EndEntityType(EndEntityTypes.INVALID), 0, cainfo.getCertificateProfileId(), null, null, 0, 0, null);
                CryptoToken signCryptoToken = cryptoTokenSession.getCryptoToken(signca.getCAToken().getCryptoTokenId());
                Certificate cacertificate = signca.generateCertificate(signCryptoToken, cadata,
                        cryptoToken.getPublicKey(aliasCertSign), -1, null, cainfo.getValidity(),
                        certprofile, sequence);
                // Build Certificate Chain
                Collection<Certificate> rootcachain = signca.getCertificateChain();
                certificatechain = new ArrayList<Certificate>();
                certificatechain.add(cacertificate);
                certificatechain.addAll(rootcachain);
                // set status to active
                castatus = CAConstants.CA_ACTIVE;
            } catch (CryptoTokenOfflineException e) {
                final String detailsMsg = intres.getLocalizedMessage("error.catokenoffline", cainfo.getName());
                auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                		String.valueOf(caid), null, null, detailsMsg);
                sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
                throw e;
            } catch (Exception fe) {
                String msg = intres.getLocalizedMessage("caadmin.errorcreateca", cainfo.getName());
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                details.put("error", fe.getMessage());
                auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                		String.valueOf(caid), null, null, details);
                throw new EJBException(fe);
            }
        }

        // Set Certificate Chain
        ca.setCertificateChain(certificatechain);
        if (log.isDebugEnabled()) {
        	log.debug("Setting CA status to: "+castatus);
        }
    	ca.setStatus(castatus);
        try {
            caSession.editCA(admin, ca, true);
        } catch (CADoesntExistsException e) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.canotexistsid", Integer.valueOf(caid));
            auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, detailsMsg);
            throw new EJBException(e);
        } catch (IllegalCryptoTokenException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcreatetoken");
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            details.put("error", e.getMessage());
            auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw new EJBException(e);
        }

        // Publish CA certificates.
        publishCACertificate(admin, ca.getCertificateChain(), ca.getCRLPublishers(), ca.getSubjectDN());

        if (castatus == CAConstants.CA_ACTIVE) {
            // activate External CA Services
            activateAndPublishExternalCAServices(admin, cainfo.getExtendedCAServiceInfos(), ca);
            try {
            	caSession.editCA(admin, ca, false); // store any activates CA services
            	// create initial CRLs
                crlCreateSession.forceCRL(admin, ca.getCAId());
                crlCreateSession.forceDeltaCRL(admin, ca.getCAId());
            } catch (CADoesntExistsException e) {
                String msg = intres.getLocalizedMessage("caadmin.errorcreateca", cainfo.getName());
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                details.put("error", e.getMessage());
                auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                		String.valueOf(caid), null, null, details);
                throw new EJBException(e);
            } catch (CAOfflineException e) {
                String msg = intres.getLocalizedMessage("caadmin.errorcreateca", cainfo.getName());
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                details.put("error", e.getMessage());
                auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                		String.valueOf(caid), null, null, details);
                throw new EJBException(e);
            } catch (IllegalCryptoTokenException e) {
                String msg = intres.getLocalizedMessage("caadmin.errorcreateca", cainfo.getName());
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                details.put("error", e.getMessage());
                auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                		String.valueOf(caid), null, null, details);
                throw new EJBException(e);
			}
        } else {
            log.error("CA status not active when creating CA, extended services not created. CA status: "+castatus);
        }

        // Update local OCSP's CA certificate cache
        CertificateCacheFactory.getInstance(certificateStoreSession).forceReload();

        // caSession already audit logged that the CA was added

        if (log.isTraceEnabled()) {
            log.trace("<createCA: " + cainfo.getName());
        }
    }

    @Override
    public void editCA(AuthenticationToken admin, CAInfo cainfo) throws AuthorizationDeniedException {
        boolean xkmsrenewcert = false;
        boolean cmsrenewcert = false;
        final int caid = cainfo.getCAId();
        // Check authorization
        if (!accessSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource())) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoeditca", cainfo.getName());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw new AuthorizationDeniedException(msg);
        }

        // Check if extended service certificates are about to be renewed.
        final Collection<ExtendedCAServiceInfo> extendedCAServiceInfos = cainfo.getExtendedCAServiceInfos();
        if (extendedCAServiceInfos != null) {
            for (final ExtendedCAServiceInfo extendedCAServiceInfo : extendedCAServiceInfos) {
                // No OCSP Certificate exists that can be renewed.
                if (extendedCAServiceInfo instanceof XKMSCAServiceInfo) {
                    xkmsrenewcert = ((XKMSCAServiceInfo) extendedCAServiceInfo).getRenewFlag();
                } else if (extendedCAServiceInfo instanceof CmsCAServiceInfo) {
                    cmsrenewcert = ((CmsCAServiceInfo) extendedCAServiceInfo).getRenewFlag();
                }
            }            
        }

        // Get CA from database
        try {
            caSession.editCA(admin, cainfo);
            CA ca = caSession.getCA(admin, cainfo.getCAId());
            // No OCSP Certificate exists that can be renewed.
            if (xkmsrenewcert) {
                XKMSCAServiceInfo info = (XKMSCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceTypes.TYPE_XKMSEXTENDEDSERVICE);
                Certificate xkmscert = (Certificate) info.getXKMSSignerCertificatePath().get(0);
                ArrayList<Certificate> xkmscertificate = new ArrayList<Certificate>();
                xkmscertificate.add(xkmscert);
                // Publish the extended service certificate, but only for active services
                if ((info.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE) && (!xkmscertificate.isEmpty())) {
                    publishCACertificate(admin, xkmscertificate, ca.getCRLPublishers(), ca.getSubjectDN());
                }
            }
            if (cmsrenewcert) {
                CmsCAServiceInfo info = (CmsCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceTypes.TYPE_CMSEXTENDEDSERVICE);
                Certificate cmscert = (Certificate) info.getCertificatePath().get(0);
                ArrayList<Certificate> cmscertificate = new ArrayList<Certificate>();
                cmscertificate.add(cmscert);
                // Publish the extended service certificate, but only for active services
                if ((info.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE) && (!cmscertificate.isEmpty())) {
                    publishCACertificate(admin, cmscertificate, ca.getCRLPublishers(), ca.getSubjectDN());
                }
            }
            // Log Action was done by caSession
        } catch (Exception fe) {
            String msg = intres.getLocalizedMessage("caadmin.erroreditca", cainfo.getName());
            log.error(msg, fe);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw new EJBException(fe);
        }
    }

    @Override
    public byte[] makeRequest(AuthenticationToken authenticationToken, int caid, Collection<?> certChain, String nextSignKeyAlias) throws AuthorizationDeniedException, CertPathValidatorException, CryptoTokenOfflineException {
        if (log.isTraceEnabled()) {
            log.trace(">makeRequest: " + caid + ", certChain=" + certChain + ", nextSignKeyAlias=" + nextSignKeyAlias);
        }
        byte[] returnval = null;
        if (!accessSession.isAuthorizedNoLogging(authenticationToken, AccessRulesConstants.REGULAR_RENEWCA)) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.notauthorizedtocertreq", Integer.valueOf(caid));
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw new AuthorizationDeniedException(detailsMsg);
        }
        try {
            final CA ca = caSession.getCAForEdit(authenticationToken, caid);
            final List<Certificate> chain = new ArrayList<Certificate>();
            if (certChain!= null && certChain.size()>0) {
                chain.addAll(CertTools.createCertChain(certChain));
                log.debug("Setting request certificate chain of size: " + chain.size());
                ca.setRequestCertificateChain(chain);
            }
            // AR+ patch to make SPOC independent of external CVCA certificates for automatic renewals
            // i.e. if we don't pass a CA certificate as parameter we try to find a suitable CA certificate in the database, among existing CAs
            // (can be a simple imported CA-certificate of external CA)
            if (chain.isEmpty() && ca.getCAType() == CAInfo.CATYPE_CVC && ca.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA
                    && ca.getStatus() == CAConstants.CA_ACTIVE) {
                final CardVerifiableCertificate dvcert = (CardVerifiableCertificate) ca.getCACertificate();
                final String ca_ref = dvcert.getCVCertificate().getCertificateBody().getAuthorityReference().getConcatenated();
                log.debug("DV renewal missing CVCA cert, try finding CA for:" + ca_ref);
                for (final Integer availableCaId : caSession.getAvailableCAs(authenticationToken)) {
                    final CA cvca = caSession.getCA(authenticationToken, availableCaId);
                    if (cvca.getCAType() == CAInfo.CATYPE_CVC && cvca.getSignedBy() == CAInfo.SELFSIGNED) {
                        final CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cvca.getCACertificate();
                        if (ca_ref.equals(cvccert.getCVCertificate().getCertificateBody().getHolderReference().getConcatenated())) {
                            log.debug("Added missing CVCA to rewnewal request: " + cvca.getName());
                            chain.add(cvccert);
                            break;
                        }
                    }
                }
                if (chain.isEmpty()) {
                    log.info("Failed finding suitable CVCA, forgot to import it?");
                }
            }
            // AR-

            // Generate new certificate signing request.
            final CAToken caToken = ca.getCAToken();
            final String signatureAlgorithm = caToken.getSignatureAlgorithm();
            if (log.isDebugEnabled()) {
                log.debug("Using signing algorithm: " + signatureAlgorithm + " for the CSR.");
            }
            final Properties oldprop = caToken.getProperties();
            final String oldsequence = caToken.getKeySequence();
            // If no alias is supplied we use the CAs current signature key and the KeySequence to generate a new one
            if (nextSignKeyAlias == null || nextSignKeyAlias.length()==0) {
                nextSignKeyAlias = caToken.generateNextSignKeyAlias();
            }
            caToken.setNextCertSignKey(nextSignKeyAlias);
            final int cryptoTokenId = caToken.getCryptoTokenId();
            try {
                // Test if key already exists
                cryptoTokenManagementSession.testKeyPair(authenticationToken, cryptoTokenId, nextSignKeyAlias);
            } catch (Exception e) {
                try {
                    final String currentSignKeyAlias = caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
                    cryptoTokenManagementSession.createKeyPairWithSameKeySpec(authenticationToken, cryptoTokenId, currentSignKeyAlias, nextSignKeyAlias);
                    // Audit log CA key generation
                    final Map<String, Object> details = new LinkedHashMap<String, Object>();
                    details.put("msg", intres.getLocalizedMessage("catoken.generatedkeys", caid, true, false));
                    details.put("oldproperties", oldprop);
                    details.put("oldsequence", oldsequence);
                    details.put("properties", caToken.getProperties());
                    details.put("sequence", caToken.getKeySequence());
                    auditSession.log(EventTypes.CA_KEYGEN, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(), String.valueOf(caid), null, null, details);

                } catch (AuthorizationDeniedException e2) {
                    throw e2;
                } catch (CryptoTokenOfflineException e2) {
                    throw e2;
                } catch (Exception e2) {
                    throw new RuntimeException(e2);
                }
            }
            ca.setCAToken(caToken);
            // The CA certificate signing this request is the first in the certificate chain
            final Certificate caCert = chain.size()==0 ? null : chain.get(0);
            final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(cryptoTokenId);
            byte[] request = ca.createRequest(cryptoToken, null, signatureAlgorithm, caCert, CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
            if (ca.getCAType() == CAInfo.CATYPE_CVC) {
                /*
                 * If this is a CVC CA renewal request, we need to sign it to make an authenticated
                 * request. The CVC CAs current signing certificate will always be the right one,
                 * because it is the "previous" signing certificate until we have imported a new
                 * one as response to the request we create here.
                 */
                // Sign the request with the current sign key making it an CVCAuthenticatedRequest
                final byte[] authCertSignRequest = ca.createAuthCertSignRequest(cryptoToken, request);
                if (authCertSignRequest!=null) {
                    returnval = authCertSignRequest;
                } else {
                    // This is expected if we try to generate another CSR from a CA which has not yet recieved a response.
                    log.debug("Unable to create authorization signature on CSR. Returning a regular request.");
                    returnval = request;
                }
            } else {
                returnval = request;
            }
            caSession.editCA(authenticationToken, ca, true);
            // Log information about the event
            final String detailsMsg = intres.getLocalizedMessage("caadmin.certreqcreated", ca.getName(), Integer.valueOf(caid));
            auditSession.log(EventTypes.CA_EDITING, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
        } catch (CertPathValidatorException e) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errorcertreq", Integer.valueOf(caid));
            auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw e;
        } catch (CryptoTokenOfflineException e) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errorcertreq", Integer.valueOf(caid));
            auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw e;
        } catch (Exception e) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errorcertreq", Integer.valueOf(caid));
            auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw new EJBException(e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<makeRequest: " + caid);
        }
        return returnval;
    }

    @Override
    public byte[] createAuthCertSignRequest(AuthenticationToken authenticationToken, int caid, byte[] certSignRequest)
            throws AuthorizationDeniedException, CADoesntExistsException, CryptoTokenOfflineException {
        if (!accessSession.isAuthorizedNoLogging(authenticationToken, StandardRules.ROLE_ROOT.resource())) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.notauthorizedtocertreq", Integer.valueOf(caid));
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw new AuthorizationDeniedException(detailsMsg);
        }
        final CA signedbyCA = caSession.getCA(authenticationToken, caid);
        final String caname = signedbyCA.getName();
        final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(signedbyCA.getCAToken().getCryptoTokenId());
        final byte[] returnval = signedbyCA.createAuthCertSignRequest(cryptoToken, certSignRequest);
        final String detailsMsg = intres.getLocalizedMessage("caadmin.certreqsigned", caname);
        auditSession.log(EjbcaEventTypes.CA_SIGNREQUEST, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                String.valueOf(caid), null, null, detailsMsg);
        return returnval;
    }

    @Override
    public void receiveResponse(AuthenticationToken authenticationToken, int caid, ResponseMessage responsemessage, Collection<?> cachain, String nextKeyAlias)
            throws AuthorizationDeniedException, CertPathValidatorException, EjbcaException, CesecoreException {
        if (log.isTraceEnabled()) {
            log.trace(">receiveResponse: " + caid);
        }
        if (!accessSession.isAuthorizedNoLogging(authenticationToken, AccessRulesConstants.REGULAR_RENEWCA)) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.notauthorizedtocertresp", Integer.valueOf(caid));
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
        }
        try {
            final CA ca = caSession.getCAForEdit(authenticationToken, caid);
            if (!(responsemessage instanceof X509ResponseMessage)) {
                String msg = intres.getLocalizedMessage("caadmin.errorcertrespillegalmsg", responsemessage != null ? responsemessage.getClass()
                        .getName() : "null");
                log.info(msg);
                throw new EjbcaException(msg);
            }
            final Certificate cacert = ((X509ResponseMessage) responsemessage).getCertificate();
            // Recieving a certificate for an internal CA will transform it into an externally signed CA
            if (ca.getSignedBy() != CAInfo.SIGNEDBYEXTERNALCA) {
                ca.setSignedBy(CAInfo.SIGNEDBYEXTERNALCA);
            }
            // Check that CA DN is equal to the certificate response.
            if (!CertTools.getSubjectDN(cacert).equals(CertTools.stringToBCDNString(ca.getSubjectDN()))) {
                String msg = intres.getLocalizedMessage("caadmin.errorcertrespwrongdn", CertTools.getSubjectDN(cacert), ca.getSubjectDN());
                log.info(msg);
                throw new EjbcaException(msg);
            }
            List<Certificate> tmpchain = new ArrayList<Certificate>();
            tmpchain.add(cacert);
            // If we have a chain given as parameter, we will use that.
            // If no parameter is given we assume that the request chain was stored when the request was created.
            Collection<Certificate> reqchain = null;
            if (cachain!=null && cachain.size()>0) {
                reqchain = CertTools.createCertChain(cachain);
                log.debug("Using CA certificate chain from parameter of size: " + reqchain.size());
            } else {
                reqchain = ca.getRequestCertificateChain();
                log.debug("Using pre-stored CA certificate chain.");
                if (reqchain == null) {
                    String msg = intres.getLocalizedMessage("caadmin.errornorequestchain", caid, ca.getSubjectDN());
                    log.info(msg);
                    throw new CertPathValidatorException(msg);
                }
            }
            log.debug("Picked up request certificate chain of size: " + reqchain.size());
            tmpchain.addAll(reqchain);
            final List<Certificate> chain = CertTools.createCertChain(tmpchain);
            log.debug("Storing certificate chain of size: " + chain.size());
            // Before importing the certificate we want to make sure that the public key matches the CAs private key
            PublicKey caCertPublicKey = cacert.getPublicKey();
            // If it is a DV certificate signed by a CVCA, enrich the public key for EC parameters from the CVCA's certificate
            if (StringUtils.equals(cacert.getType(), "CVC")) {
                if (caCertPublicKey.getAlgorithm().equals("ECDSA")) {
                    CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cacert;
                    try {
                        if ((cvccert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole() == AuthorizationRoleEnum.DV_D)
                                || (cvccert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole() == AuthorizationRoleEnum.DV_F)) {
                            log.debug("Enriching DV public key with EC parameters from CVCA");
                            Certificate cvcacert = (Certificate) reqchain.iterator().next();
                            caCertPublicKey = KeyTools.getECPublicKeyWithParams(caCertPublicKey, cvcacert.getPublicKey());
                        }
                    } catch (InvalidKeySpecException e) {
                        log.debug("Strange CVCA certificate that we can't get the key from, continuing anyway...", e);
                    } catch (NoSuchFieldException e) {
                        log.debug("Strange DV certificate with no AutheorizationRole, continuing anyway...", e);
                    }
                } else {
                    log.debug("Key is not ECDSA, don't try to enrich with EC parameters.");
                }
            } else {
                log.debug("Cert is not CVC, no need to enrich with EC parameters.");
            }

            final CAToken catoken = ca.getCAToken();
            final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(catoken.getCryptoTokenId());
            boolean activatedNextSignKey = false;
            if (nextKeyAlias != null) {
                try {
                    if (log.isDebugEnabled()) {
                        log.debug("SubjectKeyId for CA cert public key: " + new String(Hex.encode(KeyTools.createSubjectKeyId(caCertPublicKey).getKeyIdentifier())));
                        log.debug("SubjectKeyId for CA next public key: " + new String(Hex.encode(KeyTools.createSubjectKeyId(cryptoToken.getPublicKey(nextKeyAlias)).getKeyIdentifier())));
                    }
                    KeyTools.testKey(cryptoToken.getPrivateKey(nextKeyAlias), caCertPublicKey, cryptoToken.getSignProviderName());
                } catch (InvalidKeyException e) {
                    throw new EjbcaException(ErrorCode.INVALID_KEY, e);
                }
                catoken.setNextCertSignKey(nextKeyAlias);
                catoken.activateNextSignKey();
                activatedNextSignKey = true;
            } else {
                // Since we don't specified the nextSignKey, we will just try the current or next CA sign key
                try {
                    KeyTools.testKey(cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)), caCertPublicKey, cryptoToken.getSignProviderName());
                } catch (Exception e1) {
                    log.debug("The received certificate response does not match the CAs private signing key for purpose CAKEYPURPOSE_CERTSIGN, trying CAKEYPURPOSE_CERTSIGN_NEXT...");
                    if (e1 instanceof InvalidKeyException) {
                        log.trace(e1);
                    } else {
                        // If it's not invalid key, we want to see more of the error
                        log.debug("Error: ", e1);
                    }
                    try {
                        KeyTools.testKey(cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT)), caCertPublicKey, cryptoToken
                                .getSignProviderName());
                        // This was OK, so we must also activate the next signing key when importing this certificate
                        catoken.activateNextSignKey();
                        activatedNextSignKey = true;
                    } catch (Exception e2) {
                        log.debug("The received certificate response does not match the CAs private signing key for purpose CAKEYPURPOSE_CERTSIGN_NEXT either, giving up.");
                        if ((e2 instanceof InvalidKeyException) || (e2 instanceof IllegalArgumentException)) {
                            log.trace(e2);
                        } else {
                            // If it's not invalid key or missing authentication code, we want to see more of the error
                            log.debug("Error: ", e2);
                        }
                        throw new EjbcaException(ErrorCode.INVALID_KEY, e2);
                    }
                }
            }
            if (activatedNextSignKey) {
                // Activated the next signing key(s) so generate audit log
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", intres.getLocalizedMessage("catoken.activatednextkey", caid));
                details.put("certSignKey", catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
                details.put("crlSignKey", catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CRLSIGN));
                details.put("sequence", catoken.getKeySequence());
                auditSession.log(EventTypes.CA_KEYACTIVATE, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(), String.valueOf(caid), null, null, details);
            }
            ca.setCAToken(catoken);
            ca.setCertificateChain(chain);

            // Set status to active, so we can sign certificates for the external services below.
            ca.setStatus(CAConstants.CA_ACTIVE);

            // activate External CA Services
            for (int type : ca.getExternalCAServiceTypes()) {
                try {
                    ca.initExtendedService(cryptoToken, type, ca);
                    final List<Certificate> extcacertificate = new ArrayList<Certificate>();
                    final ExtendedCAServiceInfo info = ca.getExtendedCAServiceInfo(type);
                    if (type == ExtendedCAServiceTypes.TYPE_OCSPEXTENDEDSERVICE) {
                        // The OCSP certificate is the same as the certificate singing certificate
                    }
                    if (type == ExtendedCAServiceTypes.TYPE_XKMSEXTENDEDSERVICE) {
                        extcacertificate.add(((XKMSCAServiceInfo) info).getXKMSSignerCertificatePath().get(0));
                    }
                    if (type == ExtendedCAServiceTypes.TYPE_CMSEXTENDEDSERVICE) {
                        extcacertificate.add(((CmsCAServiceInfo) info).getCertificatePath().get(0));
                    }
                    // Publish the extended service certificate, but only for active services
                    if ((info != null) && (info.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE) && (!extcacertificate.isEmpty())) {
                        publishCACertificate(authenticationToken, extcacertificate, ca.getCRLPublishers(), ca.getSubjectDN());
                    }
                } catch (Exception fe) {
                    final String detailsMsg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", Integer.valueOf(caid));
                    auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                            String.valueOf(caid), null, null, detailsMsg);
                    throw new EJBException(fe);
                }
            }
            // Set expire time
            ca.setExpireTime(CertTools.getNotAfter(cacert));
            // Save CA
            caSession.editCA(authenticationToken, ca, true);
            // Publish CA Certificate
            publishCACertificate(authenticationToken, chain, ca.getCRLPublishers(), ca.getSubjectDN());
            // Create initial CRL
            crlCreateSession.forceCRL(authenticationToken, caid);
            crlCreateSession.forceDeltaCRL(authenticationToken, caid);
            // All OK
            String detailsMsg = intres.getLocalizedMessage("caadmin.certrespreceived", Integer.valueOf(caid));
            auditSession.log(EventTypes.CA_EDITING, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
        } catch (CryptoTokenOfflineException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
            log.info(msg);
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (CADoesntExistsException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
            log.info(msg);
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (IllegalCryptoTokenException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
            log.info(msg);
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (CertificateEncodingException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
            log.info(msg);
            throw new EjbcaException(e.getMessage());
        } catch (CertificateException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
            log.info(msg);
            throw new EjbcaException(e.getMessage());
        } catch (InvalidAlgorithmParameterException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
            log.info(msg);
            throw new EjbcaException(e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
            log.info(msg);
            throw new EjbcaException(e.getMessage());
        } catch (NoSuchProviderException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
            log.info(msg);
            throw new EjbcaException(e.getMessage());
        }
        if (log.isTraceEnabled()) {
        	log.trace("<receiveResponse: " + caid);
        }
    }

    @Override
    public ResponseMessage processRequest(AuthenticationToken admin, CAInfo cainfo, RequestMessage requestmessage) throws CAExistsException,
            CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException {
        final CA ca;
        Collection<Certificate> certchain = null;
        CertificateResponseMessage returnval = null;
        int caid = cainfo.getCAId();
        // check authorization
        if (!accessSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource())) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtocertresp", cainfo.getName());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw new AuthorizationDeniedException(msg);
        }

        // Check that CA doesn't already exists
        CAData oldcadata = null;
        if (caid >= 0 && caid <= CAInfo.SPECIALCAIDBORDER) {
            String msg = intres.getLocalizedMessage("caadmin.errorcaexists", cainfo.getName());
            log.info(msg);
            throw new CAExistsException(msg);
        }
        oldcadata = CAData.findById(entityManager, Integer.valueOf(caid));
        // If it did not exist with a certain DN (caid) perhaps a CA with the
        // same CA name exists?
        if (oldcadata == null) {
            oldcadata = CAData.findByName(entityManager, cainfo.getName());
        }
        boolean processinternalca = false;
        if (oldcadata != null) {
            // If we find an already existing CA, there is a good chance that we
            // should throw an exception
            // Saying that the CA already exists.
            // However, if we have the same DN, and give the same name, we
            // simply assume that the admin actually wants
            // to treat an internal CA as an external CA, perhaps there is
            // different HSMs connected for root CA and sub CA?
            if (log.isDebugEnabled()) {
                log.debug("Old castatus=" + oldcadata.getStatus() + ", oldcaid=" + oldcadata.getCaId().intValue() + ", caid=" + cainfo.getCAId()
                        + ", oldcaname=" + oldcadata.getName() + ", name=" + cainfo.getName());
            }
            if (((oldcadata.getStatus() == CAConstants.CA_WAITING_CERTIFICATE_RESPONSE) || (oldcadata.getStatus() == CAConstants.CA_ACTIVE) || (oldcadata
                    .getStatus() == CAConstants.CA_EXTERNAL))
                    && (oldcadata.getCaId().intValue() == cainfo.getCAId())
                    && (oldcadata.getName().equals(cainfo.getName()))) {
                // Yes, we have all the same DN, CAName and the old CA is either
                // waiting for a certificate response or is active
                // (new CA or active CA that we want to renew)
                // or it is an external CA that we want to issue a new
                // certificate to
                processinternalca = true;
                if (oldcadata.getStatus() == CAConstants.CA_EXTERNAL) {
                    log.debug("Renewing an external CA.");
                } else {
                    log.debug("Processing an internal CA, as an external.");
                }
            } else {
                String msg = intres.getLocalizedMessage("caadmin.errorcaexists", cainfo.getName());
                log.info(msg);
                throw new CAExistsException(msg);
            }
        }

        // get signing CA
        if (cainfo.getSignedBy() > CAInfo.SPECIALCAIDBORDER || cainfo.getSignedBy() < 0) {
            try {
                final CA signca = caSession.getCAForEdit(admin, Integer.valueOf(cainfo.getSignedBy()));
                try {
                    // Check that the signer is valid
                    assertSignerValidity(admin, signca);

                    // Get public key from request
                    PublicKey publickey = requestmessage.getRequestPublicKey();

                    // Create cacertificate
                    Certificate cacertificate = null;
                    String subjectAltName = null;
                    if (cainfo instanceof X509CAInfo) {
                        subjectAltName = ((X509CAInfo) cainfo).getSubjectAltName();
                    }
                    EndEntityInformation cadata = new EndEntityInformation("nobody", cainfo.getSubjectDN(), cainfo.getSubjectDN().hashCode(),
                            subjectAltName, null, 0, new EndEntityType(EndEntityTypes.INVALID), 0, cainfo.getCertificateProfileId(), null, null, 0, 0, null);
                    // We can pass the PKCS10 request message as extra
                    // parameters
                    if (requestmessage instanceof PKCS10RequestMessage) {
                        ExtendedInformation extInfo = new ExtendedInformation();
                        PKCS10CertificationRequest pkcs10 = ((PKCS10RequestMessage) requestmessage).getCertificationRequest();
                        extInfo.setCustomData(ExtendedInformationFields.CUSTOM_PKCS10, new String(Base64.encode(pkcs10.getEncoded())));
                        cadata.setExtendedinformation(extInfo);
                    }
                    CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(cainfo.getCertificateProfileId());
                    String sequence = null;
                    byte[] ki = requestmessage.getRequestKeyInfo();
                    if ((ki != null) && (ki.length > 0)) {
                        sequence = new String(ki);
                    }
                    final CryptoToken signCryptoToken = cryptoTokenSession.getCryptoToken(signca.getCAToken().getCryptoTokenId());
                    cacertificate = signca.generateCertificate(signCryptoToken, cadata, publickey, -1, null, cainfo.getValidity(), certprofile, sequence);
                    // X509ResponseMessage works for both X509 CAs and CVC CAs, should really be called CertificateResponsMessage
                    returnval = new X509ResponseMessage();
                    returnval.setCertificate(cacertificate);

                    // Build Certificate Chain
                    Collection<Certificate> rootcachain = signca.getCertificateChain();
                    certchain = new ArrayList<Certificate>();
                    certchain.add(cacertificate);
                    certchain.addAll(rootcachain);

                    if (!processinternalca) {
                        // If this is an internal CA, we don't create it and set
                        // a NULL token, since the CA is already created
                        if (cainfo instanceof X509CAInfo) {
                            log.info("Creating a X509 CA (process request)");
                            ca = new X509CA((X509CAInfo) cainfo);
                        } else if (cainfo instanceof CVCCAInfo) {
                            // CVC CA is a special type of CA for EAC electronic
                            // passports
                            log.info("Creating a CVC CA (process request)");
                            CVCCAInfo cvccainfo = (CVCCAInfo) cainfo;
                            // Create CVCCA
                            ca = new CVCCA(cvccainfo);
                        } else {
                            ca = null;
                        }
                        ca.setCertificateChain(certchain);
                        CAToken token = new CAToken(ca.getCAId(), new NullCryptoToken().getProperties());
                        ca.setCAToken(token);

                        // set status to active
                        entityManager.persist(new CAData(cainfo.getSubjectDN(), cainfo.getName(), CAConstants.CA_EXTERNAL, ca));
                        // cadatahome.create(cainfo.getSubjectDN(), cainfo.getName(), SecConst.CA_EXTERNAL, ca);
                    } else {
                        if (oldcadata.getStatus() == CAConstants.CA_EXTERNAL) {
                            // If it is an external CA we will not import the
                            // certificate later on here, so we want to
                            // update the CA in this instance with the new
                            // certificate so it is visible
                            ca = caSession.getCAForEdit(admin, oldcadata.getCaId());//getCAFromDatabase(oldcadata.getCaId());
                            ca.setCertificateChain(certchain);
                            if (log.isDebugEnabled()) {
                                log.debug("Storing new certificate chain for external CA " + cainfo.getName() + ", CA token type: "
                                        + ca.getCAToken().getClass().getName());
                            }
                            caSession.editCA(admin, ca, true);
                        } else {
                            // If it is an internal CA so we are "simulating"
                            // signing a real external CA we don't do anything
                            // because that CA is waiting to import a
                            // certificate
                            if (log.isDebugEnabled()) {
                                log.debug("Not storing new certificate chain or updating CA for internal CA, simulating external: "
                                        + cainfo.getName());
                            }
                            ca = null;
                        }
                    }
                    // Publish CA certificates.
                    publishCACertificate(admin, certchain, signca.getCRLPublishers(), ca != null ? ca.getSubjectDN() : null);
                    // External CAs will not have any CRLs in this system, so we don't have to try to publish any CRLs
                } catch (CryptoTokenOfflineException e) {
                    String msg = intres.getLocalizedMessage("caadmin.errorprocess", cainfo.getName());
                    log.error(msg, e);
                    throw e;
                }
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("caadmin.errorprocess", cainfo.getName());
                log.error(msg, e);
                throw new EJBException(e);
            }

        }

        if (certchain != null) {
            String msg = intres.getLocalizedMessage("caadmin.processedca", cainfo.getName());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.CA_EDITING, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
        } else {
            String msg = intres.getLocalizedMessage("caadmin.errorprocess", cainfo.getName());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
        }
        return returnval;
    }

    @Override
    public void importCACertificate(AuthenticationToken admin, String caname, Collection<Certificate> certificates)
            throws AuthorizationDeniedException, CAExistsException, IllegalCryptoTokenException {
        Certificate caCertificate = (Certificate) certificates.iterator().next();
        CA ca = null;
        CAInfo cainfo = null;

        // Parameters common for both X509 and CVC CAs
        ArrayList<Integer> approvalsettings = new ArrayList<Integer>();
        int numofreqapprovals = 1;
        boolean finishuser = false;
        Collection<ExtendedCAServiceInfo> extendedcaserviceinfos = new ArrayList<ExtendedCAServiceInfo>();
        ArrayList<Integer> crlpublishers = new ArrayList<Integer>();
        long crlperiod = 0 * SimpleTime.MILLISECONDS_PER_HOUR;
        long crlIssueInterval = 0 * SimpleTime.MILLISECONDS_PER_HOUR;
        long crlOverlapTime = 10 * SimpleTime.MILLISECONDS_PER_MINUTE;
        long deltacrlperiod = 0 * SimpleTime.MILLISECONDS_PER_HOUR;
        int certprofileid = CertTools.isSelfSigned(caCertificate) ?
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA :
                CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA;
        String subjectdn = CertTools.getSubjectDN(caCertificate);
        long validity = 0;
        int signedby = CertTools.isSelfSigned(caCertificate) ? CAInfo.SELFSIGNED : CAInfo.SIGNEDBYEXTERNALCA;
        String description = "CA created by certificate import.";
        log.info("Preparing to import of CA with Subject DN " + subjectdn);

        if (caCertificate instanceof X509Certificate) {
            X509Certificate x509CaCertificate = (X509Certificate) caCertificate;
            String subjectaltname = CertTools.getSubjectAlternativeName(x509CaCertificate);

            // Process certificate policies.
            ArrayList<CertificatePolicy> policies = new ArrayList<CertificatePolicy>();
            CertificateProfile certprof = certificateProfileSession.getCertificateProfile(certprofileid);
            if (certprof.getCertificatePolicies() != null && certprof.getCertificatePolicies().size() > 0) {
                policies.addAll(certprof.getCertificatePolicies());
            }

            boolean useauthoritykeyidentifier = false;
            boolean authoritykeyidentifiercritical = false;

            boolean usecrlnumber = false;
            boolean crlnumbercritical = false;

            boolean useutf8policytext = false;
            boolean useprintablestringsubjectdn = false;
            boolean useldapdnorder = true; // Default value
            boolean usecrldistpointoncrl = false;
            boolean crldistpointoncrlcritical = false;

            cainfo = new X509CAInfo(subjectdn, caname, CAConstants.CA_EXTERNAL, new Date(), subjectaltname, certprofileid, validity,
                    CertTools.getNotAfter(x509CaCertificate), CAInfo.CATYPE_X509, signedby, null, null, description, -1, null, policies, crlperiod,
                    crlIssueInterval, crlOverlapTime, deltacrlperiod, crlpublishers, useauthoritykeyidentifier, authoritykeyidentifiercritical,
                    usecrlnumber, crlnumbercritical, "", "", "", null, "", finishuser, extendedcaserviceinfos, useutf8policytext, approvalsettings,
                    numofreqapprovals, useprintablestringsubjectdn, useldapdnorder, usecrldistpointoncrl, crldistpointoncrlcritical, false, true, // isDoEnforceUniquePublicKeys
                    true, // isDoEnforceUniqueDistinguishedName
                    false, // isDoEnforceUniqueSubjectDNSerialnumber
                    true, // useCertReqHistory
                    true, // useUserStorage
                    true, // useCertificateStorage
                    null // cmpRaAuthSecret
            );
        } else if (StringUtils.equals(caCertificate.getType(), "CVC")) {
            cainfo = new CVCCAInfo(subjectdn, caname, CAConstants.CA_EXTERNAL, new Date(), certprofileid, validity, null, CAInfo.CATYPE_CVC, signedby,
                    null, null, description, -1, null, crlperiod, crlIssueInterval, crlOverlapTime, deltacrlperiod, crlpublishers, finishuser,
                    extendedcaserviceinfos, approvalsettings, numofreqapprovals, false, true, // isDoEnforceUniquePublicKeys
                    true, // isDoEnforceUniqueDistinguishedName
                    false, // isDoEnforceUniqueSubjectDNSerialnumber
                    true, // useCertReqHistory
                    true, // useUserStorage
                    true // useCertificateStorage
            );
        }
        if (cainfo instanceof X509CAInfo) {
            log.info("Creating a X509 CA (process request)");
            ca = new X509CA((X509CAInfo) cainfo);
        } else if (cainfo instanceof CVCCAInfo) {
            // CVC CA is a special type of CA for EAC electronic passports
            log.info("Creating a CVC CA (process request)");
            CVCCAInfo cvccainfo = (CVCCAInfo) cainfo;
            ca = new CVCCA(cvccainfo);
        }
        ca.setCertificateChain(certificates);
        CAToken token = new CAToken(ca.getCAId(), new NullCryptoToken().getProperties());
        try {
        	ca.setCAToken(token);
        } catch (InvalidAlgorithmException e) {
        	throw new IllegalCryptoTokenException(e);
        }
        // Add CA
        caSession.addCA(admin, ca);
        // Publish CA certificates.
        publishCACertificate(admin, certificates, null, ca.getSubjectDN());
    }

    @Override
    public void initExternalCAService(AuthenticationToken admin, int caid, ExtendedCAServiceInfo info) throws CADoesntExistsException,
            AuthorizationDeniedException, IllegalCryptoTokenException, CAOfflineException {
        // check authorization
        if (!accessSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource())) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoeditca", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw new AuthorizationDeniedException(msg);
        }

        // Get CA info.
        CA ca = caSession.getCAForEdit(admin, caid);
        if (ca.getStatus() == CAConstants.CA_OFFLINE) {
            String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getName());
            throw new CAOfflineException(msg);
        }
        ArrayList<ExtendedCAServiceInfo> infos = new ArrayList<ExtendedCAServiceInfo>();
        infos.add(info);
        activateAndPublishExternalCAServices(admin, infos, ca);
        // Update CA in database
        caSession.editCA(admin, ca, true);
    }

    @Override
    public void renewCA(AuthenticationToken authenticationToken, int caid, boolean regenerateKeys, Date customNotBefore, final boolean createLinkCertificate) throws CADoesntExistsException,
        AuthorizationDeniedException, CryptoTokenOfflineException {
        final CA ca = caSession.getCAForEdit(authenticationToken, caid);
        final CAToken caToken = ca.getCAToken();
        final Properties oldProperties = caToken.getProperties();
        final String oldSequence = caToken.getKeySequence();
        final String currentSignKeyAlias = caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        String nextSignKeyAlias = currentSignKeyAlias;
        final int cryptoTokenId = caToken.getCryptoTokenId();
        if (regenerateKeys) {
            nextSignKeyAlias = caToken.generateNextSignKeyAlias();
            if (cryptoTokenManagementSession.getKeyPairInfo(authenticationToken, cryptoTokenId, nextSignKeyAlias)==null) {
                // Ok.. No such key..
                try {
                    cryptoTokenManagementSession.createKeyPairWithSameKeySpec(authenticationToken, cryptoTokenId, currentSignKeyAlias, nextSignKeyAlias);
                    // Audit log CA key generation
                    final Map<String, Object> details = new LinkedHashMap<String, Object>();
                    details.put("msg", intres.getLocalizedMessage("catoken.generatedkeys", caid, true, false));
                    details.put("oldproperties", oldProperties);
                    details.put("oldsequence", oldSequence);
                    details.put("properties", caToken.getProperties());
                    details.put("sequence", caToken.getKeySequence());
                    auditSession.log(EventTypes.CA_KEYGEN, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(), String.valueOf(caid), null, null, details);
                    ca.setCAToken(caToken);
                    caSession.editCA(authenticationToken, ca, true);
                } catch (AuthorizationDeniedException e2) {
                    throw e2;
                } catch (CryptoTokenOfflineException e2) {
                    throw e2;
                } catch (Exception e2) {
                    throw new RuntimeException(e2);
                }
            } else {
                log.warn("Key generation request for existing key alias ignored for CA=" + ca.getCAId() + ", CryptoToken=" + cryptoTokenId + " and alias="+nextSignKeyAlias);
            }
        }
        renewCA(authenticationToken, caid, nextSignKeyAlias, customNotBefore, createLinkCertificate);
    }

    @Override
    public void renewCA(final AuthenticationToken authenticationToken, final int caid, final String nextSignKeyAlias, Date customNotBefore, final boolean createLinkCertificate) throws AuthorizationDeniedException, CryptoTokenOfflineException {
        if (log.isTraceEnabled()) {
            log.trace(">CAAdminSession, renewCA(), caid=" + caid);
        }
        Collection<Certificate> cachain = null;
        Certificate cacertificate = null;
        // check authorization
        if (!accessSession.isAuthorizedNoLogging(authenticationToken, AccessRulesConstants.REGULAR_RENEWCA)) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.notauthorizedtorenew", Integer.valueOf(caid));
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
            		String.valueOf(caid), null, null, detailsMsg);
            throw new AuthorizationDeniedException(detailsMsg);
        }
        // Get CA info.
        try {
            CA ca = caSession.getCAForEdit(authenticationToken, caid);
            if (ca.getStatus() == CAConstants.CA_OFFLINE || ca.getCAToken().getTokenStatus(cryptoTokenSession.getCryptoToken(ca.getCAToken().getCryptoTokenId())) == CryptoToken.STATUS_OFFLINE) {
                String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getName());
                throw new CryptoTokenOfflineException(msg);
            }
            if (ca.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA) {
                // We should never get here
                log.error("Directly renewing a CA signed by external can not be done");
                throw new NotSupportedException("Directly renewing a CA signed by external can not be done");
            }
            final CAToken caToken = ca.getCAToken();
            final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(caToken.getCryptoTokenId());
            cryptoToken.testKeyPair(nextSignKeyAlias);
            caToken.setNextCertSignKey(nextSignKeyAlias);
            // Activate the next signing key(s) and generate audit log
            caToken.activateNextSignKey();
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", intres.getLocalizedMessage("catoken.activatednextkey", caid));
            details.put("certSignKey", caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            details.put("crlSignKey", caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CRLSIGN));
            details.put("sequence", caToken.getKeySequence());
            auditSession.log(EventTypes.CA_KEYACTIVATE, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(), String.valueOf(caid), null, null, details);
            // if issuer is insystem CA or selfsigned, then generate new certificate.
            log.info("Renewing CA using " + caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            final PublicKey caPublicKey = cryptoToken.getPublicKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            ca.setCAToken(caToken);
            if (ca.getSignedBy() == CAInfo.SELFSIGNED) {
                // create selfsigned certificate
                String subjectAltName = null;
                if (ca instanceof X509CA) {
                    X509CA x509ca = (X509CA) ca;
                    subjectAltName = x509ca.getSubjectAltName();
                }
                EndEntityInformation cainfodata = new EndEntityInformation("nobody", ca.getSubjectDN(), ca.getSubjectDN().hashCode(),
                        subjectAltName, null, 0, new EndEntityType(EndEntityTypes.INVALID), 0, ca.getCertificateProfileId(), null, null, 0, 0, null);

                CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(ca.getCertificateProfileId());
                // get from CAtoken to make sure it is fresh
                String sequence = caToken.getKeySequence();
                cacertificate = ca.generateCertificate(cryptoToken, cainfodata, caPublicKey, -1, customNotBefore, ca.getValidity(), certprofile, sequence);
                // Build Certificate Chain
                cachain = new ArrayList<Certificate>();
                cachain.add(cacertificate);

            } else {
                // Resign with CA above.
                if (ca.getSignedBy() > CAInfo.SPECIALCAIDBORDER || ca.getSignedBy() < 0) {
                    // Create CA signed by other internal CA.
                    final CA signca = caSession.getCAForEdit(authenticationToken, Integer.valueOf(ca.getSignedBy()));
                    // Check that the signer is valid
                    assertSignerValidity(authenticationToken, signca);
                    // Create cacertificate
                    String subjectAltName = null;
                    if (ca instanceof X509CA) {
                        X509CA x509ca = (X509CA) ca;
                        subjectAltName = x509ca.getSubjectAltName();
                    }
                    EndEntityInformation cainfodata = new EndEntityInformation("nobody", ca.getSubjectDN(), ca.getSubjectDN().hashCode(),
                            subjectAltName, null, 0, new EndEntityType(EndEntityTypes.INVALID), 0, ca.getCertificateProfileId(), null, null, 0, 0, null);

                    CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(ca.getCertificateProfileId());
                    String sequence = caToken.getKeySequence(); // get from CAtoken to make sure it is fresh
                    CryptoToken signCryptoToken = cryptoTokenSession.getCryptoToken(signca.getCAToken().getCryptoTokenId());
                    cacertificate = signca.generateCertificate(signCryptoToken, cainfodata, caPublicKey, -1,
                            customNotBefore, ca.getValidity(), certprofile, sequence);
                    // Build Certificate Chain
                    Collection<Certificate> rootcachain = signca.getCertificateChain();
                    cachain = new ArrayList<Certificate>();
                    cachain.add(cacertificate);
                    cachain.addAll(rootcachain);
                }
            }
            // Set statuses and expire time
            ca.setExpireTime(CertTools.getNotAfter(cacertificate));
            ca.setStatus(CAConstants.CA_ACTIVE);
            // Set the new certificate chain that we have created above
            ca.setCertificateChain(cachain);
            ca.createOrRemoveLinkCertificate(cryptoToken, createLinkCertificate);
            // We need to save all this, audit logging that the CA is changed
            caSession.editCA(authenticationToken, ca, true);

            // Publish the new CA certificate
            publishCACertificate(authenticationToken, cachain, ca.getCRLPublishers(), ca.getSubjectDN());
            crlCreateSession.forceCRL(authenticationToken, caid);
            crlCreateSession.forceDeltaCRL(authenticationToken, caid);
            // Audit log
            final String detailsMsg = intres.getLocalizedMessage("caadmin.renewdca", Integer.valueOf(caid));
            auditSession.log(EjbcaEventTypes.CA_RENEWED, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
            		String.valueOf(caid), null, null, detailsMsg);
        } catch (CryptoTokenOfflineException e) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errorrenewca", Integer.valueOf(caid));
            auditSession.log(EjbcaEventTypes.CA_RENEWED, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
            		String.valueOf(caid), null, null, detailsMsg);
            throw e;
        } catch (Exception e) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errorrenewca", Integer.valueOf(caid));
            auditSession.log(EjbcaEventTypes.CA_RENEWED, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
            		String.valueOf(caid), null, null, detailsMsg);
            throw new EJBException(e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<CAAdminSession, renewCA(), caid=" + caid);
        }
    }
    
    @Override
    public byte[] getLatestLinkCertificate(final int caId) throws CADoesntExistsException {
        try {
            CA ca = caSession.getCANoLog(new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Fetching link certificate user.")), caId);
            return ca.getLatestLinkCertificate();
        } catch (AuthorizationDeniedException e) {
            throw new RuntimeException(e);  // Should always be allowed
        }
    }

    @Override
    public void revokeCA(AuthenticationToken admin, int caid, int reason) throws CADoesntExistsException, AuthorizationDeniedException {
        // check authorization
        if (!accessSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource())) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.notauthorizedtorevoke", Integer.valueOf(caid));
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, detailsMsg);
            throw new AuthorizationDeniedException(detailsMsg);
        }
        // Get CA info.
        CA ca = caSession.getCAForEdit(admin, caid);
        try {
            // Revoke all issued CA certificates for this CA
            Collection<Certificate> cacerts = certificateStoreSession.findCertificatesBySubject(ca.getSubjectDN());
            for (Certificate certificate : cacerts) {
                revocationSession.revokeCertificate(admin, certificate, ca.getCRLPublishers(), reason, ca.getSubjectDN());                
            }
            // Revoke all certificates issued by this CA. If this is a root CA the CA certificates will be included in this batch as well
            // but if this is a subCA these are only the "entity" certificates issued by this CA
            if (ca.getStatus() != CAConstants.CA_EXTERNAL) {
                certificateStoreSession.revokeAllCertByCA(admin, ca.getSubjectDN(), reason);
                Collection<Integer> caids = new ArrayList<Integer>();
                caids.add(Integer.valueOf(ca.getCAId()));
                crlCreateSession.createCRLs(admin, caids, 0);
            }
            ca.setRevocationReason(reason);
            ca.setRevocationDate(new Date());
            if (ca.getStatus() != CAConstants.CA_EXTERNAL) {
                ca.setStatus(CAConstants.CA_REVOKED);
            }
            // Store new status, audit logging
            caSession.editCA(admin, ca, true);
            final String detailsMsg = intres.getLocalizedMessage("caadmin.revokedca", ca.getName(), Integer.valueOf(reason));
            auditSession.log(EjbcaEventTypes.CA_REVOKED, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, detailsMsg);
        } catch (Exception e) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errorrevoke", ca.getName());
            auditSession.log(EjbcaEventTypes.CA_REVOKED, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, detailsMsg);
            throw new EJBException(e);
        }
    }

    @Override
    public void importCAFromKeyStore(AuthenticationToken admin, String caname, byte[] p12file, String keystorepass, String privkeypass,
            String privateSignatureKeyAlias, String privateEncryptionKeyAlias) throws Exception {
        try {
            // check authorization
            if (!accessSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource())) {
                String msg = intres.getLocalizedMessage("caadmin.notauthorizedtocreateca", caname);
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), null, null,
                        null, details);
            }
            // load keystore
            java.security.KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
            keystore.load(new java.io.ByteArrayInputStream(p12file), keystorepass.toCharArray());
            // Extract signature keys
            if (privateSignatureKeyAlias == null || !keystore.isKeyEntry(privateSignatureKeyAlias)) {
                throw new Exception("Alias \"" + privateSignatureKeyAlias + "\" not found.");
            }
            Certificate[] signatureCertChain = KeyTools.getCertChain(keystore, privateSignatureKeyAlias);
            if (signatureCertChain.length < 1) {
                String msg = "Cannot load certificate chain with alias " + privateSignatureKeyAlias;
                log.error(msg);
                throw new Exception(msg);
            }
            Certificate caSignatureCertificate = (Certificate) signatureCertChain[0];
            PublicKey p12PublicSignatureKey = caSignatureCertificate.getPublicKey();
            PrivateKey p12PrivateSignatureKey = null;
            p12PrivateSignatureKey = (PrivateKey) keystore.getKey(privateSignatureKeyAlias, privkeypass.toCharArray());
            log.debug("ImportSignatureKeyAlgorithm=" + p12PrivateSignatureKey.getAlgorithm());

            // Extract encryption keys
            PrivateKey p12PrivateEncryptionKey = null;
            PublicKey p12PublicEncryptionKey = null;
            Certificate caEncryptionCertificate = null;
            if (privateEncryptionKeyAlias != null) {
                if (!keystore.isKeyEntry(privateEncryptionKeyAlias)) {
                    throw new Exception("Alias \"" + privateEncryptionKeyAlias + "\" not found.");
                }
                Certificate[] encryptionCertChain = KeyTools.getCertChain(keystore, privateEncryptionKeyAlias);
                if (encryptionCertChain.length < 1) {
                    String msg = "Cannot load certificate chain with alias " + privateEncryptionKeyAlias;
                    log.error(msg);
                    throw new Exception(msg);
                }
                caEncryptionCertificate = (Certificate) encryptionCertChain[0];
                p12PrivateEncryptionKey = (PrivateKey) keystore.getKey(privateEncryptionKeyAlias, privkeypass.toCharArray());
                p12PublicEncryptionKey = caEncryptionCertificate.getPublicKey();
            }
            importCAFromKeys(admin, caname, keystorepass, signatureCertChain, p12PublicSignatureKey, p12PrivateSignatureKey, p12PrivateEncryptionKey,
                    p12PublicEncryptionKey);
        } catch (Exception e) {
            String detailsMsg = intres.getLocalizedMessage("caadmin.errorimportca", caname, "PKCS12", e.getMessage());
            auditSession.log(EjbcaEventTypes.CA_IMPORT, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), null, null, null,
                    detailsMsg);
            throw new EJBException(e);
        }
    }

    @Override
    public void removeCAKeyStore(AuthenticationToken admin, String caname) throws EJBException {
    	if (log.isTraceEnabled()) {
    		log.trace(">removeCAKeyStore");
    	}
        try {
            // check authorization
            if (!accessSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource())) {
                String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoremovecatoken", caname);
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), null, null,
                        null, details);
            }
            CA ca = caSession.getCAForEdit(admin, caname);
            final CAToken currentCaToken = ca.getCAToken();
            final int cryptoTokenId = currentCaToken.getCryptoTokenId();
            CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(cryptoTokenId);
            if (!(cryptoToken instanceof SoftCryptoToken)) {
                throw new Exception("Cannot export anything but a soft token.");
            }
            cryptoTokenManagementSession.deactivate(admin, cryptoTokenId);
            // Create a new CAToken with the same properties but without the reference to the removed CryptoToken
            cryptoTokenSession.removeCryptoToken(cryptoTokenId);
            final CAToken newCaToken = new CAToken(0, currentCaToken.getProperties());
            newCaToken.setKeySequence(newCaToken.getKeySequence());
            newCaToken.setKeySequenceFormat(newCaToken.getKeySequenceFormat());
            newCaToken.setSignatureAlgorithm(newCaToken.getSignatureAlgorithm());
            newCaToken.setEncryptionAlgorithm(newCaToken.getEncryptionAlgorithm());
            ca.setCAToken(newCaToken);
            // Set this CA to offline, since it cannot be used without a CryptoToken this is probably intended.
            ca.setStatus(CAConstants.CA_OFFLINE);
            // Save to database
            caSession.editCA(admin, ca, false);
            // Log
            final String detailsMsg = intres.getLocalizedMessage("caadmin.removedcakeystore", Integer.valueOf(ca.getCAId()));
            auditSession.log(EjbcaEventTypes.CA_REMOVETOKEN, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(ca.getCAId()), null,
                    null, detailsMsg);
        } catch (Exception e) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errorremovecakeystore", caname, "PKCS12", e.getMessage());
            auditSession.log(EjbcaEventTypes.CA_REMOVETOKEN, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), null, null,
                    null, detailsMsg);
            throw new EJBException(detailsMsg, e);
        }
    	if (log.isTraceEnabled()) {
    		log.trace("<removeCAKeyStore");
    	}
    }

    @Override
    public void restoreCAKeyStore(AuthenticationToken authenticationToken, String caname, byte[] p12file, String keystorepass, String privkeypass,
            String privateSignatureKeyAlias, String privateEncryptionKeyAlias) {
    	if (log.isTraceEnabled()) {
    		log.trace(">restoreCAKeyStore");
    	}
        try {
            // check authorization
            if (!accessSession.isAuthorizedNoLogging(authenticationToken, StandardRules.ROLE_ROOT.resource())) {
                final String detailsMsg = intres.getLocalizedMessage("caadmin.notauthorizedtorestorecatoken", caname);
                auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(), null, null,
                        null, detailsMsg);
            }
            CA thisCa = caSession.getCAForEdit(authenticationToken, caname);
            final CAToken thisCAToken = thisCa.getCAToken();
            CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(thisCAToken.getCryptoTokenId());
            if (cryptoToken != null) {
                throw new Exception("CA already has an existing CryptoToken reference: " + cryptoToken.getId());
            }
            // load keystore from input
            KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
            keystore.load(new ByteArrayInputStream(p12file), keystorepass.toCharArray());
            // Extract signature keys
            if (privateSignatureKeyAlias == null || !keystore.isKeyEntry(privateSignatureKeyAlias)) {
                throw new Exception("Alias \"" + privateSignatureKeyAlias + "\" not found.");
            }
            Certificate[] signatureCertChain = KeyTools.getCertChain(keystore, privateSignatureKeyAlias);
            if (signatureCertChain.length < 1) {
                String msg = "Cannot load certificate chain with alias " + privateSignatureKeyAlias;
                log.error(msg);
                throw new Exception(msg);
            }
            Certificate caSignatureCertificate = (Certificate) signatureCertChain[0];
            PublicKey p12PublicSignatureKey = caSignatureCertificate.getPublicKey();
            PrivateKey p12PrivateSignatureKey = null;
            p12PrivateSignatureKey = (PrivateKey) keystore.getKey(privateSignatureKeyAlias, privkeypass.toCharArray());

            // Extract encryption keys
            PrivateKey p12PrivateEncryptionKey = null;
            PublicKey p12PublicEncryptionKey = null;
            Certificate caEncryptionCertificate = null;
            if (privateEncryptionKeyAlias != null) {
                if (!keystore.isKeyEntry(privateEncryptionKeyAlias)) {
                    throw new Exception("Alias \"" + privateEncryptionKeyAlias + "\" not found.");
                }
                Certificate[] encryptionCertChain = KeyTools.getCertChain(keystore, privateEncryptionKeyAlias);
                if (encryptionCertChain.length < 1) {
                    String msg = "Cannot load certificate chain with alias " + privateEncryptionKeyAlias;
                    log.error(msg);
                    throw new Exception(msg);
                }
                caEncryptionCertificate = (Certificate) encryptionCertChain[0];
                p12PrivateEncryptionKey = (PrivateKey) keystore.getKey(privateEncryptionKeyAlias, privkeypass.toCharArray());
                p12PublicEncryptionKey = caEncryptionCertificate.getPublicKey();
            } else {
                throw new Exception("Missing encryption key");
            }

            // Sign something to see that we are restoring the right private signature key
            String testSigAlg = (String) AlgorithmTools.getSignatureAlgorithms(thisCa.getCACertificate().getPublicKey()).iterator().next();
            if (testSigAlg == null) {
                testSigAlg = "SHA1WithRSA";
            }
            // Sign with imported private key
            byte[] input = "Test data...".getBytes();
            Signature signature = Signature.getInstance(testSigAlg, "BC");
            signature.initSign(p12PrivateSignatureKey);
            signature.update(input);
            byte[] signed = signature.sign();
            // Verify with public key from CA certificate
            signature = Signature.getInstance(testSigAlg, "BC");
            signature.initVerify(thisCa.getCACertificate().getPublicKey());
            signature.update(input);
            if (!signature.verify(signed)) {
                throw new Exception("Could not use private key for verification. Wrong p12-file for this CA?");
            }
            // Import the keys and save to database
            CAToken catoken = importKeysToCAToken(authenticationToken, keystorepass, thisCAToken.getProperties(), p12PrivateSignatureKey,
                    p12PublicSignatureKey, p12PrivateEncryptionKey, p12PublicEncryptionKey, signatureCertChain, thisCa.getCAId());
            thisCa.setCAToken(catoken);
            // Finally save the CA
            caSession.editCA(authenticationToken, thisCa, true);
            // Log
            final String detailsMsg = intres.getLocalizedMessage("caadmin.restoredcakeystore", Integer.valueOf(thisCa.getCAId()));
            auditSession.log(EjbcaEventTypes.CA_RESTORETOKEN, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(), String.valueOf(thisCa.getCAId()), null,
                    null, detailsMsg);
        } catch (Exception e) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errorrestorecakeystore", caname, "PKCS12", e.getMessage());
            auditSession.log(EjbcaEventTypes.CA_RESTORETOKEN, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(), null, null,
                    null, detailsMsg);
            throw new EJBException(e);
        }
    	if (log.isTraceEnabled()) {
    		log.trace("<restoreCAKeyStore");
    	}        
    }

    @Override
    public void importCAFromKeys(AuthenticationToken authenticationToken, String caname, String keystorepass, Certificate[] signatureCertChain,
            PublicKey p12PublicSignatureKey, PrivateKey p12PrivateSignatureKey, PrivateKey p12PrivateEncryptionKey, PublicKey p12PublicEncryptionKey)
            throws CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException, IllegalCryptoTokenException, CADoesntExistsException,
            AuthorizationDeniedException, CAExistsException {
        // Transform into token
        int caId = StringTools.strip(CertTools.getSubjectDN(signatureCertChain[0])).hashCode(); // caid
        CAToken catoken = null;
        try {
            catoken = importKeysToCAToken(authenticationToken, keystorepass, null, p12PrivateSignatureKey, p12PublicSignatureKey, p12PrivateEncryptionKey,
                    p12PublicEncryptionKey, signatureCertChain, caId);
        } catch (OperatorCreationException e) {
            log.error(e.getLocalizedMessage(), e);
            throw new EJBException(e);
        }
        log.debug("CA-Info: " + catoken.getSignatureAlgorithm() + " " + catoken.getEncryptionAlgorithm());
        // Identify the key algorithms for extended CA services, OCSP, XKMS, CMS
        String keyAlgorithm = AlgorithmTools.getKeyAlgorithm(p12PublicSignatureKey);
        String keySpecification = AlgorithmTools.getKeySpecification(p12PublicSignatureKey);
        if (keyAlgorithm == null || keyAlgorithm == AlgorithmConstants.KEYALGORITHM_RSA) {
            keyAlgorithm = AlgorithmConstants.KEYALGORITHM_RSA;
            keySpecification = "2048";
        }
        // Do the general import
        CA ca = importCA(authenticationToken, caname, keystorepass, signatureCertChain, catoken, keyAlgorithm, keySpecification);
        // Finally audit log
        String msg = intres.getLocalizedMessage("caadmin.importedca", caname, "PKCS12", ca.getStatus());
        Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        auditSession.log(EjbcaEventTypes.CA_IMPORT, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(), String.valueOf(ca.getCAId()), null, null,
                details);
    }

    /**
     * Method that import CA token keys from a P12 file. Was originally used when upgrading from old EJBCA versions. Only supports SHA1 and SHA256
     * with RSA or ECDSA and SHA1 with DSA.
     * @throws OperatorCreationException 
     * @throws AuthorizationDeniedException 
     */
    private CAToken importKeysToCAToken(AuthenticationToken authenticationToken, String authenticationCode, Properties caTokenProperties, PrivateKey privatekey, PublicKey publickey,
            PrivateKey privateEncryptionKey, PublicKey publicEncryptionKey, Certificate[] caSignatureCertChain, int caId)
            throws CryptoTokenAuthenticationFailedException, IllegalCryptoTokenException, OperatorCreationException, AuthorizationDeniedException {
        // If we don't give an authentication code, perhaps we have autoactivation enabled
        if (StringUtils.isEmpty(authenticationCode)) {
            String msg = intres.getLocalizedMessage("token.authcodemissing", Integer.valueOf(caId));
            log.info(msg);
            throw new CryptoTokenAuthenticationFailedException(msg);
        }
        if (caTokenProperties==null) {
            caTokenProperties = new Properties();
        }
        
        try {
            // Currently only RSA keys are supported
            KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
            keystore.load(null, null);

            // The CAs certificate is first in chain
            Certificate cacert = caSignatureCertChain[0];
            // Assume that the same hash algorithm is used for signing that was used to sign this CA cert
            String signatureAlgorithm = AlgorithmTools.getSignatureAlgorithm(cacert);
            String keyAlg = AlgorithmTools.getKeyAlgorithm(publickey);
            if (keyAlg == null) {
                throw new IllegalCryptoTokenException("Unknown public key type: " + publickey.getAlgorithm() + " (" + publickey.getClass() + ")");
            }

            // import sign keys.
            final Certificate[] certchain = new Certificate[1];
            certchain[0] = CertTools.genSelfCert("CN=dummy", 36500, null, privatekey, publickey, signatureAlgorithm, true);

            keystore.setKeyEntry(CAToken.SOFTPRIVATESIGNKEYALIAS, privatekey, null, certchain);

            // generate enc keys.
            // Encryption keys must be RSA still
            final String encryptionAlgorithm = AlgorithmTools.getEncSigAlgFromSigAlg(signatureAlgorithm);
            keyAlg = AlgorithmTools.getKeyAlgorithmFromSigAlg(encryptionAlgorithm);
            final String enckeyspec = "2048";
            KeyPair enckeys = null;
            if (publicEncryptionKey == null || privateEncryptionKey == null) {
                enckeys = KeyTools.genKeys(enckeyspec, keyAlg);
            } else {
                enckeys = new KeyPair(publicEncryptionKey, privateEncryptionKey);
            }
            // generate dummy certificate
            certchain[0] = CertTools.genSelfCert("CN=dummy2", 36500, null, enckeys.getPrivate(), enckeys.getPublic(), encryptionAlgorithm, true);
            keystore.setKeyEntry(CAToken.SOFTPRIVATEDECKEYALIAS, enckeys.getPrivate(), null, certchain);

            // Set the token properties
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);

            // Write the keystore to byte[] that we can feed to crypto token factory
            final char[] authCode = authenticationCode.toCharArray();
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            keystore.store(baos, authCode);

            // Now we have the PKCS12 keystore, from this we can create the CAToken
            final Properties cryptoTokenProperties = new Properties();
            final int cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(authenticationToken, "ImportedCryptoToken"+caId, SoftCryptoToken.class.getName(), cryptoTokenProperties,
                    baos.toByteArray(), authCode);
            final CAToken catoken = new CAToken(cryptoTokenId, caTokenProperties);
            // If this is a CVC CA we need to find out the sequence
            String sequence = CAToken.DEFAULT_KEYSEQUENCE;
            if (cacert instanceof CardVerifiableCertificate) {
                CardVerifiableCertificate cvccacert = (CardVerifiableCertificate) cacert;
                log.debug("Getting sequence from holderRef in CV certificate.");
                try {
                    sequence = cvccacert.getCVCertificate().getCertificateBody().getHolderReference().getSequence();
                } catch (NoSuchFieldException e) {
                    log.error("Can not get sequence from holderRef in CV certificate, using default sequence.");
                }
            }
            log.debug("Setting sequence " + sequence);
            catoken.setKeySequence(sequence);
            log.debug("Setting default sequence format " + StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
            catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
            catoken.setSignatureAlgorithm(signatureAlgorithm);
            catoken.setEncryptionAlgorithm(encryptionAlgorithm);
            return catoken;
        } catch (KeyStoreException e) {
            throw new IllegalCryptoTokenException(e);
        } catch (NoSuchProviderException e) {
            throw new IllegalCryptoTokenException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalCryptoTokenException(e);
        } catch (CertificateException e) {
            throw new IllegalCryptoTokenException(e);
        } catch (IOException e) {
            throw new IllegalCryptoTokenException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalCryptoTokenException(e);
        } catch (SignatureException e) {
            throw new IllegalCryptoTokenException(e);
        } catch (IllegalStateException e) {
            throw new IllegalCryptoTokenException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalCryptoTokenException(e);
        } catch (CryptoTokenOfflineException e) {
            throw new IllegalCryptoTokenException(e);
        }
    } // importKeys

    @Override
    public void importCAFromHSM(AuthenticationToken authenticationToken, String caname, Certificate[] signatureCertChain, String catokenpassword,
            String catokenclasspath, String catokenproperties) throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            IllegalCryptoTokenException, CADoesntExistsException, AuthorizationDeniedException, CAExistsException {
        Certificate cacert = signatureCertChain[0];
        int caId = StringTools.strip(CertTools.getSubjectDN(cacert)).hashCode();
        // Just convert string properties in a standard way...
        Properties caTokenProperties = new Properties();
        if (catokenproperties != null) {
            try {
                caTokenProperties.load(new ByteArrayInputStream(catokenproperties.getBytes()));
            } catch (IOException e) {
                log.warn("Unexpected potential problem.", e);
            }
        }
        // Create the CryptoToken
        final int cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(authenticationToken, "ImportedCryptoToken"+caId, PKCS11CryptoToken.class.getName(),
                caTokenProperties, null, catokenpassword.toCharArray());
        final CAToken catoken = new CAToken(cryptoTokenId, caTokenProperties);
        // Set a lot of properties on the crypto token

        // If this is a CVC CA we need to find out the sequence
        String signatureAlgorithm = AlgorithmTools.getSignatureAlgorithm(cacert);
        String sequence = CAToken.DEFAULT_KEYSEQUENCE;
        if (cacert instanceof CardVerifiableCertificate) {
            CardVerifiableCertificate cvccacert = (CardVerifiableCertificate) cacert;
            log.debug("Getting sequence from holderRef in CV certificate.");
            try {
                sequence = cvccacert.getCVCertificate().getCertificateBody().getHolderReference().getSequence();
            } catch (NoSuchFieldException e) {
                log.error("Can not get sequence from holderRef in CV certificate, using default sequence.");
            }
        }
        log.debug("Setting sequence " + sequence);
        catoken.setKeySequence(sequence);
        log.debug("Setting default sequence format " + StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        catoken.setSignatureAlgorithm(signatureAlgorithm);
        // Encryption keys must be RSA still
        String encryptionAlgorithm = AlgorithmTools.getEncSigAlgFromSigAlg(signatureAlgorithm);
        catoken.setEncryptionAlgorithm(encryptionAlgorithm);
        // Identify the key algorithms for extended CA services, OCSP, XKMS, CMS
        String keyAlgorithm = AlgorithmTools.getKeyAlgorithm(cacert.getPublicKey());
        String keySpecification = AlgorithmTools.getKeySpecification(cacert.getPublicKey());
        if (keyAlgorithm == null || keyAlgorithm == AlgorithmConstants.KEYALGORITHM_RSA) {
            keyAlgorithm = AlgorithmConstants.KEYALGORITHM_RSA;
            keySpecification = "2048";
        }
        // Do the general import
        importCA(authenticationToken, caname, catokenpassword, signatureCertChain, catoken, keyAlgorithm, keySpecification);
    }

    /**
     * @param keyAlgorithm keyalgorithm for extended CA services, OCSP, XKMS, CMS. Example AlgorithmConstants.KEYALGORITHM_RSA
     * @param keySpecification keyspecification for extended CA services, OCSP, XKMS, CMS. Example 2048
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException if superCA does not exist
     * @throws CAExistsException if the CA already exists
     */
    private CA importCA(AuthenticationToken admin, String caname, String keystorepass, Certificate[] signatureCertChain, CAToken catoken,
            String keyAlgorithm, String keySpecification) throws CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException,
            IllegalCryptoTokenException, AuthorizationDeniedException, CADoesntExistsException, CAExistsException {
        // Create a new CA
        int signedby = CAInfo.SIGNEDBYEXTERNALCA;
        int certprof = CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA;
        String description = "Imported external signed CA";
        Certificate caSignatureCertificate = signatureCertChain[0];
        ArrayList<Certificate> certificatechain = new ArrayList<Certificate>();
        for (int i = 0; i < signatureCertChain.length; i++) {
            certificatechain.add(signatureCertChain[i]);
        }
        if (signatureCertChain.length == 1) {
            if (verifyIssuer(caSignatureCertificate, caSignatureCertificate)) {
                signedby = CAInfo.SELFSIGNED;
                certprof = CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA;
                description = "Imported root CA";
            } else {
                // A less strict strategy can be to assume certificate signed
                // by an external CA. Useful if admin user forgot to create a
                // full certificate chain in PKCS#12 package.
                log.error("Cannot import CA " + CertTools.getSubjectDN(caSignatureCertificate) + ": certificate "
                        + CertTools.getSerialNumberAsString(caSignatureCertificate) + " is not self-signed.");
                throw new IllegalCryptoTokenException("Cannot import CA " + CertTools.getSubjectDN(caSignatureCertificate)
                        + ": certificate is not self-signed. Check " + "certificate chain in PKCS#12");
            }
        } else if (signatureCertChain.length > 1) {
            Collection<Integer> cas = caSession.getAvailableCAs();
            Iterator<Integer> iter = cas.iterator();
            // Assuming certificate chain in forward direction (from target
            // to most-trusted CA). Multiple CA chains can contains the
            // issuer certificate; so only the chain where target certificate
            // is the issuer will be selected.
            while (iter.hasNext()) {
                int caid = iter.next().intValue();
                CAInfo superCaInfo = caSession.getCAInfo(admin, caid);
                Iterator<Certificate> i = superCaInfo.getCertificateChain().iterator();
                if (i.hasNext()) {
                    Certificate superCaCert = i.next();
                    if (verifyIssuer(caSignatureCertificate, superCaCert)) {
                        signedby = caid;
                        description = "Imported sub CA";
                        break;
                    }
                }
            }
        }

        CAInfo cainfo = null;
        CA ca = null;
        int validity = (int) ((CertTools.getNotAfter(caSignatureCertificate).getTime() - CertTools.getNotBefore(caSignatureCertificate).getTime()) / (24 * 3600 * 1000));
        ArrayList<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        ArrayList<Integer> approvalsettings = new ArrayList<Integer>();
        ArrayList<Integer> crlpublishers = new ArrayList<Integer>();
        if (caSignatureCertificate instanceof X509Certificate) {
            // Create an X509CA
            // Create and active extended CA Services (OCSP, XKMS, CMS).
            extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
            // Create and active XKMS CA Service.
            extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, "CN=XKMSCertificate, "
                    + CertTools.getSubjectDN(caSignatureCertificate), "", keySpecification, keyAlgorithm));
            // Create and active CMS CA Service.
            extendedcaservices.add(new CmsCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, "CN=CMSCertificate, "
                    + CertTools.getSubjectDN(caSignatureCertificate), "", keySpecification, keyAlgorithm));

            cainfo = new X509CAInfo(CertTools.getSubjectDN(caSignatureCertificate), caname, CAConstants.CA_ACTIVE, new Date(), "", certprof, validity,
                    CertTools.getNotAfter(caSignatureCertificate), // Expiretime
                    CAInfo.CATYPE_X509, signedby, certificatechain, catoken, description, -1, // revocationReason
                    null, // revocationDate
                    null, // PolicyId
                    24 * SimpleTime.MILLISECONDS_PER_HOUR, // CRLPeriod
                    0 * SimpleTime.MILLISECONDS_PER_HOUR, // CRLIssuePeriod
                    10 * SimpleTime.MILLISECONDS_PER_MINUTE, // CRLOverlapTime
                    0 * SimpleTime.MILLISECONDS_PER_HOUR, // DeltaCRLPeriod
                    crlpublishers, // CRL publishers
                    true, // Authority Key Identifier
                    false, // Authority Key Identifier Critical
                    true, // CRL Number
                    false, // CRL Number Critical
                    "", // Default CRL Dist Point
                    "", // Default CRL Issuer
                    "", // Default OCSP Service Locator
                    null,  //Authority Information Access
                    "", // CA defined freshest CRL
                    true, // Finish User
                    extendedcaservices, false, // use default utf8 settings
                    approvalsettings, // Approvals Settings
                    1, // Number of Req approvals
                    false, // Use UTF8 subject DN by default
                    true, // Use LDAP DN order by default
                    false, // Use CRL Distribution Point on CRL
                    false, // CRL Distribution Point on CRL critical,
                    true, // Include in HealthCheck
                    true, // isDoEnforceUniquePublicKeys
                    true, // isDoEnforceUniqueDistinguishedName
                    false, // isDoEnforceUniqueSubjectDNSerialnumber
                    true, // useCertReqHistory
                    true, // useUserStorage
                    true, // useCertificateStorage
                    null // cmpRaAuthSecret
            );
            ca = new X509CA((X509CAInfo) cainfo);
        } else if (caSignatureCertificate.getType().equals("CVC")) {
            // Create a CVC CA
            // Create the CAInfo to be used for either generating the whole CA
            // or making a request
            cainfo = new CVCCAInfo(CertTools.getSubjectDN(caSignatureCertificate), caname, CAConstants.CA_ACTIVE, new Date(), certprof, validity,
                    CertTools.getNotAfter(caSignatureCertificate), CAInfo.CATYPE_CVC, signedby, certificatechain, catoken,
                    description, -1, (Date) null, 24, 0, 10, 0, // CRL periods
                    crlpublishers, // CRL publishers
                    true, // Finish user
                    extendedcaservices, approvalsettings, // Approvals Settings
                    1, // Number of Req approvals
                    true, // Include in HealthCheck
                    true, // isDoEnforceUniquePublicKeys
                    true, // isDoEnforceUniqueDistinguishedName
                    false, // isDoEnforceUniqueSubjectDNSerialnumber
                    true, // useCertReqHistory
                    true, // useUserStorage
                    true // useCertificateStorage
            );
            ca = new CVCCA((CVCCAInfo) cainfo);
        }
        // We must activate the token, in case it does not have the default password
        final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(catoken.getCryptoTokenId());
        cryptoToken.activate(keystorepass.toCharArray());
        try {
        	ca.setCAToken(catoken);
        } catch (InvalidAlgorithmException e) {
        	throw new IllegalCryptoTokenException(e);
        }
        ca.setCertificateChain(certificatechain);
        log.debug("CA-Info: " + catoken.getSignatureAlgorithm() + " " + ca.getCAToken().getEncryptionAlgorithm());
        // Publish CA certificates.
        publishCACertificate(admin, ca.getCertificateChain(), ca.getCRLPublishers(), ca.getSubjectDN());
        // activate External CA Services
        activateAndPublishExternalCAServices(admin, cainfo.getExtendedCAServiceInfos(), ca);
        // Store CA in database.
        caSession.addCA(admin, ca);

        // Create initial CRLs
        Collection<Integer> caids = new ArrayList<Integer>();
        caids.add(ca.getCAId());
        crlCreateSession.createCRLs(admin, caids, 0);
        crlCreateSession.createDeltaCRLs(admin, caids, 0);
        return ca;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public byte[] exportCAKeyStore(AuthenticationToken admin, String caname, String keystorepass, String privkeypass,
            String privateSignatureKeyAlias, String privateEncryptionKeyAlias) throws Exception {
        log.trace(">exportCAKeyStore");
        try {
            final CA thisCa = caSession.getCAForEdit(admin, caname);
            // Make sure we are not trying to export a hard or invalid token
            CAToken thisCAToken = thisCa.getCAToken();
            final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(thisCAToken.getCryptoTokenId());
            if (!(cryptoToken instanceof SoftCryptoToken)) {
                throw new IllegalCryptoTokenException("Cannot export anything but a soft token.");
            }
            // Check authorization
            if (!accessSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource())) {
                String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoexportcatoken", caname);
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(thisCa.getCAId()), null,
                        null, details);
                throw new AuthorizationDeniedException(msg);
            }
            // Fetch keys
            // This is a way of verifying the password. If activate fails, we
            // will get an exception and the export will not proceed
            cryptoToken.activate(keystorepass.toCharArray());

            PrivateKey p12PrivateEncryptionKey = cryptoToken.getPrivateKey(thisCAToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT));
            PublicKey p12PublicEncryptionKey = cryptoToken.getPublicKey(thisCAToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT));
            PrivateKey p12PrivateCertSignKey = cryptoToken.getPrivateKey(thisCAToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            PrivateKey p12PrivateCRLSignKey = cryptoToken.getPrivateKey(thisCAToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CRLSIGN));
            if (!p12PrivateCertSignKey.equals(p12PrivateCRLSignKey)) {
                throw new Exception("Assertion of equal signature keys failed.");
            }
            // Proceed with the export
            byte[] ret = null;
            String format = null;
            if (thisCa.getCAType() == CAInfo.CATYPE_CVC) {
                log.debug("Exporting private key with algorithm: " + p12PrivateCertSignKey.getAlgorithm() + " of format: "
                        + p12PrivateCertSignKey.getFormat());
                format = p12PrivateCertSignKey.getFormat();
                ret = p12PrivateCertSignKey.getEncoded();
            } else {
                log.debug("Exporting PKCS12 keystore");
                format = "PKCS12";
                KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
                keystore.load(null, keystorepass.toCharArray());
                // Load keys into keystore
                Certificate[] certificateChainSignature = (Certificate[]) thisCa.getCertificateChain().toArray(new Certificate[0]);
                Certificate[] certificateChainEncryption = new Certificate[1];
                // certificateChainSignature[0].getSigAlgName(),
                // generate dummy certificate for encryption key.
                certificateChainEncryption[0] = CertTools.genSelfCertForPurpose("CN=dummy2", 36500, null, p12PrivateEncryptionKey,
                        p12PublicEncryptionKey, thisCAToken.getEncryptionAlgorithm(), true, X509KeyUsage.keyEncipherment);
                log.debug("Exporting with sigAlgorithm " + AlgorithmTools.getSignatureAlgorithm(certificateChainSignature[0]) + "encAlgorithm="
                        + thisCAToken.getEncryptionAlgorithm());
                if (keystore.isKeyEntry(privateSignatureKeyAlias)) {
                    throw new Exception("Key \"" + privateSignatureKeyAlias + "\"already exists in keystore.");
                }
                if (keystore.isKeyEntry(privateEncryptionKeyAlias)) {
                    throw new Exception("Key \"" + privateEncryptionKeyAlias + "\"already exists in keystore.");
                }

                keystore.setKeyEntry(privateSignatureKeyAlias, p12PrivateCertSignKey, privkeypass.toCharArray(), certificateChainSignature);
                keystore.setKeyEntry(privateEncryptionKeyAlias, p12PrivateEncryptionKey, privkeypass.toCharArray(), certificateChainEncryption);
                // Return KeyStore as byte array and clean up
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                keystore.store(baos, keystorepass.toCharArray());
                if (keystore.isKeyEntry(privateSignatureKeyAlias)) {
                    keystore.deleteEntry(privateSignatureKeyAlias);
                }
                if (keystore.isKeyEntry(privateEncryptionKeyAlias)) {
                    keystore.deleteEntry(privateEncryptionKeyAlias);
                }
                ret = baos.toByteArray();
            }
            String msg = intres.getLocalizedMessage("caadmin.exportedca", caname, format);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.CA_EXPORTTOKEN, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(thisCa.getCAId()), null,
                    null, details);
            log.trace("<exportCAKeyStore");
            return ret;
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("caadmin.errorexportca", caname, "PKCS12", e.getMessage());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.CA_EXPORTTOKEN, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), null, null,
                    null, details);
            throw new EJBException(e);
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<Certificate> getAllCACertificates() {
        final ArrayList<Certificate> returnval = new ArrayList<Certificate>();
        for (final Integer caid : caSession.getAvailableCAs()) {
            try {
                final CAInfo caInfo = caSession.getCAInfoInternal(caid.intValue(), null, true);
                if (log.isDebugEnabled()) {
                    log.debug("Getting certificate chain for CA: " + caInfo.getName() + ", " + caInfo.getCAId());
                }
                final Certificate caCertificate = caInfo.getCertificateChain().iterator().next();
                returnval.add(caCertificate);
            } catch (CADoesntExistsException e) {
                log.error("\"Available\" CA does not exist! caid=" + caid);
            }
        }
        return returnval;
    }

    @Override
    public void activateCAService(AuthenticationToken admin, int caid) throws AuthorizationDeniedException, ApprovalException,
        WaitingForApprovalException, CADoesntExistsException {
        // Authorize
        if (!accessSession.isAuthorizedNoLogging(admin, AccessRulesConstants.REGULAR_ACTIVATECA)) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.notauthorizedtoactivatetoken", Integer.valueOf(caid));
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw new AuthorizationDeniedException(detailsMsg);
        }
        // Get CA also check authorization for this specific CA
        final CAInfo cainfo = caSession.getCAInfo(admin, caid);
        if (cainfo.getStatus() == CAConstants.CA_EXTERNAL) {
            log.info(intres.getLocalizedMessage("caadmin.catokenexternal", Integer.valueOf(caid)));
            return;
        }
        // Check if approvals is required.
        final int numOfApprovalsRequired = getNumOfApprovalRequired(CAInfo.REQ_APPROVAL_ACTIVATECA, cainfo.getCAId(), cainfo.getCertificateProfileId());
        final ActivateCATokenApprovalRequest ar = new ActivateCATokenApprovalRequest(cainfo.getName(), "", admin, numOfApprovalsRequired,
                caid, ApprovalDataVO.ANY_ENDENTITYPROFILE);
        if (ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_ACTIVATECATOKEN)) {
            approvalSession.addApprovalRequest(admin, ar);
            throw new WaitingForApprovalException(intres.getLocalizedMessage("ra.approvalcaactivation"));
        }
        if (cainfo.getStatus() == CAConstants.CA_OFFLINE) {
            final String detailsMsg = intres.getLocalizedMessage("catoken.activated", caid);
            auditSession.log(EventTypes.CA_SERVICEACTIVATE, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(caid), null, null, detailsMsg);
            CA ca = caSession.getCAForEdit(admin, caid);
            ca.setStatus(CAConstants.CA_ACTIVE);
            try {
                caSession.editCA(admin, ca, false);
            } catch (IllegalCryptoTokenException e) {
                throw new RuntimeException(e.getMessage());
            }
        } else {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errornotoffline", cainfo.getName());
            auditSession.log(EventTypes.CA_SERVICEACTIVATE, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw new RuntimeException(detailsMsg);
        }
    }

    private static final ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_ACTIVATECATOKEN = { new ApprovalOveradableClassName(
            org.ejbca.core.model.approval.approvalrequests.ActivateCATokenApprovalRequest.class.getName(), null), };

    @Override
    public void deactivateCAService(AuthenticationToken admin, int caid) throws AuthorizationDeniedException, CADoesntExistsException {
        // Authorize
        if (!accessSession.isAuthorizedNoLogging(admin, AccessRulesConstants.REGULAR_ACTIVATECA)) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.notauthorizedtodeactivatetoken", Integer.valueOf(caid));
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw new AuthorizationDeniedException(detailsMsg);
        }
        final CA ca = caSession.getCAForEdit(admin, caid);
        if (ca.getStatus() == CAConstants.CA_ACTIVE) {
            ca.setStatus(CAConstants.CA_OFFLINE);
            try {
                caSession.editCA(admin, ca, false);
                final String detailsMsg = intres.getLocalizedMessage("catoken.deactivated", caid);
                auditSession.log(EventTypes.CA_SERVICEDEACTIVATE, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(caid), null, null, detailsMsg);
            } catch (IllegalCryptoTokenException e) {
                throw new RuntimeException(e);
            }
        } else {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errornotoffline", ca.getName());
            auditSession.log(EventTypes.CA_SERVICEDEACTIVATE, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw new RuntimeException(detailsMsg);
           
        }
    }
    
    /** Method used to check if certificate profile id exists in any CA. */
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<String> getCAsUsingCertificateProfile(final int certificateprofileid) {
        List<String> result = new ArrayList<String>();
        for (final Integer caid : caSession.getAvailableCAs()) {
            try {
                final CAInfo caInfo = caSession.getCAInfoInternal(caid.intValue(), null, true);
                if (caInfo.getCertificateProfileId() == certificateprofileid) {
                    result.add(caInfo.getName());
                }
            } catch (CADoesntExistsException e) {
                log.error("\"Available\" CA is no longer available. caid=" + caid.toString());
            }
        }
        return result;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean exitsPublisherInCAs(AuthenticationToken admin, int publisherid) {
        try {
            for (final Integer caid : caSession.getAvailableCAs(admin)) {
                for (final Integer pubInt : caSession.getCA(admin, caid).getCRLPublishers()) {
                    if (pubInt.intValue() == publisherid) {
                        // We have found a match. No point in looking for more..
                        return true;
                    }
                }
            }
        } catch (CADoesntExistsException e) {
            throw new RuntimeException("Available CA is no longer available!");
        } catch (AuthorizationDeniedException e) {
            throw new RuntimeException("No longer authorized to authorized CA!");
        }
        return false;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public int getNumOfApprovalRequired(final int action, final int caid, final int certProfileId) {
        int retval = 0;
        try {
            // No need to do access control here on the CA, we are just internally retrieving a value
            // to be used to see if approvals are needed.
            final CAInfo cainfo = caSession.getCAInfoInternal(caid, null, true);
            if (cainfo.isApprovalRequired(action)) {
                retval = cainfo.getNumOfReqApprovals();
            }
            final CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(certProfileId);
            if (certprofile != null && certprofile.isApprovalRequired(action)) {
                retval = Math.max(retval, certprofile.getNumOfReqApprovals());
            }
        } catch (CADoesntExistsException e) {
            // NOPMD ignore cainfo is null
        }
        return retval;
    }

    @Override
    public void publishCACertificate(AuthenticationToken admin, Collection<Certificate> certificatechain, Collection<Integer> usedpublishers,
            String caDataDN) throws AuthorizationDeniedException {
        try {
            Object[] certs = certificatechain.toArray();
            for (int i = 0; i < certs.length; i++) {
                Certificate cert = (Certificate) certs[i];
                String fingerprint = CertTools.getFingerprintAsString(cert);
                // CA fingerprint, figure out the value if this is not a root CA
                String cafp = fingerprint;
                // Calculate the certificate type
                boolean isSelfSigned = CertTools.isSelfSigned(cert);
                int type = CertificateConstants.CERTTYPE_ENDENTITY;
                if (CertTools.isCA(cert)) {
                    // this is a CA
                    if (isSelfSigned) {
                        type = CertificateConstants.CERTTYPE_ROOTCA;
                    } else {
                        type = CertificateConstants.CERTTYPE_SUBCA;
                        // If not a root CA, the next certificate in the chain
                        // should be the CA of this CA
                        if ((i + 1) < certs.length) {
                            Certificate cacert = (Certificate) certs[i + 1];
                            cafp = CertTools.getFingerprintAsString(cacert);
                        }
                    }
                } else if (isSelfSigned) {
                    // If we don't have basic constraints, but is self signed,
                    // we are still a CA, just a stupid CA
                    type = CertificateConstants.CERTTYPE_ROOTCA;
                } else {
                    // If and end entity, the next certificate in the chain
                    // should be the CA of this end entity
                    if ((i + 1) < certs.length) {
                        Certificate cacert = (Certificate) certs[i + 1];
                        cafp = CertTools.getFingerprintAsString(cacert);
                    }
                }

                String name = "SYSTEMCERT";
                if (type != CertificateConstants.CERTTYPE_ENDENTITY) {
                    name = "SYSTEMCA";
                }
                // Store CA certificate in the database if it does not exist
                long updateTime = new Date().getTime();
                int profileId = 0;
                String tag = null;
                CertificateInfo ci = certificateStoreSession.getCertificateInfo(fingerprint);
                if (ci == null) {
                    // If we don't have it in the database, store it setting
                    // certificateProfileId = 0 and tag = null
                    certificateStoreSession.storeCertificate(admin, cert, name, cafp,
                            CertificateConstants.CERT_ACTIVE, type, profileId, tag, updateTime);
                } else {
                    updateTime = ci.getUpdateTime().getTime();
                    profileId = ci.getCertificateProfileId();
                    tag = ci.getTag();
                }
                if (usedpublishers != null) {
                    publisherSession.storeCertificate(admin, usedpublishers, cert, cafp, null, caDataDN, fingerprint,
                            CertificateConstants.CERT_ACTIVE, type, -1,
                            RevokedCertInfo.NOT_REVOKED, tag, profileId, updateTime, null);
                }
            }
        } catch (javax.ejb.CreateException ce) {
            throw new EJBException(ce);
        }
    }

    @Override
    public void publishCRL(AuthenticationToken admin, Certificate caCert, Collection<Integer> usedpublishers, String caDataDN,
            boolean doPublishDeltaCRL) throws AuthorizationDeniedException {
        if (usedpublishers == null) {
            return;
        }
        // Store crl in ca CRL publishers.
        if (log.isDebugEnabled()) {
            log.debug("Storing CRL in publishers");
        }
        final String issuerDN = CertTools.getSubjectDN(caCert);
        final String caCertFingerprint = CertTools.getFingerprintAsString(caCert);
        final byte crl[] = crlStoreSession.getLastCRL(issuerDN, false);
        if (crl != null) {
            final int nr = crlStoreSession.getLastCRLInfo(issuerDN, false).getLastCRLNumber();
            publisherSession.storeCRL(admin, usedpublishers, crl, caCertFingerprint, nr, caDataDN);
        }
        if (!doPublishDeltaCRL) {
            return;
        }
        final byte deltaCrl[] = crlStoreSession.getLastCRL(issuerDN, true);
        if (deltaCrl != null) {
            final int nr = crlStoreSession.getLastCRLInfo(issuerDN, true).getLastCRLNumber();
            publisherSession.storeCRL(admin, usedpublishers, deltaCrl, caCertFingerprint, nr, caDataDN);
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Collection<Integer> getAuthorizedPublisherIds(final AuthenticationToken admin) {
        final HashSet<Integer> returnval = new HashSet<Integer>();
        try {
            // If superadmin return all available publishers
            returnval.addAll(publisherSession.getAllPublisherIds());
        } catch (AuthorizationDeniedException e1) {
            // If regular CA-admin return publishers he is authorized to
            for (final Integer caid : caSession.getAvailableCAs(admin)) {
                try {
                    returnval.addAll(caSession.getCAInfo(admin, caid).getCRLPublishers());
                } catch (CADoesntExistsException e) {
                    log.debug("CA " + caid + " does not exist.");
                } catch (AuthorizationDeniedException e) {
                    log.debug("Unauthorized to CA " + caid + ", admin '" + admin.toString() + "'");
                }
            }
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public String healthCheck() {
        final StringBuilder sb = new StringBuilder();
        final boolean caTokenSignTest = EjbcaConfiguration.getHealthCheckCaTokenSignTest();
        if (log.isDebugEnabled()) {
            log.debug("CaTokenSignTest: " + caTokenSignTest);
        }
        for (final Integer caid : caSession.getAvailableCAs()) {
            try {
                final CAInfo cainfo = caSession.getCAInfoInternal(caid.intValue());
                if (caTokenSignTest && (cainfo.getStatus() == CAConstants.CA_ACTIVE) && cainfo.getIncludeInHealthCheck()) {
                    final int tokenstatus = cainfo.getCAToken().getTokenStatus(cryptoTokenSession.getCryptoToken(cainfo.getCAToken().getCryptoTokenId()));
                    if (tokenstatus == CryptoToken.STATUS_OFFLINE) {
                        sb.append("\nCA: Error CA Token is disconnected, CA Name : ").append(cainfo.getName());
                        log.error("Error CA Token is disconnected, CA Name : " + cainfo.getName());
                    }
                }
            } catch (CADoesntExistsException e) {
                if (log.isDebugEnabled()) {
                    log.debug("CA with id '" + caid.toString() + "' does not exist.");
                }
            }
        }
        return sb.toString();
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public ExtendedCAServiceResponse extendedService(AuthenticationToken admin, int caid, ExtendedCAServiceRequest request)
            throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException,
            CADoesntExistsException, AuthorizationDeniedException, CertificateEncodingException, CertificateException, OperatorCreationException {
        // Get CA that will process request
        CA ca = caSession.getCA(admin, caid);
        if (log.isDebugEnabled()) {
            log.debug("Extended service with request class '" + request.getClass().getName() + "' called for CA '" + ca.getName() + "'");
        }
        final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
        ExtendedCAServiceResponse resp = ca.extendedService(cryptoToken, request);
        String msg = intres.getLocalizedMessage("caadmin.extendedserviceexecuted", request.getClass().getName(), ca.getName());
        Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        auditSession.log(EjbcaEventTypes.CA_EXTENDEDSERVICE, EventStatus.SUCCESS, ModuleTypes.CA, EjbcaServiceTypes.EJBCA, admin.toString(),
                String.valueOf(caid), null, null, details);
        return resp;
    }

    //
    // Private methods
    //

    /**
     * Check if subject certificate is signed by issuer certificate. Used in
     * 
     * @see #upgradeFromOldCAKeyStore(Admin, String, byte[], char[], char[], String). This method does a lazy check: if signature verification failed
     *      for any reason that prevent verification, e.g. signature algorithm not supported, method returns false. Author: Marco Ferrante
     * 
     * @param subject Subject certificate
     * @param issuer Issuer certificate
     * @return true if subject certificate is signed by issuer certificate
     * @throws java.lang.Exception
     */
    private boolean verifyIssuer(Certificate subject, Certificate issuer) {
        try {
            PublicKey issuerKey = issuer.getPublicKey();
            subject.verify(issuerKey);
            return true;
        } catch (java.security.GeneralSecurityException e) {
            return false;
        }
    }

    /**
     * Checks the signer validity given a CADataLocal object, as a side-effect marks the signer as expired if it is expired, and throws an
     * EJBException to the caller. This should only be called from create and edit CA methods.
     * 
     * @param admin administrator calling the method
     * @param signcadata a CADataLocal entity object of the signer to be checked
     * @throws UnsupportedEncodingException if there is an error getting the CA from the CADataLoca
     * @throws IllegalCryptoTokenException if we can not read the CA, with it's keystore
     * @throws EJBException embedding a CertificateExpiredException or a CertificateNotYetValidException if the certificate has expired or is not yet
     *             valid
     */
    private void assertSignerValidity(AuthenticationToken admin, CA signca) {
        // Check validity of signers certificate
        final Certificate signcert = (Certificate) signca.getCACertificate();
        try {
            CertTools.checkValidity(signcert, new Date());
        } catch (CertificateExpiredException ce) {
            // Signers Certificate has expired.
            String msg = intres.getLocalizedMessage("signsession.caexpired", signca.getSubjectDN());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.CA_VALIDITY, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(signca.getCAId()), null, null, details);
            throw new EJBException(ce);
        } catch (CertificateNotYetValidException cve) {
            String msg = intres.getLocalizedMessage("signsession.canotyetvalid", signca.getSubjectDN());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.CA_VALIDITY, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(signca.getCAId()), null, null, details);
            throw new EJBException(cve);
        }
    }

    /**
     * Helper method that activates CA services and publisher their certificates, if the services are marked as active
     * 
     * @throws AuthorizationDeniedException
     */
    private void activateAndPublishExternalCAServices(AuthenticationToken admin, Collection<ExtendedCAServiceInfo> extendedCAServiceInfos, CA ca)
            throws AuthorizationDeniedException {
        // activate External CA Services
        Iterator<ExtendedCAServiceInfo> iter = extendedCAServiceInfos.iterator();
        while (iter.hasNext()) {
            ExtendedCAServiceInfo info = (ExtendedCAServiceInfo) iter.next();
            ArrayList<Certificate> certificates = new ArrayList<Certificate>();
            if (info instanceof OCSPCAServiceInfo) {
                try {
                    final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
                    ca.initExtendedService(cryptoToken, ExtendedCAServiceTypes.TYPE_OCSPEXTENDEDSERVICE, ca);
                    // The OCSP certificate is the same as the CA signing
                    // certificate
                } catch (Exception fe) {
                    String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", "OCSPCAService");
                    log.error(msg, fe);
                    throw new EJBException(fe);
                }
            }
            if (info instanceof XKMSCAServiceInfo) {
                try {
                    final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
                    ca.initExtendedService(cryptoToken, ExtendedCAServiceTypes.TYPE_XKMSEXTENDEDSERVICE, ca);
                    certificates.add(((XKMSCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceTypes.TYPE_XKMSEXTENDEDSERVICE))
                            .getXKMSSignerCertificatePath().get(0));
                } catch (Exception fe) {
                    String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", "XKMSCAService");
                    log.error(msg, fe);
                    throw new EJBException(fe);
                }
            }
            if (info instanceof CmsCAServiceInfo) {
                try {
                    final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
                    ca.initExtendedService(cryptoToken, ExtendedCAServiceTypes.TYPE_CMSEXTENDEDSERVICE, ca);
                    certificates.add(((CmsCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceTypes.TYPE_CMSEXTENDEDSERVICE))
                            .getCertificatePath().get(0));
                } catch (Exception fe) {
                    String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", "CMSCAService");
                    log.error(msg, fe);
                    throw new EJBException(fe);
                }
            }
            // Always store the certificate. Only publish the extended service
            // certificate for active services.
            Collection<Integer> publishers = null;
            if (info.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE) {
                publishers = ca.getCRLPublishers();
            }
            if ((!certificates.isEmpty())) {
                publishCACertificate(admin, certificates, publishers, ca.getSubjectDN());
            }
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public void flushCACache() {
        // Just forward the call, because in CaSession it is only in the local interface and we
        // want to be able to use it from CLI
        caSession.flushCACache();
    }

}
