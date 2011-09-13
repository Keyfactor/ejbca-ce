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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.InternalSecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.certificates.ca.CA;
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
import org.cesecore.certificates.ca.catoken.CATokenInfo;
import org.cesecore.certificates.ca.catoken.CaTokenSessionLocal;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceNotActiveException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequest;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequestException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceResponse;
import org.cesecore.certificates.ca.extendedservices.IllegalExtendedCAServiceRequestException;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.CrlCreateSessionLocal;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.ocsp.exception.NotSupportedException;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.BaseCryptoToken;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenOfflineException;
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
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.revoke.RevocationSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
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

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(CAAdminSessionBean.class);

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private AccessControlSessionLocal accessSession;
    @EJB
    private InternalSecurityEventsLoggerSessionLocal auditSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CaTokenSessionLocal caTokenSession;
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

    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @PostConstruct
    public void postConstruct() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Override
    public void initializeAndUpgradeCAs() {
        Collection<CAData> result = CAData.findAll(entityManager);
        Iterator<CAData> iter = result.iterator();
        while (iter.hasNext()) {
            CAData cadata = iter.next();
            String caname = cadata.getName();
            try {
                cadata.upgradeCA();
                log.info("Initialized CA: " + caname + ", with expire time: " + new Date(cadata.getExpireTime()));
            } catch (UnsupportedEncodingException e) {
                log.error("UnsupportedEncodingException trying to load CA with name: " + caname, e);
            } catch (IllegalCryptoTokenException e) {
                log.error("IllegalCryptoTokenException trying to load CA with name: " + caname, e);
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
        int castatus = SecConst.CA_OFFLINE;
        final int caid = cainfo.getCAId();
        // Check that administrator has superadminstrator rights.
        if (!accessSession.isAuthorizedNoLogging(admin, "/super_administrator")) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtocreateca", cainfo.getName());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(caid), null, null, details);
            throw new AuthorizationDeniedException(msg);
        } 
        // Check that CA doesn't already exists
        if (caid >= 0 && caid <= CAInfo.SPECIALCAIDBORDER) {
            String msg = intres.getLocalizedMessage("caadmin.wrongcaid", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw new CAExistsException(msg);
        }
        if (CAData.findById(entityManager, Integer.valueOf(caid)) != null) {
            String msg = intres.getLocalizedMessage("caadmin.caexistsid", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw new CAExistsException(msg);
        }
        if (CAData.findByName(entityManager, cainfo.getName()) != null) {
            String msg = intres.getLocalizedMessage("caadmin.caexistsname", cainfo.getName());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw new CAExistsException(msg);
        }
        // Create CAToken
        CATokenInfo catokeninfo = cainfo.getCATokenInfo();
        CryptoToken cryptoToken = CryptoTokenFactory.createCryptoToken(catokeninfo.getClassPath(), catokeninfo.getProperties(), null,
                cainfo.getCAId());
        CAToken catoken = new CAToken(cryptoToken);
        catoken.setSignatureAlgorithm(catokeninfo.getSignatureAlgorithm());
        catoken.setEncryptionAlgorithm(catokeninfo.getEncryptionAlgorithm());
        catoken.setKeySequence(catokeninfo.getKeySequence());
        catoken.setKeySequenceFormat(catokeninfo.getKeySequenceFormat());

        // Create CA
        CA ca = null;
        // The certificate profile used for the CAs certificate
        CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(cainfo.getCertificateProfileId());
        ca = createCAObject(cainfo, catoken, certprofile);
        // AltName is not implemented for all CA types
        String caAltName = null;
        if (cainfo instanceof X509CAInfo) {
            caAltName = ((X509CAInfo)cainfo).getSubjectAltName();
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

        // Generate keys, for soft CAs, and activate CA token
        String authCode = catokeninfo.getAuthenticationCode();
        authCode = getDefaultKeyStorePassIfSWAndEmpty(authCode, cryptoToken);
        if (cryptoToken instanceof SoftCryptoToken) {
            try {
                // There are two ways to get the authentication code:
                // 1. The user provided one when creating the CA on the create CA page
                // 2. We use the system default password
                boolean renew = false;
                caTokenSession.generateKeys(admin, ca.getCAId(), authCode.toCharArray(), renew, true);
                // Re-read them so we don't overwrite with empty values in the end...
                // Read the CA _not_ from the cache, so our changes are not overwritten somewhere else
                ca = caSession.getCAForEdit(admin, ca.getCAId());
                catoken = ca.getCAToken();
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("caadmin.errorcreatetoken");
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                details.put("error", e.getMessage());
                auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                		String.valueOf(caid), null, null, details);
                throw new EJBException(e);
            }
        }
        try {
        	// We don't have to do this if we generated keys, since caTokenSession.generateKeys should do it for us...
        	// It is not certain that caTokenSession.generateKeys was called though, probably not for HSM CA tokens
            catoken.getCryptoToken().activate(authCode.toCharArray());
        } catch (CryptoTokenAuthenticationFailedException ctaf) {
            String msg = intres.getLocalizedMessage("caadmin.errorcreatetokenpin");
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw ctaf;
        } catch (CryptoTokenOfflineException ctoe) {
            String msg = intres.getLocalizedMessage("error.catokenoffline", cainfo.getName());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw ctoe;
        }

        // Create certificate chain
        Collection<Certificate> certificatechain = null;
        String sequence = catoken.getTokenInfo().getKeySequence(); // get from CAtoken to make sure it is fresh
        if (cainfo.getSignedBy() == CAInfo.SELFSIGNED) {
            try {
                // create selfsigned certificate
                Certificate cacertificate = null;
                log.debug("CAAdminSessionBean : " + cainfo.getSubjectDN());
                EndEntityInformation cadata = new EndEntityInformation("nobody", cainfo.getSubjectDN(), cainfo.getSubjectDN().hashCode(), caAltName,
                        null, 0, 0, 0, cainfo.getCertificateProfileId(), null, null, 0, 0, null);
                cacertificate = ca.generateCertificate(cadata, catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN), -1, cainfo.getValidity(),
                        certprofile, sequence);
                log.debug("CAAdminSessionBean : " + CertTools.getSubjectDN(cacertificate));
                // Build Certificate Chain
                certificatechain = new ArrayList<Certificate>();
                certificatechain.add(cacertificate);
                // set status to active
                castatus = SecConst.CA_ACTIVE;
            } catch (CryptoTokenOfflineException e) {
                String msg = intres.getLocalizedMessage("error.catokenoffline", cainfo.getName());
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                		String.valueOf(caid), null, null, details);
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
            castatus = SecConst.CA_WAITING_CERTIFICATE_RESPONSE;
        }

        if (cainfo.getSignedBy() > CAInfo.SPECIALCAIDBORDER || cainfo.getSignedBy() < 0) {
            // Create CA signed by other internal CA.
            try {
                CAData signcadata = CAData.findByIdOrThrow(entityManager, Integer.valueOf(cainfo.getSignedBy()));
                CA signca = signcadata.getCA();
                // Check that the signer is valid
                checkSignerValidity(admin, signcadata);
                // Create CA certificate
                Certificate cacertificate = null;

                EndEntityInformation cadata = new EndEntityInformation("nobody", cainfo.getSubjectDN(), cainfo.getSubjectDN().hashCode(), caAltName,
                        null, 0, 0, 0, cainfo.getCertificateProfileId(), null, null, 0, 0, null);

                cacertificate = signca.generateCertificate(cadata, catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN), -1, cainfo.getValidity(),
                        certprofile, sequence);

                // Build Certificate Chain
                Collection<Certificate> rootcachain = signca.getCertificateChain();
                certificatechain = new ArrayList<Certificate>();
                certificatechain.add(cacertificate);
                certificatechain.addAll(rootcachain);
                // set status to active
                castatus = SecConst.CA_ACTIVE;
            } catch (CryptoTokenOfflineException e) {
                String msg = intres.getLocalizedMessage("error.catokenoffline", cainfo.getName());
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                		String.valueOf(caid), null, null, details);
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
            String msg = intres.getLocalizedMessage("caadmin.canotexistsid", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
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

        if (castatus == SecConst.CA_ACTIVE) {
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
        if (!accessSession.isAuthorizedNoLogging(admin, "/super_administrator")) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoeditca", cainfo.getName());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw new AuthorizationDeniedException(msg);
        }

        // Check if extended service certificates are about to be renewed.
        Iterator<ExtendedCAServiceInfo> iter = cainfo.getExtendedCAServiceInfos().iterator();
        while (iter.hasNext()) {
            ExtendedCAServiceInfo next = iter.next();
            // No OCSP Certificate exists that can be renewed.
            if (next instanceof XKMSCAServiceInfo) {
                xkmsrenewcert = ((XKMSCAServiceInfo) next).getRenewFlag();
            } else if (next instanceof CmsCAServiceInfo) {
                cmsrenewcert = ((CmsCAServiceInfo) next).getRenewFlag();
            }
        }

        // Get CA from database
        try {
            caSession.editCA(admin, cainfo);
            CA ca = caSession.getCA(admin, cainfo.getCAId());
            // Try to activate the CA token after we have edited the CA
            try {
                CATokenInfo catokeninfo = cainfo.getCATokenInfo();
                String authCode = catokeninfo.getAuthenticationCode();
                String keystorepass = getDefaultKeyStorePassIfSWAndEmpty(authCode, ca.getCAToken().getCryptoToken());
                if (keystorepass != null) {
                    caTokenSession.activateCAToken(admin, cainfo.getCAId(), keystorepass.toCharArray());
                } else {
                    log.debug("Not trying to activate CAToken after editing, authCode == null.");
                }
            } catch (CryptoTokenAuthenticationFailedException ctaf) {
                String msg = intres.getLocalizedMessage("caadmin.errorcreatetokenpin");
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                		String.valueOf(caid), null, null, details);
            } catch (CryptoTokenOfflineException ctoe) {
                String msg = intres.getLocalizedMessage("error.catokenoffline", cainfo.getName());
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                		String.valueOf(caid), null, null, details);
            }
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
    public void verifyExistenceOfCA(int caid) throws CADoesntExistsException {
        // TODO: Test if "SELECT a.caId FROM CAData a WHERE a.caId=:caId" improves performance
        CAData.findByIdOrThrow(entityManager, Integer.valueOf(caid));
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public HashMap<Integer, String> getCAIdToNameMap(AuthenticationToken admin) {
        HashMap<Integer, String> returnval = new HashMap<Integer, String>();
        Collection<CAData> result = CAData.findAll(entityManager);
        Iterator<CAData> iter = result.iterator();
        while (iter.hasNext()) {
            CAData cadata = iter.next();
            returnval.put(cadata.getCaId(), cadata.getName());
        }
        return returnval;
    }

    @Override
    public byte[] makeRequest(AuthenticationToken admin, int caid, Collection<?> cachainin, boolean regenerateKeys, boolean usenextkey,
            boolean activatekey, String keystorepass) throws CADoesntExistsException, AuthorizationDeniedException, CertPathValidatorException,
            CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
        if (log.isTraceEnabled()) {
            log.trace(">makeRequest: " + caid + ", regenerateKeys=" + regenerateKeys + ", usenextkey=" + usenextkey + ", activatekey=" + activatekey);
        }
        byte[] returnval = null;
        // Check authorization
        if (!accessSession.isAuthorizedNoLogging(admin, AccessRulesConstants.REGULAR_RENEWCA)) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtocertreq", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw new AuthorizationDeniedException(msg);
        }

        try {
            CA ca = caSession.getCAForEdit(admin, caid);
            String caname = ca.getName();

            Collection<Certificate> chain = null;
            if ((cachainin != null) && (cachainin.size() > 0)) {
                chain = CertTools.createCertChain(cachainin);
                log.debug("Setting request certificate chain of size: " + chain.size());
                ca.setRequestCertificateChain(chain);
            } else {
                log.debug("Empty request certificate chain parameter.");
                // create empty list if input was null
                chain = new ArrayList<Certificate>();
            }
            // AR+ patch to make SPOC independent of external CVCA certificates for automatic renewals
            // i.e. if we don't pass a CA certificate as parameter we try to find a suitable CA certificate in the database, among existing CAs
            // (can be a simple imported CA-certificate of external CA)
            if (chain.isEmpty() && ca.getCAType() == CAInfo.CATYPE_CVC && ca.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA
                    && ca.getStatus() == SecConst.CA_ACTIVE) {
                CardVerifiableCertificate dvcert = (CardVerifiableCertificate) ca.getCACertificate();
                String ca_ref = dvcert.getCVCertificate().getCertificateBody().getAuthorityReference().getConcatenated();
                log.debug("DV renewal missing CVCA cert, try finding CA for:" + ca_ref);
                Iterator<Integer> cas = caSession.getAvailableCAs(admin).iterator();
                while (cas.hasNext()) {
                    CA cvca = caSession.getCA(admin, cas.next());
                    if (cvca.getCAType() == CAInfo.CATYPE_CVC && cvca.getSignedBy() == CAInfo.SELFSIGNED) {
                        CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cvca.getCACertificate();
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

            // Generate new certificate request.
            String signAlg = "SHA1WithRSA"; // Default algorithm
            CATokenInfo tinfo = ca.getCAInfo().getCATokenInfo();
            if (tinfo != null) {
                signAlg = tinfo.getSignatureAlgorithm();
            }
            log.debug("Using signing algorithm: " + signAlg + " for the CSR.");

            CAToken caToken = ca.getCAToken();
            if (regenerateKeys) {
                log.debug("Generating new keys.");
                keystorepass = getDefaultKeyStorePassIfSWAndEmpty(keystorepass, caToken.getCryptoToken());

                caTokenSession.generateKeys(admin, caid, keystorepass.toCharArray(), true, activatekey);
                // In order to generate a certificate with this keystore we must make sure it is activated
                // generateKeys above makes sure it is active
            }
            // The CA certificate signing this request is the first in the certificate chain
            Iterator<Certificate> iter = chain.iterator();
            Certificate cacert = null;
            if (iter.hasNext()) {
                cacert = (Certificate) iter.next();
            }
            // If we don't set status to waiting we want to use the next
            // signature key pair
            int keyPurpose = SecConst.CAKEYPURPOSE_CERTSIGN;
            boolean usepreviouskey = true; // for creating an authenticated
            // request we sign it with the
            // previous key
            if (usenextkey || (regenerateKeys && !activatekey)) {
                keyPurpose = SecConst.CAKEYPURPOSE_CERTSIGN_NEXT;
                usepreviouskey = false; // for creating an authenticated request
                // we sign it with the current key,
                // which will be the previous once we
                // activate the new key
            }
            log.debug("Creating certificate request with key purpose: " + keyPurpose);
            byte[] request = ca.createRequest(null, signAlg, cacert, keyPurpose);
            if (ca.getCAType() == CAInfo.CATYPE_CVC) {
                // If this is a CVC CA renewal request, we need to sign it to
                // make an authenticated request
                // The CVC CAs current signing certificate will always be the
                // right one, because it is the "previous" signing certificate
                // until we have imported a new one
                // as response to the request we create here.
                boolean createlinkcert = false; // this is not a link
                // certificate, and never can be
                // If we try to sign an initial request there will be no CA
                // certificate and signRequest will return the same as we pass
                // in, i.e. do nothing.
                try {
                    returnval = ca.signRequest(request, usepreviouskey, createlinkcert);
                } catch (CryptoTokenOfflineException e) {
                    // If this is an CryptoTokenOfflineException we it's possible that
                    // we did not have a previous key, then just skip and make it un-authenticated
                    // and return the request message as is
                	log.info("Failed to sign CVC request with previous key (does it exist?). Returning unauthenticated request.", e);
                	returnval = request;
                }
            } else {
                returnval = request;
            }

            // Set statuses if it should be set.
            if ((regenerateKeys || usenextkey) && activatekey) {
                ca.setStatus(SecConst.CA_WAITING_CERTIFICATE_RESPONSE);
            }

            caSession.editCA(admin, ca, true);
            // Log information about the event
            String msg = intres.getLocalizedMessage("caadmin.certreqcreated", caname, Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.CA_EDITING, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
        } catch (CertPathValidatorException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertreq", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw e;
        } catch (CryptoTokenOfflineException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertreq", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw e;
        } catch (CryptoTokenAuthenticationFailedException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertreq", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw e;
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertreq", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw new EJBException(e);
        }

        if (log.isTraceEnabled()) {
            log.trace("<makeRequest: " + caid);
        }
        return returnval;
    }

    @Override
    public byte[] signRequest(AuthenticationToken admin, int caid, byte[] request, boolean usepreviouskey, boolean createlinkcert)
            throws AuthorizationDeniedException, CADoesntExistsException, CryptoTokenOfflineException {
        if (!accessSession.isAuthorizedNoLogging(admin, "/super_administrator")) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtocertreq", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw new AuthorizationDeniedException(msg);
        }
        byte[] returnval = null;
        String caname = "" + caid;
        try {
            CA signedbyCA = caSession.getCA(admin, caid);
            caname = signedbyCA.getName();
            returnval = signedbyCA.signRequest(request, usepreviouskey, createlinkcert);
            String msg = intres.getLocalizedMessage("caadmin.certreqsigned", caname);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.CA_SIGNREQUEST, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertreqsign", caname);
            log.error(msg, e);
            throw new EJBException(e);
        }
        return returnval;
    }

    @Override
    public void receiveResponse(AuthenticationToken admin, int caid, ResponseMessage responsemessage, Collection<?> cachain,
            String tokenAuthenticationCode) throws AuthorizationDeniedException, CertPathValidatorException, EjbcaException, CesecoreException {
        if (log.isTraceEnabled()) {
            log.trace(">receiveResponse: " + caid);
        }
        Certificate cacert = null;
        // Check authorization
        if (!accessSession.isAuthorizedNoLogging(admin, AccessRulesConstants.REGULAR_RENEWCA)) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtocertresp", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
        }

        // Get CA info.
        try {
            CA ca = caSession.getCAForEdit(admin, caid);
            if (responsemessage instanceof X509ResponseMessage) {
                cacert = ((X509ResponseMessage) responsemessage).getCertificate();
            } else {
                String msg = intres.getLocalizedMessage("caadmin.errorcertrespillegalmsg", responsemessage != null ? responsemessage.getClass()
                        .getName() : "null");
                log.info(msg);
                throw new EjbcaException(msg);
            }

            // If signed by external CA, process the received certificate and store it, activating the CA
            if (ca.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA) {
                // Check that CA DN is equal to the certificate response.
                if (!CertTools.getSubjectDN(cacert).equals(CertTools.stringToBCDNString(ca.getSubjectDN()))) {
                    String msg = intres.getLocalizedMessage("caadmin.errorcertrespwrongdn", CertTools.getSubjectDN(cacert), ca.getSubjectDN());
                    log.info(msg);
                    throw new EjbcaException(msg);
                }

                ArrayList<Certificate> tmpchain = new ArrayList<Certificate>();
                tmpchain.add(cacert);
                // If we have a chain given as parameter, we will use that.
                // If no parameter is given we assume that the request chain
                // was stored when the request was created.
                Collection<Certificate> reqchain = null;
                if ((cachain != null) && (cachain.size() > 0)) {
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
                Collection<Certificate> chain = CertTools.createCertChain(tmpchain);
                log.debug("Storing certificate chain of size: " + chain.size());
                // Before importing the certificate we want to make sure
                // that the public key matches the CAs private key
                CAToken catoken = ca.getCAToken();
                // If it is a DV certificate signed by a CVCA, enrich the
                // public key for EC parameters from the CVCA's certificate
                PublicKey pk = cacert.getPublicKey();
                if (StringUtils.equals(cacert.getType(), "CVC")) {
                    if (pk.getAlgorithm().equals("ECDSA")) {
                        CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cacert;
                        try {
                            if ((cvccert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole() == AuthorizationRoleEnum.DV_D)
                                    || (cvccert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole() == AuthorizationRoleEnum.DV_F)) {
                                log.debug("Enriching DV public key with EC parameters from CVCA");
                                Certificate cvcacert = (Certificate) reqchain.iterator().next();
                                pk = KeyTools.getECPublicKeyWithParams(pk, cvcacert.getPublicKey());
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
                try {
                    KeyTools.testKey(catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), pk, catoken.getCryptoToken().getSignProviderName());
                } catch (Exception e1) {
                    log.debug("The received certificate response does not match the CAs private signing key for purpose CAKEYPURPOSE_CERTSIGN, trying CAKEYPURPOSE_CERTSIGN_NEXT...");
                    if (e1 instanceof InvalidKeyException) {
                        log.trace(e1);
                    } else {
                        // If it's not invalid key, we want to see more of the error
                        log.debug("Error: ", e1);
                    }
                    try {
                        KeyTools.testKey(catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN_NEXT), pk, catoken.getCryptoToken()
                                .getSignProviderName());
                        // This was OK, so we must also activate the next signing key when importing this certificate
                        // this makes sure the ca token is active
                        caTokenSession.activateNextSignKey(admin, caid, tokenAuthenticationCode.toCharArray());
                    } catch (Exception e2) {
                        log.debug("The received certificate response does not match the CAs private signing key for purpose CAKEYPURPOSE_CERTSIGN_NEXT either, giving up.");
                        if ((e2 instanceof InvalidKeyException) || (e2 instanceof IllegalArgumentException)) {
                            log.trace(e2);
                        } else {
                            // If it's not invalid key or missing authentication code,
                            // we want to see more of the error
                            log.debug("Error: ", e2);
                        }
                        throw new EjbcaException(ErrorCode.INVALID_KEY, e2);
                    }
                }
                ca.setCertificateChain(chain);

                // Set status to active, so we can sign certificates for the external services below.
                ca.setStatus(SecConst.CA_ACTIVE);

                // activate External CA Services
                Iterator<Integer> iter = ca.getExternalCAServiceTypes().iterator();
                while (iter.hasNext()) {
                    int type = iter.next().intValue();
                    try {
                        ca.initExtendedService(type, ca);
                        ArrayList<Certificate> extcacertificate = new ArrayList<Certificate>();
                        ExtendedCAServiceInfo info = null;
                        if (type == ExtendedCAServiceTypes.TYPE_OCSPEXTENDEDSERVICE) {
                            info = (OCSPCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceTypes.TYPE_OCSPEXTENDEDSERVICE);
                            // The OCSP certificate is the same as the
                            // singing certificate
                        }
                        if (type == ExtendedCAServiceTypes.TYPE_XKMSEXTENDEDSERVICE) {
                            info = ca.getExtendedCAServiceInfo(ExtendedCAServiceTypes.TYPE_XKMSEXTENDEDSERVICE);
                            extcacertificate.add(((XKMSCAServiceInfo) info).getXKMSSignerCertificatePath().get(0));
                        }
                        if (type == ExtendedCAServiceTypes.TYPE_CMSEXTENDEDSERVICE) {
                            info = ca.getExtendedCAServiceInfo(ExtendedCAServiceTypes.TYPE_CMSEXTENDEDSERVICE);
                            extcacertificate.add(((CmsCAServiceInfo) info).getCertificatePath().get(0));
                        }
                        // Publish the extended service certificate, but only for active services
                        if ((info != null) && (info.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE) && (!extcacertificate.isEmpty())) {
                            publishCACertificate(admin, extcacertificate, ca.getCRLPublishers(), ca.getSubjectDN());
                        }
                    } catch (Exception fe) {
                        String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", Integer.valueOf(caid));
                        Map<String, Object> details = new LinkedHashMap<String, Object>();
                        details.put("msg", msg);
                        auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                        		String.valueOf(caid), null, null, details);
                        throw new EJBException(fe);
                    }
                }

                // Set expire time
                ca.setExpireTime(CertTools.getNotAfter(cacert));
                // Save CA
                caSession.editCA(admin, ca, true);

                // Publish CA Certificate
                publishCACertificate(admin, chain, ca.getCRLPublishers(), ca.getSubjectDN());

                // Create initial CRL
                crlCreateSession.forceCRL(admin, caid);
                crlCreateSession.forceDeltaCRL(admin, caid);
            } else {
                // Cannot receive certificate response for internal CA
                String msg = intres.getLocalizedMessage("caadmin.errorcertrespinternalca", Integer.valueOf(caid));
                log.info(msg);
                throw new EjbcaException(msg);
            }

            // All OK
            String msg = intres.getLocalizedMessage("caadmin.certrespreceived", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.CA_EDITING, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
        } catch (CryptoTokenOfflineException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
            log.info(msg);
            throw e;
        } catch (CADoesntExistsException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
            log.info(msg);
            throw e;
        } catch (IllegalCryptoTokenException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
            log.info(msg);
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
        if (!accessSession.isAuthorizedNoLogging(admin, "/super_administrator")) {
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
            if (((oldcadata.getStatus() == SecConst.CA_WAITING_CERTIFICATE_RESPONSE) || (oldcadata.getStatus() == SecConst.CA_ACTIVE) || (oldcadata
                    .getStatus() == SecConst.CA_EXTERNAL))
                    && (oldcadata.getCaId().intValue() == cainfo.getCAId())
                    && (oldcadata.getName().equals(cainfo.getName()))) {
                // Yes, we have all the same DN, CAName and the old CA is either
                // waiting for a certificate response or is active
                // (new CA or active CA that we want to renew)
                // or it is an external CA that we want to issue a new
                // certificate to
                processinternalca = true;
                if (oldcadata.getStatus() == SecConst.CA_EXTERNAL) {
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
                CAData signcadata = CAData.findByIdOrThrow(entityManager, Integer.valueOf(cainfo.getSignedBy()));
                CA signca = signcadata.getCA();
                try {
                    // Check that the signer is valid
                    checkSignerValidity(admin, signcadata);

                    // Get public key from request
                    PublicKey publickey = requestmessage.getRequestPublicKey();

                    // Create cacertificate
                    Certificate cacertificate = null;
                    String subjectAltName = null;
                    if (cainfo instanceof X509CAInfo) {
                        subjectAltName = ((X509CAInfo) cainfo).getSubjectAltName();
                    }
                    EndEntityInformation cadata = new EndEntityInformation("nobody", cainfo.getSubjectDN(), cainfo.getSubjectDN().hashCode(),
                            subjectAltName, null, 0, 0, 0, cainfo.getCertificateProfileId(), null, null, 0, 0, null);
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
                    cacertificate = signca.generateCertificate(cadata, publickey, -1, cainfo.getValidity(), certprofile, sequence);
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
                        CAToken token = new CAToken(new NullCryptoToken());
                        ca.setCAToken(token);

                        // set status to active
                        entityManager.persist(new CAData(cainfo.getSubjectDN(), cainfo.getName(), SecConst.CA_EXTERNAL, ca));
                        // cadatahome.create(cainfo.getSubjectDN(), cainfo.getName(), SecConst.CA_EXTERNAL, ca);
                    } else {
                        if (oldcadata.getStatus() == SecConst.CA_EXTERNAL) {
                            // If it is an external CA we will not import the
                            // certificate later on here, so we want to
                            // update the CA in this instance with the new
                            // certificate so it is visible
                            ca = oldcadata.getCAFromDatabase();
                            ca.setCertificateChain(certchain);
                            if (log.isDebugEnabled()) {
                                log.debug("Storing new certificate chain for external CA " + cainfo.getName() + ", CA token type: "
                                        + ca.getCAToken().getClass().getName());
                            }
                            oldcadata.setCA(ca);
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
        long crlOverlapTime = 10 * SimpleTime.MILLISECONDS_PER_HOUR;
        long deltacrlperiod = 0 * SimpleTime.MILLISECONDS_PER_HOUR;
        int certprofileid = CertTools.isSelfSigned(caCertificate) ? SecConst.CERTPROFILE_FIXED_ROOTCA : SecConst.CERTPROFILE_FIXED_SUBCA;
        String subjectdn = CertTools.getSubjectDN(caCertificate);
        int validity = 0;
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

            cainfo = new X509CAInfo(subjectdn, caname, SecConst.CA_EXTERNAL, new Date(), subjectaltname, certprofileid, validity,
                    CertTools.getNotAfter(x509CaCertificate), CAInfo.CATYPE_X509, signedby, null, null, description, -1, null, policies, crlperiod,
                    crlIssueInterval, crlOverlapTime, deltacrlperiod, crlpublishers, useauthoritykeyidentifier, authoritykeyidentifiercritical,
                    usecrlnumber, crlnumbercritical, "", "", "", "", finishuser, extendedcaserviceinfos, useutf8policytext, approvalsettings,
                    numofreqapprovals, useprintablestringsubjectdn, useldapdnorder, usecrldistpointoncrl, crldistpointoncrlcritical, false, true, // isDoEnforceUniquePublicKeys
                    true, // isDoEnforceUniqueDistinguishedName
                    false, // isDoEnforceUniqueSubjectDNSerialnumber
                    true, // useCertReqHistory
                    true, // useUserStorage
                    true, // useCertificateStorage
                    null // cmpRaAuthSecret
            );
        } else if (StringUtils.equals(caCertificate.getType(), "CVC")) {
            cainfo = new CVCCAInfo(subjectdn, caname, SecConst.CA_EXTERNAL, new Date(), certprofileid, validity, null, CAInfo.CATYPE_CVC, signedby,
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
        CAToken token = new CAToken(new NullCryptoToken());
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
        if (!accessSession.isAuthorizedNoLogging(admin, "/super_administrator")) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoeditca", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw new AuthorizationDeniedException(msg);
        }

        // Get CA info.
        CA ca = caSession.getCAForEdit(admin, caid);
        if (ca.getStatus() == SecConst.CA_OFFLINE) {
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
    public void renewCA(AuthenticationToken admin, int caid, String keystorepass, boolean regenerateKeys) throws CADoesntExistsException,
            AuthorizationDeniedException, CertPathValidatorException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
        if (log.isTraceEnabled()) {
            log.trace(">CAAdminSession, renewCA(), caid=" + caid);
        }
        Collection<Certificate> cachain = null;
        Certificate cacertificate = null;
        // check authorization
        if (!accessSession.isAuthorizedNoLogging(admin, AccessRulesConstants.REGULAR_RENEWCA)) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtorenew", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw new AuthorizationDeniedException(msg);
        }

        // Get CA info.
        try {
            CA ca = caSession.getCAForEdit(admin, caid);

            if (ca.getStatus() == SecConst.CA_OFFLINE) {
                String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getName());
                throw new CryptoTokenOfflineException(msg);
            }

            CAToken caToken = ca.getCAToken();
            if (regenerateKeys) {
                boolean renew = true;
                keystorepass = getDefaultKeyStorePassIfSWAndEmpty(keystorepass, caToken.getCryptoToken());
                // for internal CAs the new keys are always activated
                caTokenSession.generateKeys(admin, caid, keystorepass.toCharArray(), renew, true);
                // We save the CA later on, as the last step
            }

            // if issuer is insystem CA or selfsigned, then generate new certificate.
            if (ca.getSignedBy() != CAInfo.SIGNEDBYEXTERNALCA) {
                if (ca.getSignedBy() == CAInfo.SELFSIGNED) {
                    // create selfsigned certificate
                    String subjectAltName = null;
                    if (ca instanceof X509CA) {
                        X509CA x509ca = (X509CA) ca;
                        subjectAltName = x509ca.getSubjectAltName();
                    }
                    EndEntityInformation cainfodata = new EndEntityInformation("nobody", ca.getSubjectDN(), ca.getSubjectDN().hashCode(),
                            subjectAltName, null, 0, 0, 0, ca.getCertificateProfileId(), null, null, 0, 0, null);

                    CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(ca.getCertificateProfileId());
                    // get from CAtoken to make sure it is fresh
                    String sequence = caToken.getTokenInfo().getKeySequence();
                    cacertificate = ca.generateCertificate(cainfodata, ca.getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN), -1,
                            ca.getValidity(), certprofile, sequence);
                    // Build Certificate Chain
                    cachain = new ArrayList<Certificate>();
                    cachain.add(cacertificate);

                } else {
                    // Resign with CA above.
                    if (ca.getSignedBy() > CAInfo.SPECIALCAIDBORDER || ca.getSignedBy() < 0) {
                        // Create CA signed by other internal CA.
                        CAData signcadata = CAData.findByIdOrThrow(entityManager, Integer.valueOf(ca.getSignedBy()));
                        CA signca = signcadata.getCA();
                        // Check that the signer is valid
                        checkSignerValidity(admin, signcadata);
                        // Create cacertificate
                        String subjectAltName = null;
                        if (ca instanceof X509CA) {
                            X509CA x509ca = (X509CA) ca;
                            subjectAltName = x509ca.getSubjectAltName();
                        }
                        EndEntityInformation cainfodata = new EndEntityInformation("nobody", ca.getSubjectDN(), ca.getSubjectDN().hashCode(),
                                subjectAltName, null, 0, 0, 0, ca.getCertificateProfileId(), null, null, 0, 0, null);

                        CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(ca.getCertificateProfileId());
                        String sequence = caToken.getTokenInfo().getKeySequence(); // get from CAtoken to make sure it is fresh
                        cacertificate = signca.generateCertificate(cainfodata, ca.getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN), -1,
                                ca.getValidity(), certprofile, sequence);
                        // Build Certificate Chain
                        Collection<Certificate> rootcachain = signca.getCertificateChain();
                        cachain = new ArrayList<Certificate>();
                        cachain.add(cacertificate);
                        cachain.addAll(rootcachain);
                    }
                }
            } else {
                // We should never get here
                log.error("Directly renewing a CA signed by external can not be done");
                throw new NotSupportedException("Directly renewing a CA signed by external can not be done");
            }
            // Set statuses and expire time
            ca.setExpireTime(CertTools.getNotAfter(cacertificate));
            ca.setStatus(SecConst.CA_ACTIVE);
            // Set the new certificate chain that we have created above
            ca.setCertificateChain(cachain);
            // We need to save all this, audit logging that the CA is changed
            caSession.editCA(admin, ca, true);

            // Publish the new CA certificate
            publishCACertificate(admin, cachain, ca.getCRLPublishers(), ca.getSubjectDN());
            crlCreateSession.forceCRL(admin, caid);
            crlCreateSession.forceDeltaCRL(admin, caid);
            // Audit log
            String msg = intres.getLocalizedMessage("caadmin.renewdca", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.CA_RENEWED, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
        } catch (CryptoTokenOfflineException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorrenewca", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.CA_RENEWED, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw e;
        } catch (CryptoTokenAuthenticationFailedException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorrenewca", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.CA_RENEWED, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw e;
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("caadmin.errorrenewca", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.CA_RENEWED, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw new EJBException(e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<CAAdminSession, renewCA(), caid=" + caid);
        }
    }

    /**
     * Soft KeyStores can not have empty passwords, it probably means to use the default one
     * 
     * @param keystorepass The password that can not be empty if SW.
     * @param tokenInfo Used to determine if it is a soft token
     * @return The password to use.
     */
    private String getDefaultKeyStorePassIfSWAndEmpty(final String keystorepass, CryptoToken token) {
        if (token instanceof SoftCryptoToken && StringUtils.isEmpty(keystorepass)) {
            log.debug("Using system default keystore password");
            final String newKeystorepass = CesecoreConfiguration.getCaKeyStorePass();
            return StringTools.passwordDecryption(newKeystorepass, "ca.keystorepass");
        }
        return keystorepass;
    }

    @Override
    public void revokeCA(AuthenticationToken admin, int caid, int reason) throws CADoesntExistsException, AuthorizationDeniedException {
        // check authorization
        if (!accessSession.isAuthorizedNoLogging(admin, "/super_administrator")) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtorevoke", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw new AuthorizationDeniedException(msg);
        }
        // Get CA info.
        CA ca = caSession.getCAForEdit(admin, caid);
        try {
            // Revoke CA certificate
            revocationSession.revokeCertificate(admin, ca.getCACertificate(), ca.getCRLPublishers(), reason, ca.getSubjectDN());
            // Revoke all certificates generated by CA
            if (ca.getStatus() != SecConst.CA_EXTERNAL) {
                certificateStoreSession.revokeAllCertByCA(admin, ca.getSubjectDN(), RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE);
                Collection<Integer> caids = new ArrayList<Integer>();
                caids.add(Integer.valueOf(ca.getCAId()));
                crlCreateSession.createCRLs(admin, caids, 0);
            }
            ca.setRevocationReason(reason);
            ca.setRevocationDate(new Date());
            if (ca.getStatus() != SecConst.CA_EXTERNAL) {
                ca.setStatus(SecConst.CA_REVOKED);
            }
            // Store new status, audit logging
            caSession.editCA(admin, ca, true);
            String msg = intres.getLocalizedMessage("caadmin.revokedca", ca.getName(), Integer.valueOf(reason));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.CA_REVOKED, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("caadmin.errorrevoke", ca.getName());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.CA_REVOKED, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
            		String.valueOf(caid), null, null, details);
            throw new EJBException(e);
        }
    }

    @Override
    public void importCAFromKeyStore(AuthenticationToken admin, String caname, byte[] p12file, String keystorepass, String privkeypass,
            String privateSignatureKeyAlias, String privateEncryptionKeyAlias) throws Exception {
        try {
            // check authorization
            if (!accessSession.isAuthorizedNoLogging(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR)) {
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
            String msg = intres.getLocalizedMessage("caadmin.errorimportca", caname, "PKCS12", e.getMessage());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.CA_IMPORT, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), null, null, null,
                    details);
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
            if (!accessSession.isAuthorizedNoLogging(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR)) {
                String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoremovecatoken", caname);
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), null, null,
                        null, details);
            }
            CA thisCa = caSession.getCAForEdit(admin, caname);
            CAToken thisCAToken = thisCa.getCAToken();
            if (!(thisCAToken.getCryptoToken() instanceof SoftCryptoToken)) {
                throw new Exception("Cannot export anything but a soft token.");
            }
            // Create a new CAToken with the same properties but OFFLINE and without keystore
            CryptoToken cryptotoken = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), thisCAToken.getCryptoToken()
                    .getProperties(), null, thisCAToken.getCryptoToken().getId());
            cryptotoken.deactivate(); // Sets status to offline
            CAToken catoken = new CAToken(cryptotoken);
            catoken.setKeySequence(catoken.getKeySequence());
            catoken.setKeySequenceFormat(catoken.getKeySequenceFormat());
            catoken.setSignatureAlgorithm(catoken.getTokenInfo().getSignatureAlgorithm());
            catoken.setEncryptionAlgorithm(catoken.getTokenInfo().getEncryptionAlgorithm());
            thisCa.setCAToken(catoken);
            // Save to database
            caSession.editCA(admin, thisCa, false);
            // Log
            String msg = intres.getLocalizedMessage("caadmin.removedcakeystore", Integer.valueOf(thisCa.getCAId()));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.CA_REMOVETOKEN, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(thisCa.getCAId()), null,
                    null, details);
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("caadmin.errorremovecakeystore", caname, "PKCS12", e.getMessage());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.CA_REMOVETOKEN, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), null, null,
                    null, details);
            throw new EJBException(e);
        }
    	if (log.isTraceEnabled()) {
    		log.trace("<removeCAKeyStore");
    	}
    }

    @Override
    public void restoreCAKeyStore(AuthenticationToken admin, String caname, byte[] p12file, String keystorepass, String privkeypass,
            String privateSignatureKeyAlias, String privateEncryptionKeyAlias) {
    	if (log.isTraceEnabled()) {
    		log.trace(">restoreCAKeyStore");
    	}
        try {
            // check authorization
            if (!accessSession.isAuthorizedNoLogging(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR)) {
                String msg = intres.getLocalizedMessage("caadmin.notauthorizedtorestorecatoken", caname);
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), null, null,
                        null, details);
            }

            CA thisCa = caSession.getCAForEdit(admin, caname);

            CAToken thisCAToken = thisCa.getCAToken();
            if (!(thisCAToken.getCryptoToken() instanceof SoftCryptoToken)) {
                throw new Exception("Cannot restore anything but a soft token.");
            }

            // Only restore to an offline CA
            if (thisCAToken.getTokenStatus() != CryptoToken.STATUS_OFFLINE) {
                throw new Exception("The CA already has an active CA token.");
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

            // Sign something to see that we are restoring the right private
            // signature key
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
            CAToken catoken = importKeysToCAToken(keystorepass, thisCAToken.getTokenInfo().getProperties(), p12PrivateSignatureKey,
                    p12PublicSignatureKey, p12PrivateEncryptionKey, p12PublicEncryptionKey, signatureCertChain, thisCa.getCAId());
            thisCa.setCAToken(catoken);
            // Finally save the CA
            caSession.editCA(admin, thisCa, true);
            // Log
            String msg = intres.getLocalizedMessage("caadmin.restoredcakeystore", Integer.valueOf(thisCa.getCAId()));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.CA_RESTORETOKEN, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(thisCa.getCAId()), null,
                    null, details);
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("caadmin.errorrestorecakeystore", caname, "PKCS12", e.getMessage());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.CA_RESTORETOKEN, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), null, null,
                    null, details);
            throw new EJBException(e);
        }
    	if (log.isTraceEnabled()) {
    		log.trace("<restoreCAKeyStore");
    	}        
    }

    @Override
    public void importCAFromKeys(AuthenticationToken admin, String caname, String keystorepass, Certificate[] signatureCertChain,
            PublicKey p12PublicSignatureKey, PrivateKey p12PrivateSignatureKey, PrivateKey p12PrivateEncryptionKey, PublicKey p12PublicEncryptionKey)
            throws CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException, IllegalCryptoTokenException, CADoesntExistsException,
            AuthorizationDeniedException, CAExistsException {
        // Transform into token
        int tokenId = StringTools.strip(CertTools.getSubjectDN(signatureCertChain[0])).hashCode(); // caid
        CAToken catoken = importKeysToCAToken(keystorepass, null, p12PrivateSignatureKey, p12PublicSignatureKey, p12PrivateEncryptionKey,
                p12PublicEncryptionKey, signatureCertChain, tokenId);
        log.debug("CA-Info: " + catoken.getTokenInfo().getSignatureAlgorithm() + " " + catoken.getTokenInfo().getEncryptionAlgorithm());
        // Identify the key algorithms for extended CA services, OCSP, XKMS, CMS
        String keyAlgorithm = AlgorithmTools.getKeyAlgorithm(p12PublicSignatureKey);
        String keySpecification = AlgorithmTools.getKeySpecification(p12PublicSignatureKey);
        if (keyAlgorithm == null || keyAlgorithm == AlgorithmConstants.KEYALGORITHM_RSA) {
            keyAlgorithm = AlgorithmConstants.KEYALGORITHM_RSA;
            keySpecification = "2048";
        }
        // Do the general import
        CA ca = importCA(admin, caname, keystorepass, signatureCertChain, catoken, keyAlgorithm, keySpecification);
        // Finally audit log
        String msg = intres.getLocalizedMessage("caadmin.importedca", caname, "PKCS12", ca.getStatus());
        Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        auditSession.log(EjbcaEventTypes.CA_IMPORT, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(ca.getCAId()), null, null,
                details);
    }

    /**
     * Method that import CA token keys from a P12 file. Was originally used when upgrading from old EJBCA versions. Only supports SHA1 and SHA256
     * with RSA or ECDSA and SHA1 with DSA.
     */
    private CAToken importKeysToCAToken(String authenticationCode, Properties tokenProperties, PrivateKey privatekey, PublicKey publickey,
            PrivateKey privateEncryptionKey, PublicKey publicEncryptionKey, Certificate[] caSignatureCertChain, int tokenId)
            throws CryptoTokenAuthenticationFailedException, IllegalCryptoTokenException {

    	if (tokenProperties == null) {
    		tokenProperties = new Properties();
    	}
        // If we don't give an authentication code, perhaps we have autoactivation enabled
        char[] authCode;
        if (StringUtils.isEmpty(authenticationCode)) {
            // See if we have auto activation password defined
            String pin = BaseCryptoToken.getAutoActivatePin(tokenProperties);
            if (pin == null) {
                String msg = intres.getLocalizedMessage("token.authcodemissing", Integer.valueOf(tokenId));
                log.info(msg);
                throw new CryptoTokenAuthenticationFailedException(msg);
            }
            authCode = pin.toCharArray();
        } else {
            authCode = authenticationCode.toCharArray();
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
            final String sigkeyspec = AlgorithmTools.getKeySpecification(publickey);
            tokenProperties.setProperty(CryptoToken.KEYSPEC_PROPERTY, sigkeyspec);
            tokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            tokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            tokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);

            // Write the keystore to byte[] that we can feed to crypto token factory
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            keystore.store(baos, authCode);

            // Now we have the PKCS12 keystore, from this we can create the CAToken
            final CryptoToken cryptoToken = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), tokenProperties, baos.toByteArray(),
                    tokenId);
            final CAToken catoken = new CAToken(cryptoToken);
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
        }
    } // importKeys

    @Override
    public void importCAFromHSM(AuthenticationToken admin, String caname, Certificate[] signatureCertChain, String catokenpassword,
            String catokenclasspath, String catokenproperties) throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            IllegalCryptoTokenException, CADoesntExistsException, AuthorizationDeniedException, CAExistsException {
        Certificate cacert = signatureCertChain[0];
        int caId = StringTools.strip(CertTools.getSubjectDN(cacert)).hashCode();
        // Just convert string properties in a standard way...
        CATokenInfo info = new CATokenInfo();
        info.setProperties(catokenproperties);
        // Create the crypt token
        CryptoToken cryptoToken = CryptoTokenFactory.createCryptoToken(PKCS11CryptoToken.class.getName(), info.getProperties(), null, caId);
        CAToken catoken = new CAToken(cryptoToken);
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

        catoken.getCryptoToken().activate(catokenpassword.toCharArray());

        // Identify the key algorithms for extended CA services, OCSP, XKMS, CMS
        String keyAlgorithm = AlgorithmTools.getKeyAlgorithm(cacert.getPublicKey());
        String keySpecification = AlgorithmTools.getKeySpecification(cacert.getPublicKey());
        if (keyAlgorithm == null || keyAlgorithm == AlgorithmConstants.KEYALGORITHM_RSA) {
            keyAlgorithm = AlgorithmConstants.KEYALGORITHM_RSA;
            keySpecification = "2048";
        }
        // Do the general import
        importCA(admin, caname, catokenpassword, signatureCertChain, catoken, keyAlgorithm, keySpecification);
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
        int certprof = SecConst.CERTPROFILE_FIXED_SUBCA;
        String description = "Imported external signed CA";
        Certificate caSignatureCertificate = signatureCertChain[0];
        ArrayList<Certificate> certificatechain = new ArrayList<Certificate>();
        for (int i = 0; i < signatureCertChain.length; i++) {
            certificatechain.add(signatureCertChain[i]);
        }
        if (signatureCertChain.length == 1) {
            if (verifyIssuer(caSignatureCertificate, caSignatureCertificate)) {
                signedby = CAInfo.SELFSIGNED;
                certprof = SecConst.CERTPROFILE_FIXED_ROOTCA;
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

            cainfo = new X509CAInfo(CertTools.getSubjectDN(caSignatureCertificate), caname, SecConst.CA_ACTIVE, new Date(), "", certprof, validity,
                    CertTools.getNotAfter(caSignatureCertificate), // Expiretime
                    CAInfo.CATYPE_X509, signedby, certificatechain, catoken.getTokenInfo(), description, -1, // revocationReason
                    null, // revocationDate
                    null, // PolicyId
                    24 * SimpleTime.MILLISECONDS_PER_HOUR, // CRLPeriod
                    0 * SimpleTime.MILLISECONDS_PER_HOUR, // CRLIssuePeriod
                    10 * SimpleTime.MILLISECONDS_PER_HOUR, // CRLOverlapTime
                    0 * SimpleTime.MILLISECONDS_PER_HOUR, // DeltaCRLPeriod
                    crlpublishers, // CRL publishers
                    true, // Authority Key Identifier
                    false, // Authority Key Identifier Critical
                    true, // CRL Number
                    false, // CRL Number Critical
                    "", // Default CRL Dist Point
                    "", // Default CRL Issuer
                    "", // Default OCSP Service Locator
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
            cainfo = new CVCCAInfo(CertTools.getSubjectDN(caSignatureCertificate), caname, SecConst.CA_ACTIVE, new Date(), certprof, validity,
                    CertTools.getNotAfter(caSignatureCertificate), CAInfo.CATYPE_CVC, signedby, certificatechain, catoken.getTokenInfo(),
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
        catoken.getCryptoToken().activate(keystorepass.toCharArray());
        try {
        	ca.setCAToken(catoken);
        } catch (InvalidAlgorithmException e) {
        	throw new IllegalCryptoTokenException(e);
        }
        ca.setCertificateChain(certificatechain);
        log.debug("CA-Info: " + catoken.getTokenInfo().getSignatureAlgorithm() + " " + ca.getCAToken().getTokenInfo().getEncryptionAlgorithm());
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
    public byte[] exportCAKeyStore(AuthenticationToken admin, String caname, String keystorepass, String privkeypass,
            String privateSignatureKeyAlias, String privateEncryptionKeyAlias) throws Exception {
        log.trace(">exportCAKeyStore");
        try {
            CAData cadata = CAData.findByNameOrThrow(entityManager, caname);
            CA thisCa = cadata.getCA();
            // Make sure we are not trying to export a hard or invalid token
            CAToken thisCAToken = thisCa.getCAToken();
            if (!(thisCAToken.getCryptoToken() instanceof SoftCryptoToken)) {
                throw new IllegalCryptoTokenException("Cannot export anything but a soft token.");
            }
            // Check authorization
            if (!accessSession.isAuthorizedNoLogging(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR)) {
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
            thisCAToken.getCryptoToken().activate(keystorepass.toCharArray());

            PrivateKey p12PrivateEncryptionKey = thisCAToken.getPrivateKey(SecConst.CAKEYPURPOSE_KEYENCRYPT);
            PublicKey p12PublicEncryptionKey = thisCAToken.getPublicKey(SecConst.CAKEYPURPOSE_KEYENCRYPT);
            PrivateKey p12PrivateCertSignKey = thisCAToken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN);
            PrivateKey p12PrivateCRLSignKey = thisCAToken.getPrivateKey(SecConst.CAKEYPURPOSE_CRLSIGN);
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
                        p12PublicEncryptionKey, thisCAToken.getTokenInfo().getEncryptionAlgorithm(), true, X509KeyUsage.keyEncipherment);
                log.debug("Exporting with sigAlgorithm " + AlgorithmTools.getSignatureAlgorithm(certificateChainSignature[0]) + "encAlgorithm="
                        + thisCAToken.getTokenInfo().getEncryptionAlgorithm());
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
        ArrayList<Certificate> returnval = new ArrayList<Certificate>();

        try {
            Collection<Integer> caids = caSession.getAvailableCAs();
            Iterator<Integer> iter = caids.iterator();
            while (iter.hasNext()) {
                Integer caid = iter.next();
                CAData cadata = CAData.findById(entityManager, Integer.valueOf(caid));
                if (cadata == null) {
                    log.error("Can't find CA: " + caid);
                }
                CA ca = cadata.getCA();
                if (log.isDebugEnabled()) {
                    log.debug("Getting certificate chain for CA: " + ca.getName() + ", " + ca.getCAId());
                }
                returnval.add(ca.getCACertificate());
            }
        } catch (UnsupportedEncodingException uee) {
            throw new EJBException(uee);
        } catch (IllegalCryptoTokenException e) {
            throw new EJBException(e);
        }
        return returnval;
    }

    @Override
    public void activateCAToken(AuthenticationToken admin, int caid, String authorizationcode, GlobalConfiguration gc)
            throws AuthorizationDeniedException, CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException, ApprovalException,
            WaitingForApprovalException, CADoesntExistsException {
        // Authorize
        if (!accessSession.isAuthorizedNoLogging(admin, AccessRulesConstants.REGULAR_ACTIVATECA)) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoactivatetoken", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(caid), null, null, details);
            throw new AuthorizationDeniedException(msg);
        }

        // Get CA also check authorization for this specific CA
        CAInfo cainfo = caSession.getCAInfo(admin, caid);
        if (cainfo.getStatus() == SecConst.CA_EXTERNAL) {
            String msg = intres.getLocalizedMessage("caadmin.catokenexternal", Integer.valueOf(caid));
            log.info(msg);
            return;
        }
        // Check if approvals is required.
        int numOfApprovalsRequired = getNumOfApprovalRequired(CAInfo.REQ_APPROVAL_ACTIVATECATOKEN, cainfo.getCAId(), cainfo.getCertificateProfileId());
        ActivateCATokenApprovalRequest ar = new ActivateCATokenApprovalRequest(cainfo.getName(), authorizationcode, admin, numOfApprovalsRequired,
                caid, ApprovalDataVO.ANY_ENDENTITYPROFILE);
        if (ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_ACTIVATECATOKEN)) {
            approvalSession.addApprovalRequest(admin, ar, gc);
            String msg = intres.getLocalizedMessage("ra.approvalcaactivation");
            throw new WaitingForApprovalException(msg);
        }
        if (caid >= 0 && caid <= CAInfo.SPECIALCAIDBORDER) {
            String msg = intres.getLocalizedMessage("caadmin.erroractivatetoken", Integer.valueOf(caid));
            log.info(msg);
            throw new CryptoTokenAuthenticationFailedException(msg);
        }
        boolean cATokenDisconnected = false;
        if ((cainfo.getCATokenInfo()).getTokenStatus() == CryptoToken.STATUS_OFFLINE) {
        	cATokenDisconnected = true;
        }
        if (cainfo.getStatus() == SecConst.CA_OFFLINE || cATokenDisconnected) {
            try {
                // CA Token session also handles audit
                caTokenSession.activateCAToken(admin, caid, authorizationcode.toCharArray());
                // If the CA was off-line, this is activation of the CA, if
                // only the token was disconnected we only connect the token
                // If CA is waiting for certificate response, expired or revoked we can not
                // change this status just by activating the token.
                if ((cainfo.getStatus() == SecConst.CA_OFFLINE)) {
                	CA ca = caSession.getCAForEdit(admin, caid);
                    ca.setStatus(SecConst.CA_ACTIVE);
                    caSession.editCA(admin, ca, false);
                }
            } catch (CryptoTokenAuthenticationFailedException e) {
                String msg = intres.getLocalizedMessage("caadmin.badcaactivationcode", cainfo.getName());
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EventTypes.CA_TOKENACTIVATE, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                        String.valueOf(caid), null, null, details);
                throw e;
            } catch (IllegalCryptoTokenException e) {
                throw new EJBException(e);
            }
        } else {
            String msg = intres.getLocalizedMessage("caadmin.errornotoffline", cainfo.getName());
            log.info(msg);
            throw new CryptoTokenAuthenticationFailedException(msg);
        }
    }

    private static final ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_ACTIVATECATOKEN = { new ApprovalOveradableClassName(
            org.ejbca.core.model.approval.approvalrequests.ActivateCATokenApprovalRequest.class.getName(), null), };

    @Override
    public void deactivateCAToken(AuthenticationToken admin, int caid) throws AuthorizationDeniedException, CADoesntExistsException,
            IllegalCryptoTokenException {
        // Authorize
        if (!accessSession.isAuthorizedNoLogging(admin, AccessRulesConstants.REGULAR_ACTIVATECA)) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtodeactivatetoken", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(caid), null, null, details);
            throw new AuthorizationDeniedException(msg);
        }
        // CA Token session also handles audit
        caTokenSession.deactivateCAToken(admin, caid);
        // Setting CA token to offline, makes the CA offline
		CA ca = caSession.getCAForEdit(admin, caid);
		ca.setStatus(SecConst.CA_OFFLINE);
		caSession.editCA(admin, ca, false);
    }

    /** Method used to check if certificate profile id exists in any CA. */
    @Override
    public boolean existsCertificateProfileInCAs(int certificateprofileid) {
        boolean returnval = false;
        try {
            Collection<CAData> result = CAData.findAll(entityManager);
            Iterator<CAData> iter = result.iterator();
            while (iter.hasNext()) {
                CAData cadata = iter.next();
                returnval = returnval || (cadata.getCA().getCertificateProfileId() == certificateprofileid);
            }
        } catch (java.io.UnsupportedEncodingException e) {
        } catch (IllegalCryptoTokenException e) {
            if (log.isDebugEnabled()) {
                log.debug("CA has illegal crypto token: ", e);
            }
        }
        return returnval;
    }

    @Override
    public byte[] encryptWithCA(int caid, byte[] data) throws Exception {
        CAData caData = CAData.findByIdOrThrow(entityManager, Integer.valueOf(caid));
        return caData.getCA().encryptData(data, SecConst.CAKEYPURPOSE_KEYENCRYPT);
    }

    @Override
    public byte[] decryptWithCA(int caid, byte[] data) throws Exception {
        CAData caData = CAData.findByIdOrThrow(entityManager, Integer.valueOf(caid));
        return caData.getCA().decryptData(data, SecConst.CAKEYPURPOSE_KEYENCRYPT);
    }

    @Override
    public boolean exitsPublisherInCAs(AuthenticationToken admin, int publisherid) {
        boolean returnval = false;
        try {
            Collection<CAData> result = CAData.findAll(entityManager);
            Iterator<CAData> iter = result.iterator();
            while (iter.hasNext()) {
                CAData cadata = iter.next();
                Iterator<Integer> pubiter = cadata.getCA().getCRLPublishers().iterator();
                while (pubiter.hasNext()) {
                    Integer pubInt = pubiter.next();
                    returnval = returnval || (pubInt.intValue() == publisherid);
                }
            }
        } catch (java.io.UnsupportedEncodingException e) {
        } catch (IllegalCryptoTokenException e) {
            if (log.isDebugEnabled()) {
                log.debug("CA has illegal crypto token: ", e);
            }
        }
        return returnval;
    }

    @Override
    public int getNumOfApprovalRequired(int action, int caid, int certProfileId) {
        int retval = 0;
        AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CAAdminSessionBean.getNumOfApprovalRequired"));
        CAInfo cainfo = null;
        try {
            cainfo = caSession.getCAInfo(admin, caid);
        } catch (CADoesntExistsException e) {
            // NOPMD ignore cainfo is null
        } catch (AuthorizationDeniedException e) {
            // Should never happen
            log.error("AlwaysAllowLocalAuthenticationToken was not allowed access: ", e);
            throw new EJBException(e);
        }
        if (cainfo != null) {
            if (cainfo.isApprovalRequired(action)) {
                retval = cainfo.getNumOfReqApprovals();
            }
            CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(certProfileId);
            if (certprofile != null && certprofile.isApprovalRequired(action)) {
                retval = Math.max(retval, certprofile.getNumOfReqApprovals());
            }
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
                int type = SecConst.CERTTYPE_ENDENTITY;
                if (CertTools.isCA(cert)) {
                    // this is a CA
                    if (isSelfSigned) {
                        type = SecConst.CERTTYPE_ROOTCA;
                    } else {
                        type = SecConst.CERTTYPE_SUBCA;
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
                    type = SecConst.CERTTYPE_ROOTCA;
                } else {
                    // If and end entity, the next certificate in the chain
                    // should be the CA of this end entity
                    if ((i + 1) < certs.length) {
                        Certificate cacert = (Certificate) certs[i + 1];
                        cafp = CertTools.getFingerprintAsString(cacert);
                    }
                }

                String name = "SYSTEMCERT";
                if (type != SecConst.CERTTYPE_ENDENTITY) {
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
                    certificateStoreSession.storeCertificate(admin, cert, name, cafp, SecConst.CERT_ACTIVE, type, profileId, tag, updateTime);
                } else {
                    updateTime = ci.getUpdateTime().getTime();
                    profileId = ci.getCertificateProfileId();
                    tag = ci.getTag();
                }
                if (usedpublishers != null) {
                    publisherSession.storeCertificate(admin, usedpublishers, cert, cafp, null, caDataDN, fingerprint, SecConst.CERT_ACTIVE, type, -1,
                            RevokedCertInfo.NOT_REVOKED, tag, profileId, updateTime, null);
                }
            }
        } catch (javax.ejb.CreateException ce) {
            throw new EJBException(ce);
        }
    }

    @Override
    public void publishCRL(AuthenticationToken admin, Certificate caCert, Collection<Integer> usedpublishers, String caDataDN,
            boolean doPublishDeltaCRL) {
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
    public Collection<Integer> getAuthorizedPublisherIds(AuthenticationToken admin) {
        HashSet<Integer> returnval = new HashSet<Integer>();
        try {
            // If superadmin return all available publishers
            returnval.addAll(publisherSession.getAllPublisherIds(admin));
        } catch (AuthorizationDeniedException e1) {
            // If regular CA-admin return publishers he is authorized to
            Iterator<Integer> authorizedcas = caSession.getAvailableCAs(admin).iterator();
            while (authorizedcas.hasNext()) {
                int caid = authorizedcas.next().intValue();
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
        String returnval = "";
        final AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CAAdminSession healthCheck"));
        boolean caTokenSignTest = EjbcaConfiguration.getHealthCheckCaTokenSignTest();
        if (log.isDebugEnabled()) {
            log.debug("CaTokenSignTest: " + caTokenSignTest);
        }
        Iterator<Integer> iter = caSession.getAvailableCAs().iterator();
        while (iter.hasNext()) {
            int caid = iter.next().intValue();
            try {
                CAInfo cainfo = caSession.getCAInfo(admin, caid, caTokenSignTest);
                if ((cainfo.getStatus() == SecConst.CA_ACTIVE) && cainfo.getIncludeInHealthCheck()) {
                    int tokenstatus = cainfo.getCATokenInfo().getTokenStatus();
                    if (tokenstatus == CryptoToken.STATUS_OFFLINE) {
                        returnval += "\nCA: Error CA Token is disconnected, CA Name : " + cainfo.getName();
                        log.error("Error CA Token is disconnected, CA Name : " + cainfo.getName());
                    }
                }
            } catch (CADoesntExistsException e) {
                if (log.isDebugEnabled()) {
                    log.debug("CA with id '" + caid + "' does not exist.");
                }
            } catch (AuthorizationDeniedException e) {
                log.debug("Not authorized to CA? We should be authorized to all?", e);
            }
        }
        return returnval;
    }

    @Override
    public ExtendedCAServiceResponse extendedService(AuthenticationToken admin, int caid, ExtendedCAServiceRequest request)
            throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException,
            CADoesntExistsException, AuthorizationDeniedException {
        // Get CA that will process request
        CA ca = caSession.getCA(admin, caid);
        if (log.isDebugEnabled()) {
            log.debug("Extended service with request class '" + request.getClass().getName() + "' called for CA '" + ca.getName() + "'");
        }
        return ca.extendedService(request);
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
    private void checkSignerValidity(AuthenticationToken admin, CAData signcadata) throws UnsupportedEncodingException, IllegalCryptoTokenException {
        // Check validity of signers certificate
        Certificate signcert = (Certificate) signcadata.getCA().getCACertificate();
        try {
            CertTools.checkValidity(signcert, new Date());
        } catch (CertificateExpiredException ce) {
            // Signers Certificate has expired.
            signcadata.setStatus(SecConst.CA_EXPIRED);
            String msg = intres.getLocalizedMessage("signsession.caexpired", signcadata.getSubjectDN());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.CA_VALIDITY, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(signcadata.getCaId()), null, null, details);
            throw new EJBException(ce);
        } catch (CertificateNotYetValidException cve) {
            String msg = intres.getLocalizedMessage("signsession.canotyetvalid", signcadata.getSubjectDN());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.CA_VALIDITY, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(signcadata.getCaId()), null, null, details);
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
                    ca.initExtendedService(ExtendedCAServiceTypes.TYPE_OCSPEXTENDEDSERVICE, ca);
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
                    ca.initExtendedService(ExtendedCAServiceTypes.TYPE_XKMSEXTENDEDSERVICE, ca);
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
                    ca.initExtendedService(ExtendedCAServiceTypes.TYPE_CMSEXTENDEDSERVICE, ca);
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
    public void flushCACache() {
        // Just forward the call, because in CaSession it is only in the local interface and we
        // want to be able to use it from CLI
        caSession.flushCACache();
    }

}
