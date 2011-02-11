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
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;

import javax.annotation.PostConstruct;
import javax.ejb.CreateException;
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
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.core.ejb.ca.crl.CrlCreateSessionLocal;
import org.cesecore.core.ejb.ca.store.CertificateProfileSessionLocal;
import org.cesecore.core.ejb.log.LogSessionLocal;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ErrorCode;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.authorization.AuthorizationSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionLocal;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalExecutorUtil;
import org.ejbca.core.model.approval.ApprovalOveradableClassName;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.approvalrequests.ActivateCATokenApprovalRequest;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.authorization.Authorizer;
import org.ejbca.core.model.ca.NotSupportedException;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.CACacheManager;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.CAExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.CVCCA;
import org.ejbca.core.model.ca.caadmin.CVCCAInfo;
import org.ejbca.core.model.ca.caadmin.IllegalKeyStoreException;
import org.ejbca.core.model.ca.caadmin.X509CA;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceResponse;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceInfo;
import org.ejbca.core.model.ca.catoken.CATokenAuthenticationFailedException;
import org.ejbca.core.model.ca.catoken.CATokenConstants;
import org.ejbca.core.model.ca.catoken.CATokenContainer;
import org.ejbca.core.model.ca.catoken.CATokenContainerImpl;
import org.ejbca.core.model.ca.catoken.CATokenInfo;
import org.ejbca.core.model.ca.catoken.CATokenManager;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.catoken.HardCATokenInfo;
import org.ejbca.core.model.ca.catoken.ICAToken;
import org.ejbca.core.model.ca.catoken.NullCATokenInfo;
import org.ejbca.core.model.ca.catoken.SoftCATokenInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificatePolicy;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.core.model.util.AlgorithmTools;
import org.ejbca.core.protocol.IRequestMessage;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.PKCS10RequestMessage;
import org.ejbca.core.protocol.X509ResponseMessage;
import org.ejbca.core.protocol.certificatestore.CertificateCacheFactory;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.SimpleTime;
import org.ejbca.util.StringTools;
import org.ejbca.util.keystore.KeyTools;

/**
 * Administrates and manages CAs in EJBCA system.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "CAAdminSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CAAdminSessionBean implements CAAdminSessionLocal, CAAdminSessionRemote {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(CAAdminSessionBean.class);

    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    @EJB
    private LogSessionLocal logSession;
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CrlCreateSessionLocal crlCreateSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private ApprovalSessionLocal approvalSession;

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @PostConstruct
    public void postConstruct() {
        CryptoProviderTools.installBCProvider();
    }

    @Override
    public void initializeAndUpgradeCAs(Admin admin) {
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
    		} catch (IllegalKeyStoreException e) {
    			log.error("IllegalKeyStoreException trying to load CA with name: " + caname, e);
    		}
    	}
    }

    @Override
    public void createCA(Admin admin, CAInfo cainfo) throws CAExistsException, AuthorizationDeniedException, CATokenOfflineException,
            CATokenAuthenticationFailedException {
    	if (log.isTraceEnabled()) {
    		log.trace(">createCA: "+cainfo.getName());
    	}
        int castatus = SecConst.CA_OFFLINE;
        // Check that administrator has superadminstrator rights.
        if(!authorizationSession.isAuthorizedNoLog(admin, "/super_administrator")) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtocreateca", "create", cainfo.getName());
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,
                    msg);
            throw new AuthorizationDeniedException(msg);
        }
        // Check that CA doesn't already exists
        int caid = cainfo.getCAId();
        if (caid >= 0 && caid <= CAInfo.SPECIALCAIDBORDER) {
        	String msg = intres.getLocalizedMessage("caadmin.wrongcaid", Integer.valueOf(caid));
        	logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg);
        	throw new CAExistsException(msg);
        }
        if (CAData.findById(entityManager, Integer.valueOf(caid)) != null) {
        	String msg = intres.getLocalizedMessage("caadmin.caexistsid", Integer.valueOf(caid));
        	logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg);
        	throw new CAExistsException(msg);
        }
        if (CAData.findByName(entityManager, cainfo.getName()) != null) {
        	String msg = intres.getLocalizedMessage("caadmin.caexistsname", cainfo.getName());
        	logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg);
        	throw new CAExistsException(msg);
        }
        // Create CAToken
        CATokenInfo catokeninfo = cainfo.getCATokenInfo();
        CATokenContainer catoken = new CATokenContainerImpl(catokeninfo, cainfo.getCAId());
        String authCode = catokeninfo.getAuthenticationCode();
        authCode = getDefaultKeyStorePassIfSWAndEmpty(authCode, catokeninfo);
        if (catokeninfo instanceof SoftCATokenInfo) {
            try {
                // There are two ways to get the authentication code:
                // 1. The user provided one when creating the CA on the create
                // CA page
                // 2. We use the system default password
                boolean renew = false;
                catoken.generateKeys(authCode, renew, true);
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("caadmin.errorcreatetoken");
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg, e);
                throw new EJBException(e);
            }
        }
        try {
            catoken.activate(authCode);
        } catch (CATokenAuthenticationFailedException ctaf) {
            String msg = intres.getLocalizedMessage("caadmin.errorcreatetokenpin");
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg, ctaf);
            throw ctaf;
        } catch (CATokenOfflineException ctoe) {
            String msg = intres.getLocalizedMessage("error.catokenoffline", cainfo.getName());
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg, ctoe);
            throw ctoe;
        }

        // Create CA
        CA ca = null;
        // The certificate profile used for the CAs certificate
        CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(admin, cainfo.getCertificateProfileId());
        // AltName is not implemented for all CA types
        String caAltName = null;
        // X509 CA is the normal type of CA
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
            caAltName = x509cainfo.getSubjectAltName();
        } else {
            // CVC CA is a special type of CA for EAC electronic passports
            log.info("Creating a CVC CA");
            CVCCAInfo cvccainfo = (CVCCAInfo) cainfo;
            // Create CVCCA
            ca = new CVCCA(cvccainfo);
            ca.setCAToken(catoken);
        }

        // Certificate chain
        Collection<Certificate> certificatechain = null;
        String sequence = catoken.getCATokenInfo().getKeySequence(); // get from CAtoken to make sure it is fresh
        if (cainfo.getSignedBy() == CAInfo.SELFSIGNED) {
            try {
                // create selfsigned certificate
                Certificate cacertificate = null;

                log.debug("CAAdminSessionBean : " + cainfo.getSubjectDN());

                UserDataVO cadata = new UserDataVO("nobody", cainfo.getSubjectDN(), cainfo.getSubjectDN().hashCode(), caAltName, null, 0, 0, 0, cainfo
                        .getCertificateProfileId(), null, null, 0, 0, null);

                cacertificate = ca.generateCertificate(cadata, catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN), -1, cainfo.getValidity(), certprofile,
                        sequence);

                log.debug("CAAdminSessionBean : " + CertTools.getSubjectDN(cacertificate));

                // Build Certificate Chain
                certificatechain = new ArrayList<Certificate>();
                certificatechain.add(cacertificate);

                // set status to active
                castatus = SecConst.CA_ACTIVE;
            } catch (CATokenOfflineException e) {
                String msg = intres.getLocalizedMessage("error.catokenoffline", cainfo.getName());
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg, e);
                throw e;
            } catch (Exception fe) {
                String msg = intres.getLocalizedMessage("caadmin.errorcreateca", cainfo.getName());
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg, fe);
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

                UserDataVO cadata = new UserDataVO("nobody", cainfo.getSubjectDN(), cainfo.getSubjectDN().hashCode(), caAltName, null, 0, 0, 0, cainfo
                        .getCertificateProfileId(), null, null, 0, 0, null);

                cacertificate = signca.generateCertificate(cadata, catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN), -1, cainfo.getValidity(), certprofile,
                        sequence);

                // Build Certificate Chain
                Collection<Certificate> rootcachain = signca.getCertificateChain();
                certificatechain = new ArrayList<Certificate>();
                certificatechain.add(cacertificate);
                certificatechain.addAll(rootcachain);
                // set status to active
                castatus = SecConst.CA_ACTIVE;
            } catch (CATokenOfflineException e) {
                String msg = intres.getLocalizedMessage("error.catokenoffline", cainfo.getName());
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg, e);
                throw e;
            } catch (Exception fe) {
                String msg = intres.getLocalizedMessage("caadmin.errorcreateca", cainfo.getName());
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg, fe);
                throw new EJBException(fe);
            }
        }

        // Set Certificate Chain
        ca.setCertificateChain(certificatechain);

        // Publish CA certificates.
        publishCACertificate(admin, ca.getCertificateChain(), ca.getCRLPublishers(), ca.getSubjectDN());

        if (castatus == SecConst.CA_ACTIVE) {
            // activate External CA Services
            activateAndPublishExternalCAServices(admin, cainfo.getExtendedCAServiceInfos(), ca);
        }
        // Store CA in database.
        try {
        	entityManager.persist(new CAData(cainfo.getSubjectDN(), cainfo.getName(), castatus, ca));
            if (castatus == SecConst.CA_ACTIVE) {
                // create initial CRL
                crlCreateSession.createCRLs(admin, ca, cainfo);
            }
            String msg = intres.getLocalizedMessage("caadmin.createdca", cainfo.getName(), Integer.valueOf(castatus));
            logSession.log(admin, ca.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CACREATED, msg);
        } catch (RuntimeException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcreateca", cainfo.getName());
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg);
            throw e;
        }
        // Update local OCSP's CA certificate cache
        CertificateCacheFactory.getInstance(certificateStoreSession).forceReload();
    	if (log.isTraceEnabled()) {
    		log.trace("<createCA: "+cainfo.getName());
    	}
    }

    @Override
    public void editCA(Admin admin, CAInfo cainfo) throws AuthorizationDeniedException {
        boolean xkmsrenewcert = false;
        boolean cmsrenewcert = false;

        // Check authorization
        if(!authorizationSession.isAuthorizedNoLog(admin, "/super_administrator")) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoeditca", cainfo.getName());
            logSession.log(admin, cainfo.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,
                    msg);
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
        	CAData cadata = CAData.findByIdOrThrow(entityManager, Integer.valueOf(cainfo.getCAId()));
            CA ca = cadata.getCA();

            // Update CA values
            ca.updateCA(cainfo);
            // Store CA in database
            cadata.setCA(ca);
            // Try to activate the CA token after we have edited the CA
            try {
                CATokenContainer catoken = ca.getCAToken();
                CATokenInfo catokeninfo = cainfo.getCATokenInfo();
                String authCode = catokeninfo.getAuthenticationCode();
                String keystorepass = getDefaultKeyStorePassIfSWAndEmpty(authCode, catokeninfo);
                if (keystorepass != null) {
                    catoken.activate(keystorepass);
                } else {
                    log.debug("Not trying to activate CAToken after editing, authCode == null.");
                }
            } catch (CATokenAuthenticationFailedException ctaf) {
                String msg = intres.getLocalizedMessage("caadmin.errorcreatetokenpin");
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, ctaf);
            } catch (CATokenOfflineException ctoe) {
                String msg = intres.getLocalizedMessage("error.catokenoffline", cainfo.getName());
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, ctoe);
            }
            // No OCSP Certificate exists that can be renewed.
            if (xkmsrenewcert) {
                XKMSCAServiceInfo info = (XKMSCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE);
                Certificate xkmscert = (Certificate) info.getXKMSSignerCertificatePath().get(0);
                ArrayList<Certificate> xkmscertificate = new ArrayList<Certificate>();
                xkmscertificate.add(xkmscert);
                // Publish the extended service certificate, but only for active
                // services
                if ((info.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE) && (!xkmscertificate.isEmpty())) {
                    publishCACertificate(admin, xkmscertificate, ca.getCRLPublishers(), ca.getSubjectDN());
                }
            }
            if (cmsrenewcert) {
                CmsCAServiceInfo info = (CmsCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE);
                Certificate cmscert = (Certificate) info.getCertificatePath().get(0);
                ArrayList<Certificate> cmscertificate = new ArrayList<Certificate>();
                cmscertificate.add(cmscert);
                // Publish the extended service certificate, but only for active
                // services
                if ((info.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE) && (!cmscertificate.isEmpty())) {
                    publishCACertificate(admin, cmscertificate, ca.getCRLPublishers(), ca.getSubjectDN());
                }
            }
            // Log Action
            String msg = intres.getLocalizedMessage("caadmin.editedca", cainfo.getName());
            logSession.log(admin, cainfo.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEDITED, msg);
        } catch (Exception fe) {
            String msg = intres.getLocalizedMessage("caadmin.erroreditca", cainfo.getName());
            log.error(msg, fe);
            logSession.log(admin, cainfo.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, fe);
            throw new EJBException(fe);
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public CAInfo getCAInfoOrThrowException(Admin admin, String name) throws CADoesntExistsException {
        return caSession.getCA(admin, name).getCAInfo();
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public CAInfo getCAInfo(Admin admin, String name) {
        CAInfo caInfo = null;
        try {
            caInfo = getCAInfoOrThrowException(admin, name);
        } catch (CADoesntExistsException e) {
            // NOPMD ignore, we want to return null and getCAInfoOrThrowException already logged
        	// that we could not find it
        }
        return caInfo;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public CAInfo getCAInfoOrThrowException(Admin admin, int caid) throws CADoesntExistsException {
        return getCAInfoOrThrowException(admin, caid, false);
    }

    /**
     * Internal method that get CA info, and optionally performs a sign test
     * with the CAs test signing key.
     * 
     * If doSignTest is true, and the CA is active and the CA is included in
     * healthcheck (cainfo.getIncludeInHealthCheck()), a signature with the test
     * keys is performed to set the CA Token status correctly.
     * 
     * @param admin
     *            administrator performing this action
     * @param caid
     *            numerical id of CA (subjectDN.hashCode()) that we search for
     * @param doSignTest
     *            true if a test signature should be performed, false if only
     *            the status from token info is checked. Should normally be set
     *            to false.
     * @return CAInfo value object, never null
     * @throws CADoesntExistsException
     *             if CA with caid does not exist or admin is not authorized to CA
     */
    private CAInfo getCAInfoOrThrowException(Admin admin, int caid, boolean doSignTest) throws CADoesntExistsException {
        if (!authorizedToCA(admin, caid)) {
            if (log.isDebugEnabled()) {
                log.debug("Admin (" + admin.toString() + ") is not authorized to CA: " + caid);
            }
            String msg = intres.getLocalizedMessage("caadmin.canotexistsid", Integer.valueOf(caid));
            throw new CADoesntExistsException(msg);
        }
        CAInfo cainfo = null;
        try {
            CA ca = caSession.getCA(admin, caid);       
            cainfo = ca.getCAInfo();
            int status = cainfo.getStatus();
            boolean includeInHealthCheck = cainfo.getIncludeInHealthCheck();
            int tokenstatus = ICAToken.STATUS_OFFLINE;
            if (doSignTest && status == SecConst.CA_ACTIVE && includeInHealthCheck) {
                // Only do a real test signature if the CA is supposed to be
                // active and if it is included in healthchecking
                // Otherwise we will only waste resources
                if (log.isDebugEnabled()) {
                    log.debug("Making test signature with CAs token. CA=" + ca.getName() + ", doSignTest=" + doSignTest + ", CA status=" + status
                            + ", includeInHealthCheck=" + includeInHealthCheck);
                }
                CATokenContainer catoken = ca.getCAToken();
                tokenstatus = catoken.getCATokenInfo().getCATokenStatus();
            } else {
                // if (log.isDebugEnabled()) {
                // log.debug("Not making test signature with CAs token. doSignTest="+doSignTest+", CA status="+status+", includeInHealthCheck="+includeInHealthCheck);
                // }
                tokenstatus = cainfo.getCATokenInfo().getCATokenStatus();
            }
            // Set a possible new status in the info value object
            cainfo.getCATokenInfo().setCATokenStatus(tokenstatus);
        } catch (CADoesntExistsException ce) {
            // Just re-throw, getCAInternal has already logged that the CA does
            // not exist
            throw ce;
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("caadmin.errorgetcainfo", Integer.valueOf(caid));
            log.error(msg, e);
            throw new EJBException(e);
        }
        return cainfo;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public CAInfo getCAInfo(Admin admin, int caid) {
        // No sign test for the standard method
        return getCAInfo(admin, caid, false);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public CAInfo getCAInfo(Admin admin, int caid, boolean doSignTest) {
        CAInfo caInfo = null;
        try {
            caInfo = getCAInfoOrThrowException(admin, caid, doSignTest);
        } catch (CADoesntExistsException e) {
            // NOPMD ignore, we want to return null and getCAInfoOrThrowException already logged
        	// that we could not find it
        }
        return caInfo;
    }

    @Override
    public void verifyExistenceOfCA(int caid) throws CADoesntExistsException {
    	// TODO: Test if "SELECT a.caId FROM CAData a WHERE a.caId=:caId" improves performance
    	CAData.findByIdOrThrow(entityManager, Integer.valueOf(caid));
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public HashMap<Integer,String> getCAIdToNameMap(Admin admin) {
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
    public byte[] makeRequest(Admin admin, int caid, Collection<?> cachainin, boolean regenerateKeys, boolean usenextkey, boolean activatekey, String keystorepass)
            throws CADoesntExistsException, AuthorizationDeniedException, CertPathValidatorException, CATokenOfflineException,
            CATokenAuthenticationFailedException {
        if (log.isTraceEnabled()) {
            log.trace(">makeRequest: " + caid + ", regenerateKeys=" + regenerateKeys + ", usenextkey=" + usenextkey + ", activatekey=" + activatekey);
        }
        byte[] returnval = null;
        // Check authorization
        try {
            
            if(!authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_RENEWCA)) {
                Authorizer.throwAuthorizationException(admin, AccessRulesConstants.REGULAR_RENEWCA, null);
            }
            if (!authorizedToCA(admin, caid)) {
                throw new AuthorizationDeniedException("Not authorized to CA");
            }
        } catch (AuthorizationDeniedException e) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtocertreq", Integer.valueOf(caid));
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, msg, e);
            throw new AuthorizationDeniedException(msg);
        }

        // Get CA info.
        CAData cadata = null;
        try {
        	cadata = CAData.findByIdOrThrow(entityManager, Integer.valueOf(caid));
            CA ca = cadata.getCA();
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
            if (chain.isEmpty() &&
            	ca.getCAType() == CAInfo.CATYPE_CVC &&
                ca.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA &&
                ca.getStatus() == SecConst.CA_ACTIVE){
            	CardVerifiableCertificate dvcert = (CardVerifiableCertificate)ca.getCACertificate();
    			String ca_ref = dvcert.getCVCertificate().getCertificateBody().getAuthorityReference().getConcatenated();
            	log.debug("DV renewal missing CVCA cert, try finding CA for:"+ ca_ref);
	        	Iterator<Integer> cas = caSession.getAvailableCAs(admin).iterator();
	        	while (cas.hasNext()){
	        		CA cvca = caSession.getCA(admin,cas.next());
	        		if (cvca.getCAType() == CAInfo.CATYPE_CVC && cvca.getSignedBy() == CAInfo.SELFSIGNED){
	        			CardVerifiableCertificate cvccert = (CardVerifiableCertificate)cvca.getCACertificate();
	        			if (ca_ref.equals (cvccert.getCVCertificate().getCertificateBody().getHolderReference().getConcatenated())){
	                    	log.debug("Added missing CVCA to rewnewal request: "+ cvca.getName());
	        				chain.add(cvccert);
	        				break;
	        			}
	        		}
       			}
	        	if (chain.isEmpty ()){
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

            CATokenContainer caToken = ca.getCAToken();
            if (regenerateKeys) {
                log.debug("Generating new keys.");
                keystorepass = getDefaultKeyStorePassIfSWAndEmpty(keystorepass, caToken.getCATokenInfo());
                caToken.generateKeys(keystorepass, true, activatekey);
                ca.setCAToken(caToken);
                // In order to generate a certificate with this keystore we must
                // make sure it is activated
                ca.getCAToken().activate(keystorepass);
            }
            // The CA certificate signing this request is the first in the
            // certificate chain
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
                } catch (RuntimeException e) {
                    Throwable cause = e.getCause();
                    // If this is an IllegalKeyException we it's possible that
                    // we did not have a previous key, then just skip and make
                    // it authenticated
                    // and return the request message as is
                    if (cause instanceof InvalidKeyException) {
                        log.info("Failed to sign CVC request with previous key (does it exist?). Returning unauthenticated request.", e);
                        returnval = request;
                    } else {
                        throw e;
                    }
                }
            } else {
                returnval = request;
            }

            // Set statuses if it should be set.
            if ((regenerateKeys || usenextkey) && activatekey) {
                cadata.setStatus(SecConst.CA_WAITING_CERTIFICATE_RESPONSE);
                ca.setStatus(SecConst.CA_WAITING_CERTIFICATE_RESPONSE);
            }

            cadata.setCA(ca);
            // Log information about the event
            String msg = intres.getLocalizedMessage("caadmin.certreqcreated", caname, Integer.valueOf(caid));
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEDITED, msg);
        } catch (CertPathValidatorException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertreq", Integer.valueOf(caid));
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, e);
            throw e;
        } catch (CATokenOfflineException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertreq", Integer.valueOf(caid));
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, e);
            throw e;
        } catch (CATokenAuthenticationFailedException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertreq", Integer.valueOf(caid));
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, e);
            throw e;
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertreq", Integer.valueOf(caid));
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, e);
            throw new EJBException(e);
        }

        String msg = intres.getLocalizedMessage("caadmin.certreqcreated", Integer.valueOf(caid));
        logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEDITED, msg);
        if (log.isTraceEnabled()) {
            log.trace("<makeRequest: " + caid);
        }
        return returnval;
    }

    @Override
    public byte[] signRequest(Admin admin, int caid, byte[] request, boolean usepreviouskey, boolean createlinkcert) throws AuthorizationDeniedException,
            CADoesntExistsException, CATokenOfflineException {
       if(!authorizationSession.isAuthorizedNoLog(admin, "/super_administrator")) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtocertreq", Integer.valueOf(caid));
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, msg);
            throw new AuthorizationDeniedException(msg);
        }
        byte[] returnval = null;
        String caname = "" + caid;
        CAData signedbydata = CAData.findByIdOrThrow(entityManager, Integer.valueOf(caid));
        try {
            caname = signedbydata.getName();
            CA signedbyCA = signedbydata.getCA();
            returnval = signedbyCA.signRequest(request, usepreviouskey, createlinkcert);
            String msg = intres.getLocalizedMessage("caadmin.certreqsigned", caname);
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_SIGNEDREQUEST, msg);
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertreqsign", caname);
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_SIGNEDREQUEST, msg, e);
            throw new EJBException(e);
        }
        return returnval;
    }

    @Override
    public void receiveResponse(Admin admin, int caid, IResponseMessage responsemessage, Collection<?> cachain, String tokenAuthenticationCode)
            throws AuthorizationDeniedException, CertPathValidatorException, EjbcaException {
        Certificate cacert = null;
        // Check authorization
        try {
            if(!authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_RENEWCA)) {
                Authorizer.throwAuthorizationException(admin, AccessRulesConstants.REGULAR_RENEWCA, null);
            }
            if (!authorizedToCA(admin, caid)) {
                throw new AuthorizationDeniedException("Not authorized to CA");
            }
        } catch (AuthorizationDeniedException e) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtocertresp", Integer.valueOf(caid));
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, msg, e);
            throw new AuthorizationDeniedException(msg);
        }

        // Get CA info.
        CAData cadata = CAData.findById(entityManager, Integer.valueOf(caid));
        if (cadata == null) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg);
            throw new EjbcaException(msg);
        }
        try {
            CA ca = cadata.getCA();
            try {
                if (responsemessage instanceof X509ResponseMessage) {
                    cacert = ((X509ResponseMessage) responsemessage).getCertificate();
                } else {
                    String msg = intres.getLocalizedMessage("caadmin.errorcertrespillegalmsg", responsemessage != null ? responsemessage.getClass().getName()
                            : "null");
                    logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg);
                    throw new EjbcaException(msg);
                }

                // If signed by external CA, process the received certificate
                // and store it, activating the CA
                if (ca.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA) {
                    // Check that CA DN is equal to the certificate response.
                    if (!CertTools.getSubjectDN(cacert).equals(CertTools.stringToBCDNString(ca.getSubjectDN()))) {
                        String msg = intres.getLocalizedMessage("caadmin.errorcertrespwrongdn", CertTools.getSubjectDN(cacert), ca.getSubjectDN());
                        logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg);
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
                    CATokenContainer catoken = ca.getCAToken();
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
                        KeyTools.testKey(catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), pk, catoken.getProvider());
                    } catch (Exception e1) {
                        log.debug("The received certificate response does not match the CAs private signing key for purpose CAKEYPURPOSE_CERTSIGN, trying CAKEYPURPOSE_CERTSIGN_NEXT...");
                        if (e1 instanceof InvalidKeyException) {
                            log.trace(e1);
                        } else {
                            // If it's not invalid key, we want to see more of
                            // the error
                            log.debug("Error: ", e1);
                        }
                        try {
                            KeyTools.testKey(catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN_NEXT), pk, catoken.getProvider());
                            // This was OK, so we must also activate the next
                            // signing key when importing this certificate
                            catoken.activateNextSignKey(tokenAuthenticationCode);
                            ca.setCAToken(catoken);
                            // In order to generate a certificate with this
                            // keystore we must make sure it is activated
                            ca.getCAToken().activate(tokenAuthenticationCode);
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

                    // Publish CA Certificate
                    publishCACertificate(admin, chain, ca.getCRLPublishers(), ca.getSubjectDN());

                    // Set status to active, so we can sign certificates for the
                    // external services below.
                    cadata.setStatus(SecConst.CA_ACTIVE);
                    ca.setStatus(SecConst.CA_ACTIVE);

                    // activate External CA Services
                    Iterator<Integer> iter = ca.getExternalCAServiceTypes().iterator();
                    while (iter.hasNext()) {
                        int type = iter.next().intValue();
                        try {
                            ca.initExternalService(type, ca);
                            ArrayList<Certificate> extcacertificate = new ArrayList<Certificate>();
                            ExtendedCAServiceInfo info = null;
                            if (type == ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE) {
                                info = (OCSPCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE);
                                // The OCSP certificate is the same as the
                                // singing certificate
                            }
                            if (type == ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE) {
                                info = ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE);
                                extcacertificate.add(((XKMSCAServiceInfo) info).getXKMSSignerCertificatePath().get(0));
                            }
                            if (type == ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE) {
                                info = ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE);
                                extcacertificate.add(((CmsCAServiceInfo) info).getCertificatePath().get(0));
                            }
                            // Publish the extended service certificate, but
                            // only for active services
                            if ((info != null) && (info.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE) && (!extcacertificate.isEmpty())) {
                                publishCACertificate(admin, extcacertificate, ca.getCRLPublishers(), ca.getSubjectDN());
                            }
                        } catch (CATokenOfflineException e) {
                            String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", Integer.valueOf(caid));
                            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null,
                                    LogConstants.EVENT_ERROR_CACREATED, msg, e);
                            throw e;
                        } catch (Exception fe) {
                            String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", Integer.valueOf(caid));
                            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null,
                                    LogConstants.EVENT_ERROR_CACREATED, msg, fe);
                            throw new EJBException(fe);
                        }
                    }

                    // Set expire time
                    ca.setExpireTime(CertTools.getNotAfter(cacert));
                    cadata.setExpireTime(CertTools.getNotAfter(cacert).getTime());
                    // Save CA
                    cadata.setCA(ca);

                    // Create initial CRL
                    crlCreateSession.createCRLs(admin, ca, ca.getCAInfo());
                } else {
                    String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", Integer.valueOf(caid));
                    // Cannot create certificate request for internal CA
                    logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg);
                    throw new EjbcaException(msg);
                }

            } catch (CATokenOfflineException e) {
                String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
                logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, e);
                throw e;
            } catch (CertificateEncodingException e) {
                String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
                logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, e);
                throw new EjbcaException(e.getMessage());
            } catch (CertificateException e) {
                String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
                logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, e);
                throw new EjbcaException(e.getMessage());
            } catch (IOException e) {
                String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
                logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, e);
                throw new EjbcaException(e.getMessage());
            } catch (InvalidAlgorithmParameterException e) {
                String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
                logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, e);
                throw new EjbcaException(e.getMessage());
            } catch (NoSuchAlgorithmException e) {
                String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
                logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, e);
                throw new EjbcaException(e.getMessage());
            } catch (NoSuchProviderException e) {
                String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
                logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, e);
                throw new EjbcaException(e.getMessage());
            }
        } catch (UnsupportedEncodingException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, e);
            throw new EjbcaException(e.getMessage());
        }

        String msg = intres.getLocalizedMessage("caadmin.certrespreceived", Integer.valueOf(caid));
        logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEDITED, msg);
    }

    @Override
    public IResponseMessage processRequest(Admin admin, CAInfo cainfo, IRequestMessage requestmessage) throws CAExistsException, CADoesntExistsException,
            AuthorizationDeniedException, CATokenOfflineException {
        final CA ca;
        Collection<Certificate> certchain = null;
        IResponseMessage returnval = null;
        // check authorization
        if(!authorizationSession.isAuthorizedNoLog(admin, "/super_administrator")) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtocertresp", cainfo.getName());
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,
                    msg);
            throw new AuthorizationDeniedException(msg);
        }

        // Check that CA doesn't already exists
        CAData oldcadata = null;
        int caid = cainfo.getCAId();
        if (caid >= 0 && caid <= CAInfo.SPECIALCAIDBORDER) {
        	String msg = intres.getLocalizedMessage("caadmin.errorcaexists", cainfo.getName());
        	logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg);
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
            if (((oldcadata.getStatus() == SecConst.CA_WAITING_CERTIFICATE_RESPONSE) || (oldcadata.getStatus() == SecConst.CA_ACTIVE) || (oldcadata.getStatus() == SecConst.CA_EXTERNAL))
                    && (oldcadata.getCaId().intValue() == cainfo.getCAId()) && (oldcadata.getName().equals(cainfo.getName()))) {
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
                    UserDataVO cadata = new UserDataVO("nobody", cainfo.getSubjectDN(), cainfo.getSubjectDN().hashCode(), subjectAltName, null, 0, 0, 0, cainfo
                            .getCertificateProfileId(), null, null, 0, 0, null);
                    // We can pass the PKCS10 request message as extra
                    // parameters
                    if (requestmessage instanceof PKCS10RequestMessage) {
                        ExtendedInformation extInfo = new ExtendedInformation();
                        PKCS10CertificationRequest pkcs10 = ((PKCS10RequestMessage) requestmessage).getCertificationRequest();
                        extInfo.setCustomData(ExtendedInformation.CUSTOM_PKCS10, new String(Base64.encode(pkcs10.getEncoded())));
                        cadata.setExtendedinformation(extInfo);
                    }
                    CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(admin, cainfo.getCertificateProfileId());
                    String sequence = null;
                    byte[] ki = requestmessage.getRequestKeyInfo();
                    if ((ki != null) && (ki.length > 0)) {
                        sequence = new String(ki);
                    }
                    cacertificate = signca.generateCertificate(cadata, publickey, -1, cainfo.getValidity(), certprofile, sequence);
                    // X509ResponseMessage works for both X509 CAs and CVC CAs
                    // here...pure luck? I don't think so!
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
                        CATokenContainer token = new CATokenContainerImpl(new NullCATokenInfo(), cainfo.getCAId());
                        ca.setCAToken(token);

                        // set status to active
                        entityManager.persist(new CAData(cainfo.getSubjectDN(), cainfo.getName(), SecConst.CA_EXTERNAL, ca));
                        //cadatahome.create(cainfo.getSubjectDN(), cainfo.getName(), SecConst.CA_EXTERNAL, ca);
                    } else {
                        if (oldcadata.getStatus() == SecConst.CA_EXTERNAL) {
                            // If it is an external CA we will not import the
                            // certificate later on here, so we want to
                            // update the CA in this instance with the new
                            // certificate so it is visible
                            ca = oldcadata.getCA();
                            ca.setCertificateChain(certchain);
                            if (log.isDebugEnabled()) {
                                log.debug("Storing new certificate chain for external CA " + cainfo.getName() + ", CA token type: "
                                        + ca.getCAToken().getCATokenType());
                            }
                            oldcadata.setCA(ca);
                        } else {
                            // If it is an internal CA so we are "simulating"
                            // signing a real external CA we don't do anything
                            // because that CA is waiting to import a
                            // certificate
                            if (log.isDebugEnabled()) {
                                log.debug("Not storing new certificate chain or updating CA for internal CA, simulating external: " + cainfo.getName());
                            }
                            ca = null;
                        }
                    }
                    // Publish CA certificates.
                    publishCACertificate(admin, certchain, signca.getCRLPublishers(), ca != null ? ca.getSubjectDN() : null);
                    // External CAs will not have any CRLs in this system, so we don't have to try to publish any CRLs
                } catch (CATokenOfflineException e) {
                    String msg = intres.getLocalizedMessage("caadmin.errorprocess", cainfo.getName());
                    log.error(msg, e);
                    logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, e);
                    throw e;
                }
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("caadmin.errorprocess", cainfo.getName());
                log.error(msg, e);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, e);
                throw new EJBException(e);
            }

        }

        if (certchain != null) {
            String msg = intres.getLocalizedMessage("caadmin.processedca", cainfo.getName());
            logSession.log(admin, cainfo.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEDITED, msg);
        } else {
            String msg = intres.getLocalizedMessage("caadmin.errorprocess", cainfo.getName());
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg);
        }
        return returnval;
    }

    @Override
    public void importCACertificate(Admin admin, String caname, Collection<Certificate> certificates) throws CreateException {
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
            String subjectaltname = null;
            try {
                subjectaltname = CertTools.getSubjectAlternativeName(x509CaCertificate);
            } catch (CertificateParsingException e) {
                log.error("", e);
            } catch (IOException e) {
                log.error("", e);
            }

            // Process certificate policies.
            ArrayList<CertificatePolicy> policies = new ArrayList<CertificatePolicy>();
            CertificateProfile certprof = certificateProfileSession.getCertificateProfile(admin, certprofileid);
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

            cainfo = new X509CAInfo(subjectdn, caname, SecConst.CA_EXTERNAL, new Date(), subjectaltname, certprofileid, validity, CertTools
                    .getNotAfter(x509CaCertificate), CAInfo.CATYPE_X509, signedby, null, null, description, -1, null, policies, crlperiod, crlIssueInterval,
                    crlOverlapTime, deltacrlperiod, crlpublishers, useauthoritykeyidentifier, authoritykeyidentifiercritical, usecrlnumber, crlnumbercritical,
                    "", "", "", "", finishuser, extendedcaserviceinfos, useutf8policytext, approvalsettings, numofreqapprovals, useprintablestringsubjectdn,
                    useldapdnorder, usecrldistpointoncrl, crldistpointoncrlcritical, false, true, // isDoEnforceUniquePublicKeys
                    true, // isDoEnforceUniqueDistinguishedName
                    false, // isDoEnforceUniqueSubjectDNSerialnumber
                    true, // useCertReqHistory
                    true, // useUserStorage
                    true, // useCertificateStorage
                    null //cmpRaAuthSecret
            );
        } else if (StringUtils.equals(caCertificate.getType(), "CVC")) {
            cainfo = new CVCCAInfo(subjectdn, caname, 0, new Date(), certprofileid, validity, null, CAInfo.CATYPE_CVC, signedby, null, null, description, -1,
                    null, crlperiod, crlIssueInterval, crlOverlapTime, deltacrlperiod, crlpublishers, finishuser, extendedcaserviceinfos, approvalsettings,
                    numofreqapprovals, false, true, // isDoEnforceUniquePublicKeys
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
        CATokenContainer token = new CATokenContainerImpl(new NullCATokenInfo(), cainfo.getCAId());
        ca.setCAToken(token);
        // set status to active
        entityManager.persist(new CAData(cainfo.getSubjectDN(), cainfo.getName(), SecConst.CA_EXTERNAL, ca));
        // Publish CA certificates.
        publishCACertificate(admin, certificates, null, ca.getSubjectDN());
    }

    @Override
    public void initExternalCAService(Admin admin, int caid, ExtendedCAServiceInfo info) throws CATokenOfflineException, AuthorizationDeniedException,
            CADoesntExistsException, UnsupportedEncodingException, IllegalKeyStoreException {
        // check authorization
        if(!authorizationSession.isAuthorizedNoLog(admin, "/super_administrator")) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtorenew", Integer.valueOf(caid));
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, msg);
            throw new AuthorizationDeniedException(msg);
        }

        // Get CA info.
        CAData cadata = CAData.findByIdOrThrow(entityManager, Integer.valueOf(caid));
        CA ca = cadata.getCA();
        if (ca.getStatus() == SecConst.CA_OFFLINE) {
        	String msg = intres.getLocalizedMessage("error.catokenoffline", cadata.getName());
        	throw new CATokenOfflineException(msg);
        }
        ArrayList<ExtendedCAServiceInfo> infos = new ArrayList<ExtendedCAServiceInfo>();
        infos.add(info);
        activateAndPublishExternalCAServices(admin, infos, ca);
        // Update CA in database
        cadata.setCA(ca);
    }

    @Override
    public void renewCA(Admin admin, int caid, String keystorepass, boolean regenerateKeys) throws CADoesntExistsException, AuthorizationDeniedException,
            CertPathValidatorException, CATokenOfflineException, CATokenAuthenticationFailedException {
        if (log.isTraceEnabled()) {
            log.trace(">CAAdminSession, renewCA(), caid=" + caid);
        }
        Collection<Certificate> cachain = null;
        Certificate cacertificate = null;
        // check authorization
        try {
            if(!authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_RENEWCA)) {
                Authorizer.throwAuthorizationException(admin, AccessRulesConstants.REGULAR_RENEWCA, null);
            }
            if (!authorizedToCA(admin, caid)) {
                throw new AuthorizationDeniedException("Not authorized to CA");
            }
        } catch (AuthorizationDeniedException e) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtorenew", Integer.valueOf(caid));
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, msg, e);
            throw new AuthorizationDeniedException(msg);
        }

        // Get CA info.
        CAData cadata = null;
        try {
        	cadata = CAData.findByIdOrThrow(entityManager, Integer.valueOf(caid));
            CA ca = cadata.getCA();

            if (ca.getStatus() == SecConst.CA_OFFLINE) {
                String msg = intres.getLocalizedMessage("error.catokenoffline", cadata.getName());
                throw new CATokenOfflineException(msg);
            }

            CATokenContainer caToken = ca.getCAToken();
            if (regenerateKeys) {
                boolean renew = true;
                keystorepass = getDefaultKeyStorePassIfSWAndEmpty(keystorepass, caToken.getCATokenInfo());
                // for internal CAs the new keys are always activated
                caToken.generateKeys(keystorepass, renew, true);
                // We need to save all this
                ca.setCAToken(caToken);
                cadata.setCA(ca);
                // After this we need to reload all CAs?
                // Make sure we store the new CA and token and reload or update
                // the caches
                Provider prov = Security.getProvider(caToken.getProvider());
                if (log.isDebugEnabled() && (prov != null)) {
                    log.debug("Provider classname: " + prov.getClass().getName());
                }
                if ((prov != null) && StringUtils.contains(prov.getClass().getName(), "iaik")) {
                    // This is because IAIK PKCS#11 provider cuts ALL PKCS#11
                    // sessions when I generate new keys for one CA
                    CACacheManager.instance().removeAll();
                    CATokenManager.instance().removeAll();
                } else {
                    // Using the Sun provider we don't have to reload every CA,
                    // just update values in the caches
                    CACacheManager.instance().removeCA(ca.getCAId());
                    CATokenManager.instance().removeCAToken(ca.getCAId());
                }
            	cadata = CAData.findByIdOrThrow(entityManager, Integer.valueOf(caid));
                ca = cadata.getCA();
                // In order to generate a certificate with this keystore we must
                // make sure it is activated
                caToken = ca.getCAToken();
                caToken.activate(keystorepass);
            }

            // if issuer is insystem CA or selfsigned, then generate new
            // certificate.
            if (ca.getSignedBy() != CAInfo.SIGNEDBYEXTERNALCA) {
                if (ca.getSignedBy() == CAInfo.SELFSIGNED) {
                    // create selfsigned certificate
                    String subjectAltName = null;
                    if (ca instanceof X509CA) {
                        X509CA x509ca = (X509CA) ca;
                        subjectAltName = x509ca.getSubjectAltName();
                    }
                    UserDataVO cainfodata = new UserDataVO("nobody", ca.getSubjectDN(), ca.getSubjectDN().hashCode(), subjectAltName, null, 0, 0, 0, ca
                            .getCertificateProfileId(), null, null, 0, 0, null);

                    CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(admin, ca.getCertificateProfileId());
                    // get from CAtoken to make sure it is fresh
                    String sequence = caToken.getCATokenInfo().getKeySequence();
                    cacertificate = ca.generateCertificate(cainfodata, ca.getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN), -1, ca.getValidity(),
                            certprofile, sequence);
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
                        UserDataVO cainfodata = new UserDataVO("nobody", ca.getSubjectDN(), ca.getSubjectDN().hashCode(), subjectAltName, null, 0, 0, 0, ca
                                .getCertificateProfileId(), null, null, 0, 0, null);

                        CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(admin, ca.getCertificateProfileId());
                        String sequence = caToken.getCATokenInfo().getKeySequence(); // get from CAtoken to make sure it is fresh
                        cacertificate = signca.generateCertificate(cainfodata, ca.getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN), -1, ca
                                .getValidity(), certprofile, sequence);
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
            cadata.setExpireTime(CertTools.getNotAfter(cacertificate).getTime());
            ca.setExpireTime(CertTools.getNotAfter(cacertificate));
            cadata.setStatus(SecConst.CA_ACTIVE);
            ca.setStatus(SecConst.CA_ACTIVE);

            ca.setCertificateChain(cachain);
            cadata.setCA(ca);

            // Publish the new CA certificate
            publishCACertificate(admin, cachain, ca.getCRLPublishers(), ca.getSubjectDN());
            crlCreateSession.createCRLs(admin, ca, ca.getCAInfo());
        } catch (CATokenOfflineException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorrenewca", Integer.valueOf(caid));
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, e);
            throw e;
        } catch (CATokenAuthenticationFailedException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorrenewca", Integer.valueOf(caid));
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, e);
            throw e;
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("caadmin.errorrenewca", Integer.valueOf(caid));
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, e);
            throw new EJBException(e);
        }
        String msg = intres.getLocalizedMessage("caadmin.renewdca", Integer.valueOf(caid));
        logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CARENEWED, msg);
        if (log.isTraceEnabled()) {
            log.trace("<CAAdminSession, renewCA(), caid=" + caid);
        }
    }

    /**
     * Soft KeyStores can not have empty passwords, it probably means to use the
     * default one
     * 
     * @param keystorepass The password that can not be empty if SW.
     * @param tokenInfo Used to determine if it is a soft token
     * @return The password to use.
     */
    private String getDefaultKeyStorePassIfSWAndEmpty(final String keystorepass, CATokenInfo tokenInfo) {
        if (tokenInfo instanceof SoftCATokenInfo && StringUtils.isEmpty(keystorepass)) {
            log.debug("Using system default keystore password");
            final String newKeystorepass = EjbcaConfiguration.getCaKeyStorePass();
            return StringTools.passwordDecryption(newKeystorepass, "ca.keystorepass");
        }
        return keystorepass;
    }

    @Override
    public void revokeCA(Admin admin, int caid, int reason) throws CADoesntExistsException, AuthorizationDeniedException {
        // check authorization
        if(!authorizationSession.isAuthorizedNoLog(admin, "/super_administrator")) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtorevoke", Integer.valueOf(caid));
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, msg);
            throw new AuthorizationDeniedException(msg);
        }
        // Get CA info.
        CAData cadata = CAData.findByIdOrThrow(entityManager, Integer.valueOf(caid));
        String issuerdn = cadata.getSubjectDN();
        try {
            CA ca = cadata.getCA();
            // Revoke CA certificate
            certificateStoreSession.revokeCertificate(admin, ca.getCACertificate(), ca.getCRLPublishers(), reason, cadata.getSubjectDN());
            // Revoke all certificates generated by CA
            if (ca.getStatus() != SecConst.CA_EXTERNAL) {
                certificateStoreSession.revokeAllCertByCA(admin, issuerdn, RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE);
                crlCreateSession.run(admin, ca);
            }
            ca.setRevocationReason(reason);
            ca.setRevocationDate(new Date());
            if (ca.getStatus() != SecConst.CA_EXTERNAL) {
                ca.setStatus(SecConst.CA_REVOKED);
            }
            cadata.setCA(ca);
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("caadmin.errorrevoke", cadata.getName());
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAREVOKED, msg, e);
            throw new EJBException(e);
        }
        String msg = intres.getLocalizedMessage("caadmin.revokedca", cadata.getName(), Integer.valueOf(reason));
        logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAREVOKED, msg);
    }

    @Override
    public void importCAFromKeyStore(Admin admin, String caname, byte[] p12file, String keystorepass, String privkeypass, String privateSignatureKeyAlias,
            String privateEncryptionKeyAlias) throws Exception {
        try {
            // check authorization
            if (admin.getAdminType() != Admin.TYPE_CACOMMANDLINE_USER && !authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR)) {
                Authorizer.throwAuthorizationException(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR, null);
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
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg, e);
            throw new EJBException(e);
        }
    }

    @Override
    public void removeCAKeyStore(Admin admin, String caname) throws EJBException {
        try {
            // check authorization
            if (admin.getAdminType() != Admin.TYPE_CACOMMANDLINE_USER) {
                if(!authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR)) {
                    Authorizer.throwAuthorizationException(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR, null);
                }
            }
            CAData caData = CAData.findByNameOrThrow(entityManager, caname);
            CA thisCa = caData.getCA();
            CATokenContainer thisCAToken = thisCa.getCAToken();
            int tokentype = thisCAToken.getCATokenType();
            if (tokentype != CATokenConstants.CATOKENTYPE_P12 && thisCAToken.getCATokenInfo() instanceof SoftCATokenInfo) {
                throw new Exception("Cannot export anything but a soft token.");
            }
            // Create a new CAToken with the same properties but OFFLINE and
            // without keystore
            SoftCATokenInfo thisCATokenInfo = (SoftCATokenInfo) thisCAToken.getCATokenInfo();
            thisCATokenInfo.setCATokenStatus(ICAToken.STATUS_OFFLINE);
            CATokenContainer emptyToken = new CATokenContainerImpl(thisCATokenInfo, caData.getCaId());
            thisCa.setCAToken(emptyToken);
            // Save to database
            caData.setCA(thisCa);
            // Log
            String msg = intres.getLocalizedMessage("caadmin.removedcakeystore", Integer.valueOf(thisCa.getCAId()));
            logSession.log(admin, thisCa.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEDITED, msg);
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("caadmin.errorremovecakeystore", caname, "PKCS12", e.getMessage());
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg, e);
            throw new EJBException(e);
        }
    }

    @Override
    public void restoreCAKeyStore(Admin admin, String caname, byte[] p12file, String keystorepass, String privkeypass, String privateSignatureKeyAlias,
            String privateEncryptionKeyAlias) throws EJBException {
        try {
            // check authorization
            if (admin.getAdminType() != Admin.TYPE_CACOMMANDLINE_USER) {
                if (!authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR)) {
                    Authorizer.throwAuthorizationException(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR, null);
                }
            }

            CAData caData = CAData.findByNameOrThrow(entityManager, caname);
            CA thisCa = caData.getCA();

            CATokenContainer thisCAToken = thisCa.getCAToken();
            int tokentype = thisCAToken.getCATokenType();
            if (tokentype != CATokenConstants.CATOKENTYPE_P12 && thisCAToken.getCATokenInfo() instanceof SoftCATokenInfo) {
                throw new Exception("Cannot restore anything but a soft token.");
            }

            // Only restore to an offline CA
            if (thisCAToken.getCATokenInfo().getCATokenStatus() != ICAToken.STATUS_OFFLINE) {
                throw new Exception("The CA already has an active CA token.");
            }

            // load keystore
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
            thisCAToken.importKeys(keystorepass, p12PrivateSignatureKey, p12PublicSignatureKey, p12PrivateEncryptionKey, p12PublicEncryptionKey,
                    signatureCertChain);
            thisCa.setCAToken(thisCAToken);
            caData.setCA(thisCa);

            // Log
            String msg = intres.getLocalizedMessage("caadmin.restoredcakeystore", Integer.valueOf(thisCa.getCAId()));
            logSession.log(admin, thisCa.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEDITED, msg);
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("caadmin.errorrestorecakeystore", caname, "PKCS12", e.getMessage());
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, e);
            throw new EJBException(e);
        }
    }

    @Override
    public void importCAFromKeys(Admin admin, String caname, String keystorepass, Certificate[] signatureCertChain, PublicKey p12PublicSignatureKey,
            PrivateKey p12PrivateSignatureKey, PrivateKey p12PrivateEncryptionKey, PublicKey p12PublicEncryptionKey) throws Exception,
            CATokenAuthenticationFailedException, CATokenOfflineException, IllegalKeyStoreException, CreateException {
        // Transform into token
        SoftCATokenInfo sinfo = new SoftCATokenInfo();
        CATokenContainer catoken = new CATokenContainerImpl(sinfo, CertTools.stringToBCDNString(
                StringTools.strip(CertTools.getSubjectDN(signatureCertChain[0]))).hashCode());
        catoken.importKeys(keystorepass, p12PrivateSignatureKey, p12PublicSignatureKey, p12PrivateEncryptionKey, p12PublicEncryptionKey, signatureCertChain);
        log.debug("CA-Info: " + catoken.getCATokenInfo().getSignatureAlgorithm() + " " + catoken.getCATokenInfo().getEncryptionAlgorithm());
        // Identify the key algorithms for extended CA services, OCSP, XKMS, CMS
        String keyAlgorithm = AlgorithmTools.getKeyAlgorithm(p12PublicSignatureKey);
        String keySpecification = AlgorithmTools.getKeySpecification(p12PublicSignatureKey);
        if (keyAlgorithm == null || keyAlgorithm == AlgorithmConstants.KEYALGORITHM_RSA) {
            keyAlgorithm = AlgorithmConstants.KEYALGORITHM_RSA;
            keySpecification = "2048";
        }
        // Do the general import
        CA ca = importCA(admin, caname, keystorepass, signatureCertChain, catoken, keyAlgorithm, keySpecification);
        String msg = intres.getLocalizedMessage("caadmin.importedca", caname, "PKCS12", ca.getStatus());
        logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CACREATED, msg);
    }

    @Override
    public void importCAFromHSM(Admin admin, String caname, Certificate[] signatureCertChain, String catokenpassword, String catokenclasspath,
            String catokenproperties) throws Exception {
        String signatureAlgorithm = CertTools.getSignatureAlgorithm((Certificate) signatureCertChain[0]);
        HardCATokenInfo hardcatokeninfo = new HardCATokenInfo();
        hardcatokeninfo.setAuthenticationCode(catokenpassword);
        hardcatokeninfo.setCATokenStatus(ICAToken.STATUS_ACTIVE);
        hardcatokeninfo.setClassPath(catokenclasspath);
        hardcatokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        hardcatokeninfo.setProperties(catokenproperties);
        hardcatokeninfo.setSignatureAlgorithm(signatureAlgorithm);

        CATokenInfo catokeninfo = hardcatokeninfo;
        CATokenContainer catoken = new CATokenContainerImpl(catokeninfo, CertTools.stringToBCDNString(
                StringTools.strip(CertTools.getSubjectDN(signatureCertChain[0]))).hashCode());
        catoken.activate(catokenpassword);

        String keyAlgorithm = AlgorithmConstants.KEYALGORITHM_RSA;
        String keySpecification = "2048";
        // Do the general import
        importCA(admin, caname, catokenpassword, signatureCertChain, catoken, keyAlgorithm, keySpecification);
    }

    /**
     * @param keyAlgorithm
     *            keyalgorithm for extended CA services, OCSP, XKMS, CMS.
     *            Example AlgorithmConstants.KEYALGORITHM_RSA
     * @param keySpecification
     *            keyspecification for extended CA services, OCSP, XKMS, CMS.
     *            Example 2048
     */
    private CA importCA(Admin admin, String caname, String keystorepass, Certificate[] signatureCertChain, CATokenContainer catoken, String keyAlgorithm,
            String keySpecification) throws Exception, CATokenAuthenticationFailedException, CATokenOfflineException, IllegalKeyStoreException, CreateException {
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
                // full
                // certificate chain in PKCS#12 package.
                log.error("Cannot import CA " + CertTools.getSubjectDN(caSignatureCertificate) + ": certificate "
                        + CertTools.getSerialNumberAsString(caSignatureCertificate) + " is not self-signed.");
                throw new Exception("Cannot import CA " + CertTools.getSubjectDN(caSignatureCertificate) + ": certificate is not self-signed. Check "
                        + "certificate chain in PKCS#12");
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
                CAInfo superCaInfo = getCAInfo(admin, caid);
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

            cainfo = new X509CAInfo(CertTools.getSubjectDN(caSignatureCertificate), caname, SecConst.CA_ACTIVE, new Date(), "", certprof, validity, CertTools
                    .getNotAfter(caSignatureCertificate), // Expiretime
                    CAInfo.CATYPE_X509, signedby, certificatechain, catoken.getCATokenInfo(), description,
                    -1, // revocationReason
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
                    null //cmpRaAuthSecret
            );
            ca = new X509CA((X509CAInfo) cainfo);
        } else if (caSignatureCertificate.getType().equals("CVC")) {
            // Create a CVC CA
            // Create the CAInfo to be used for either generating the whole CA
            // or making a request
            cainfo = new CVCCAInfo(CertTools.getSubjectDN(caSignatureCertificate), caname, SecConst.CA_ACTIVE, new Date(), certprof, validity, CertTools
                    .getNotAfter(caSignatureCertificate), CAInfo.CATYPE_CVC, signedby, certificatechain, catoken.getCATokenInfo(), description, -1,
                    (Date) null, 24, 0, 10, 0, // CRL periods
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
        // We must activate the token, in case it does not have the default
        // password
        catoken.activate(keystorepass);
        ca.setCAToken(catoken);
        ca.setCertificateChain(certificatechain);
        log.debug("CA-Info: " + catoken.getCATokenInfo().getSignatureAlgorithm() + " " + ca.getCAToken().getCATokenInfo().getEncryptionAlgorithm());
        // Publish CA certificates.
        publishCACertificate(admin, ca.getCertificateChain(), ca.getCRLPublishers(), ca.getSubjectDN());
        // activate External CA Services
        activateAndPublishExternalCAServices(admin, cainfo.getExtendedCAServiceInfos(), ca);
        // Store CA in database.
        entityManager.persist(new CAData(cainfo.getSubjectDN(), cainfo.getName(), SecConst.CA_ACTIVE, ca));
        crlCreateSession.run(admin, ca);
        return ca;
    }

    @Override
    public byte[] exportCAKeyStore(Admin admin, String caname, String keystorepass, String privkeypass, String privateSignatureKeyAlias,
            String privateEncryptionKeyAlias) throws Exception {
        log.trace(">exportCAKeyStore");
        try {
        	CAData cadata = CAData.findByNameOrThrow(entityManager, caname);
        	CA thisCa = cadata.getCA();
            // Make sure we are not trying to export a hard or invalid token
            CATokenContainer thisCAToken = thisCa.getCAToken();
            int tokentype = thisCAToken.getCATokenType();
            if (tokentype != CATokenConstants.CATOKENTYPE_P12) {
                throw new Exception("Cannot export anything but a soft token.");
            }
            // Check authorization
            if (admin.getAdminType() != Admin.TYPE_CACOMMANDLINE_USER && !authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR)) {
                Authorizer.throwAuthorizationException(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR, null);
            }
            // Fetch keys
            // This is a way of verifying the password. If activate fails, we
            // will get an exception and the export will not proceed
            thisCAToken.activate(keystorepass);

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
                log.debug("Exporting private key with algorithm: " + p12PrivateCertSignKey.getAlgorithm() + " of format: " + p12PrivateCertSignKey.getFormat());
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
                certificateChainEncryption[0] = CertTools.genSelfCertForPurpose("CN=dummy2", 36500, null, p12PrivateEncryptionKey, p12PublicEncryptionKey,
                        thisCAToken.getCATokenInfo().getEncryptionAlgorithm(), true, X509KeyUsage.keyEncipherment);
                log.debug("Exporting with sigAlgorithm " + CertTools.getSignatureAlgorithm(certificateChainSignature[0]) + "encAlgorithm="
                        + thisCAToken.getCATokenInfo().getEncryptionAlgorithm());
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
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEXPORTED, msg);
            log.trace("<exportCAKeyStore");
            return ret;
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("caadmin.errorexportca", caname, "PKCS12", e.getMessage());
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEXPORTED, msg, e);
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
        } catch (IllegalKeyStoreException e) {
            throw new EJBException(e);
        }
        return returnval;
    }

    //FIXME: Fix exception handling for this method.
    @Override
    public String getKeyFingerPrint(Admin admin, String caname) throws Exception {
            if (admin.getAdminType() != Admin.TYPE_CACOMMANDLINE_USER) {
                if(!authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR)) {
                    Authorizer.throwAuthorizationException(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR, null);
                }
            }
        	CAData cadata = CAData.findByNameOrThrow(entityManager, caname);
        	CA thisCa = cadata.getCA();

            // Make sure we are not trying to export a hard or invalid token
            if (thisCa.getCAType() != CATokenConstants.CATOKENTYPE_P12) {
                throw new Exception("Cannot extract fingerprint from a non-soft token (" + thisCa.getCAType() + ").");
            }
            // Fetch keys
            CATokenContainer thisCAToken = thisCa.getCAToken();
            PrivateKey p12PrivateEncryptionKey = thisCAToken.getPrivateKey(SecConst.CAKEYPURPOSE_KEYENCRYPT);
            PrivateKey p12PrivateCertSignKey = thisCAToken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN);
            PrivateKey p12PrivateCRLSignKey = thisCAToken.getPrivateKey(SecConst.CAKEYPURPOSE_CRLSIGN);
            MessageDigest md = MessageDigest.getInstance("SHA1");
            md.update(p12PrivateEncryptionKey.getEncoded());
            md.update(p12PrivateCertSignKey.getEncoded());
            md.update(p12PrivateCRLSignKey.getEncoded());
            return new String(Hex.encode(md.digest()));
    }

    @Override
    public void activateCAToken(Admin admin, int caid, String authorizationcode, GlobalConfiguration gc) throws AuthorizationDeniedException,
            CATokenAuthenticationFailedException, CATokenOfflineException, ApprovalException, WaitingForApprovalException {
        // Authorize
        if(!authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_ACTIVATECA)) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoactivatetoken", Integer.valueOf(caid));
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, msg);
            throw new AuthorizationDeniedException(msg);
        }

        // Check if approvals is required.
        CAInfo cainfo = getCAInfo(admin, caid);
        if (cainfo == null) {
            String msg = intres.getLocalizedMessage("caadmin.errorgetcainfo", Integer.valueOf(caid));
            log.error(msg);
            return;
        }
        if (cainfo.getStatus() == SecConst.CA_EXTERNAL) {
            String msg = intres.getLocalizedMessage("caadmin.catokenexternal", Integer.valueOf(caid));
            log.info(msg);
            return;
        }
        int numOfApprovalsRequired = getNumOfApprovalRequired(admin, CAInfo.REQ_APPROVAL_ACTIVATECATOKEN, cainfo.getCAId(), cainfo.getCertificateProfileId());
        ActivateCATokenApprovalRequest ar = new ActivateCATokenApprovalRequest(cainfo.getName(), authorizationcode, admin, numOfApprovalsRequired, caid,
                ApprovalDataVO.ANY_ENDENTITYPROFILE);
        if (ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_ACTIVATECATOKEN)) {
            approvalSession.addApprovalRequest(admin, ar, gc);
            String msg = intres.getLocalizedMessage("ra.approvalcaactivation");
            throw new WaitingForApprovalException(msg);
        }
        if (caid >= 0 && caid <= CAInfo.SPECIALCAIDBORDER) {
        	String msg = intres.getLocalizedMessage("caadmin.erroractivatetoken", Integer.valueOf(caid));
        	logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg);
        	throw new CATokenAuthenticationFailedException(msg);
        }
        CAData cadata = CAData.findById(entityManager, Integer.valueOf(caid));
        if (cadata == null) {
        	String msg = intres.getLocalizedMessage("caadmin.errorcanotfound", Integer.valueOf(caid));
        	logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg);
        	throw new EJBException(msg);
        }
        boolean cATokenDisconnected = false;
        try {
        	if ((cadata.getCA().getCAToken().getCATokenInfo()).getCATokenStatus() == ICAToken.STATUS_OFFLINE) {
        		cATokenDisconnected = true;
        	}
        } catch (IllegalKeyStoreException e) {
        	String msg = intres.getLocalizedMessage("caadmin.errorreadingtoken", Integer.valueOf(caid));
        	log.error(msg, e);
        } catch (UnsupportedEncodingException e) {
        	String msg = intres.getLocalizedMessage("caadmin.errorreadingtoken", Integer.valueOf(caid));
        	log.error(msg, e);
        }
        if (cadata.getStatus() == SecConst.CA_OFFLINE || cATokenDisconnected) {
        	try {
        		cadata.getCA().getCAToken().activate(authorizationcode);
        		// If the CA was off-line, this is activation of the CA, if
        		// only the token was disconnected we only connect the token
        		// If CA is waiting for certificate response we can not
        		// change this status just by activating the token.
        		if (cadata.getStatus() != SecConst.CA_WAITING_CERTIFICATE_RESPONSE) {
        			cadata.setStatus(SecConst.CA_ACTIVE);
        		}
        		// Invalidate CA cache to refresh information
        		CACacheManager.instance().removeCA(cadata.getCaId().intValue());
        		String msg = intres.getLocalizedMessage("caadmin.catokenactivated", cadata.getName());
        		logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEDITED, msg);
        	} catch (CATokenAuthenticationFailedException e) {
        		String msg = intres.getLocalizedMessage("caadmin.badcaactivationcode", cadata.getName());
        		logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAACTIVATIONCODE, msg);
        		throw e;
        	} catch (IllegalKeyStoreException e) {
        		throw new EJBException(e);
        	} catch (UnsupportedEncodingException e) {
        		throw new EJBException(e);
        	}
        } else {
        	String msg = intres.getLocalizedMessage("caadmin.errornotoffline", cadata.getName());
        	logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg);
        	throw new CATokenAuthenticationFailedException(msg);
        }
    }

    private static final ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_ACTIVATECATOKEN = { new ApprovalOveradableClassName(
            org.ejbca.core.model.approval.approvalrequests.ActivateCATokenApprovalRequest.class.getName(), null), };

    @Override
    public void deactivateCAToken(Admin admin, int caid) throws AuthorizationDeniedException, EjbcaException {
        // Authorize
        if(!authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_ACTIVATECA)) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtodeactivatetoken", Integer.valueOf(caid));
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, msg);
            throw new AuthorizationDeniedException(msg);
        }
        if (caid >= 0 && caid <= CAInfo.SPECIALCAIDBORDER) {
        	// This should never happen.
        	String msg = intres.getLocalizedMessage("caadmin.errordeactivatetoken", Integer.valueOf(caid));
        	logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg);
        	throw new EjbcaException(msg);
        }
        CAData cadata = CAData.findById(entityManager, Integer.valueOf(caid));
        if (cadata == null) {
        	String msg = intres.getLocalizedMessage("caadmin.errorcanotfound", Integer.valueOf(caid));
        	logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg);
        	throw new EJBException(msg);
        }
        if (cadata.getStatus() == SecConst.CA_EXTERNAL) {
        	String msg = intres.getLocalizedMessage("caadmin.catokenexternal", Integer.valueOf(caid));
        	log.info(msg);
        	return;
        } else if (cadata.getStatus() == SecConst.CA_ACTIVE) {
        	try {
        		cadata.getCA().getCAToken().deactivate();
        		cadata.setStatus(SecConst.CA_OFFLINE);
        		// Invalidate CA cache to refresh information
        		CACacheManager.instance().removeCA(cadata.getCaId().intValue());
        		String msg = intres.getLocalizedMessage("caadmin.catokendeactivated", cadata.getName());
        		logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEDITED, msg);
        	} catch (Exception e) {
        		throw new EJBException(e);
        	}
        } else {
        	String msg = intres.getLocalizedMessage("caadmin.errornotonline", cadata.getName());
        	logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg);
        	throw new EjbcaException(msg);
        }
    }

    /** Method used to check if certificate profile id exists in any CA. */
    @Override
    public boolean exitsCertificateProfileInCAs(Admin admin, int certificateprofileid) {
        boolean returnval = false;
        try {
        	Collection<CAData> result = CAData.findAll(entityManager);
            Iterator<CAData> iter = result.iterator();
            while (iter.hasNext()) {
                CAData cadata = iter.next();
                returnval = returnval || (cadata.getCA().getCertificateProfileId() == certificateprofileid);
            }
        } catch (java.io.UnsupportedEncodingException e) {
        } catch (IllegalKeyStoreException e) {
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
    public boolean exitsPublisherInCAs(Admin admin, int publisherid) {
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
        } catch (IllegalKeyStoreException e) {
        }
        return returnval;
    }

    @Override
    public int getNumOfApprovalRequired(Admin admin, int action, int caid, int certProfileId) {
        int retval = 0;
        CAInfo cainfo = getCAInfo(admin, caid);
        if (cainfo != null) {
            if (cainfo.isApprovalRequired(action)) {
                retval = cainfo.getNumOfReqApprovals();
            }
            CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(admin, certProfileId);
            if (certprofile != null && certprofile.isApprovalRequired(action)) {
                retval = Math.max(retval, certprofile.getNumOfReqApprovals());
            }
        }
        return retval;
    }

    @Override
    public void publishCACertificate(Admin admin, Collection<Certificate> certificatechain, Collection<Integer> usedpublishers, String caDataDN) {
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
                CertificateInfo ci = certificateStoreSession.getCertificateInfo(admin, fingerprint);
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
    public Collection<Integer> getAuthorizedPublisherIds(Admin admin) {
        HashSet<Integer> returnval = new HashSet<Integer>();
        try {
            // If superadmin return all available publishers
            returnval.addAll(publisherSession.getAllPublisherIds(admin));
        } catch (AuthorizationDeniedException e1) {
            // If regular CA-admin return publishers he is authorized to
            Iterator<Integer> authorizedcas = caSession.getAvailableCAs(admin).iterator();
            while (authorizedcas.hasNext()) {
                returnval.addAll(getCAInfo(admin, authorizedcas.next().intValue()).getCRLPublishers());
            }
        }
        return returnval;
    }

    private boolean authorizedToCA(Admin admin, int caid) {
        if (admin.getAdminType() == Admin.TYPE_INTERNALUSER) {
            return true; // Skip database search since this is always ok
        }
        return authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.CAPREFIX + caid);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public String healthCheck() {
        String returnval = "";
        final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
        boolean caTokenSignTest = EjbcaConfiguration.getHealthCheckCaTokenSignTest();
        log.debug("CaTokenSignTest: " + caTokenSignTest);
        Iterator<Integer> iter = caSession.getAvailableCAs().iterator();
        while (iter.hasNext()) {
            int caid = iter.next().intValue();
            CAInfo cainfo = getCAInfo(admin, caid, caTokenSignTest);
            if ((cainfo.getStatus() == SecConst.CA_ACTIVE) && cainfo.getIncludeInHealthCheck()) {
                int tokenstatus = cainfo.getCATokenInfo().getCATokenStatus();
                if (tokenstatus == ICAToken.STATUS_OFFLINE) {
                    returnval += "\nCA: Error CA Token is disconnected, CA Name : " + cainfo.getName();
                    log.error("Error CA Token is disconnected, CA Name : " + cainfo.getName());
                }
            }
        }
        return returnval;
    }

    @Override
    public ExtendedCAServiceResponse extendedService(Admin admin, int caid, ExtendedCAServiceRequest request)
            throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException, CADoesntExistsException {
        // Get CA that will process request
        CA ca = caSession.getCA(admin, caid);
        if (log.isDebugEnabled()) {
        	log.debug("Exteneded service with request class '"+request.getClass().getName()+"' called for CA '"+ca.getName()+"'");            	
        }
        return ca.extendedService(request);
    }

    //
    // Private methods
    //

    /**
     * Check if subject certificate is signed by issuer certificate. Used in
     * 
     * @see #upgradeFromOldCAKeyStore(Admin, String, byte[], char[], char[],
     *      String). This method does a lazy check: if signature verification
     *      failed for any reason that prevent verification, e.g. signature
     *      algorithm not supported, method returns false. Author: Marco
     *      Ferrante
     * 
     * @param subject
     *            Subject certificate
     * @param issuer
     *            Issuer certificate
     * @return true if subject certificate is signed by issuer certificate
     * @throws java.lang.Exception
     */
    private boolean verifyIssuer(Certificate subject, Certificate issuer) throws Exception {
        try {
            PublicKey issuerKey = issuer.getPublicKey();
            subject.verify(issuerKey);
            return true;
        } catch (java.security.GeneralSecurityException e) {
            return false;
        }
    }

    /**
     * Checks the signer validity given a CADataLocal object, as a side-effect
     * marks the signer as expired if it is expired, and throws an EJBException
     * to the caller. This should only be called from create and edit CA methods.
     * 
     * @param admin
     *            administrator calling the method
     * @param signcadata
     *            a CADataLocal entity object of the signer to be checked
     * @throws UnsupportedEncodingException
     *             if there is an error getting the CA from the CADataLoca
     * @throws IllegalKeyStoreException
     *             if we can not read the CA, with it's keystore
     * @throws EJBException
     *             embedding a CertificateExpiredException or a
     *             CertificateNotYetValidException if the certificate has
     *             expired or is not yet valid
     */
    private void checkSignerValidity(Admin admin, CAData signcadata) throws UnsupportedEncodingException, IllegalKeyStoreException {
        // Check validity of signers certificate
        Certificate signcert = (Certificate) signcadata.getCA().getCACertificate();
        try {
            CertTools.checkValidity(signcert, new Date());
        } catch (CertificateExpiredException ce) {
            // Signers Certificate has expired.
            signcadata.setStatus(SecConst.CA_EXPIRED);
            String msg = intres.getLocalizedMessage("signsession.caexpired", signcadata.getSubjectDN());
            logSession.log(admin, signcadata.getCaId().intValue(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,
                    msg, ce);
            throw new EJBException(ce);
        } catch (CertificateNotYetValidException cve) {
            String msg = intres.getLocalizedMessage("signsession.canotyetvalid", signcadata.getSubjectDN());
            logSession.log(admin, signcadata.getCaId().intValue(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,
                    msg, cve);
            throw new EJBException(cve);
        }
    }

    /**
     * Helper method that activates CA services and publisher their
     * certificates, if the services are marked as active
     */
    private void activateAndPublishExternalCAServices(Admin admin, Collection<ExtendedCAServiceInfo> extendedCAServiceInfos, CA ca) {
        // activate External CA Services
        Iterator<ExtendedCAServiceInfo> iter = extendedCAServiceInfos.iterator();
        while (iter.hasNext()) {
            ExtendedCAServiceInfo info = (ExtendedCAServiceInfo) iter.next();
            ArrayList<Certificate> certificate = new ArrayList<Certificate>();
            if (info instanceof OCSPCAServiceInfo) {
                try {
                    ca.initExternalService(ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE, ca);
                    // The OCSP certificate is the same as the CA signing
                    // certificate
                } catch (Exception fe) {
                    String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", "OCSPCAService");
                    logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg,
                            fe);
                    throw new EJBException(fe);
                }
            }
            if (info instanceof XKMSCAServiceInfo) {
                try {
                    ca.initExternalService(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE, ca);
                    certificate.add(((XKMSCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE))
                            .getXKMSSignerCertificatePath().get(0));
                } catch (Exception fe) {
                    String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", "XKMSCAService");
                    logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg,
                            fe);
                    throw new EJBException(fe);
                }
            }
            if (info instanceof CmsCAServiceInfo) {
                try {
                    ca.initExternalService(ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE, ca);
                    certificate
                            .add(((CmsCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE)).getCertificatePath().get(0));
                } catch (Exception fe) {
                    String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", "CMSCAService");
                    logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg,
                            fe);
                    throw new EJBException(fe);
                }
            }
            // Always store the certificate. Only publish the extended service
            // certificate for active services.
            Collection<Integer> publishers = null;
            if (info.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE) {
                publishers = ca.getCRLPublishers();
            }
            if ((!certificate.isEmpty())) {
                publishCACertificate(admin, certificate, publishers, ca.getSubjectDN());
            }
        }
    }
}
