/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.Timeout;
import javax.ejb.Timer;
import javax.ejb.TimerService;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
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
import org.cesecore.certificates.ca.internal.CaCertificateCache;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.cvc.PublicKeyEC;

/**
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CertificateStoreSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class CertificateStoreSessionBean implements CertificateStoreSessionRemote, CertificateStoreSessionLocal {

    private final static Logger log = Logger.getLogger(CertificateStoreSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();
    private static final int TIMERID_CACERTIFICATECACHE = 1;

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @EJB
    private AccessControlSessionLocal accessSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;
    // Myself needs to be looked up in postConstruct
    @Resource
    private SessionContext sessionContext;
    private CertificateStoreSessionLocal certificateStoreSession;
    /* When the sessionContext is injected, the timerService should be looked up.
     * This is due to the Glassfish EJB verifier complaining. 
     */
    private TimerService timerService;

    /** Default create for SessionBean without any creation Arguments. */
    @PostConstruct
    public void postConstruct() {
        // We lookup the reference to our-self in PostConstruct, since we cannot inject this.
        // We can not inject ourself, JBoss will not start then therefore we use this to get a reference to this session bean
        // to call isUniqueCertificateSerialNumberIndex we want to do it on the real bean in order to get
        // the transaction setting (NOT_SUPPORTED) which suspends the active transaction and makes the check outside the transaction
        certificateStoreSession = sessionContext.getBusinessObject(CertificateStoreSessionLocal.class);
        timerService = sessionContext.getTimerService();
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void initTimers() {
        // Reload CA certificate cache cache, and cancel/create timers if there are no timers or if the cache is empty (probably a fresh startup)
        if (getTimerCount(TIMERID_CACERTIFICATECACHE)==0 || CaCertificateCache.INSTANCE.isCacheExpired()){
        	reloadCaCertificateCacheAndSetTimeout();
        } else {
            log.info("Not initing CaCertificateCache reload timers, there are already some.");
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public CertificateDataWrapper storeCertificate(AuthenticationToken admin, Certificate incert, String username, String cafp, int status, int type,
            int certificateProfileId, String tag, long updateTime) throws AuthorizationDeniedException {
    	// Check that user is authorized to the CA that issued this certificate
    	int caid = CertTools.getIssuerDN(incert).hashCode();
        authorizedToCA(admin, caid);
    	return storeCertificateNoAuth(admin, incert, username, cafp, status, type, certificateProfileId, tag, updateTime);
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void storeCertificateRemote(AuthenticationToken admin, Certificate incert, String username, String cafp, int status, int type,
            int certificateProfileId, String tag, long updateTime) throws AuthorizationDeniedException {
        // Check that user is authorized to the CA that issued this certificate
        int caid = CertTools.getIssuerDN(incert).hashCode();
        authorizedToCA(admin, caid);
        storeCertificateNoAuth(admin, incert, username, cafp, status, type, certificateProfileId, tag, updateTime);
    }
    
    /** Local interface only */
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public CertificateDataWrapper storeCertificateNoAuth(AuthenticationToken adminForLogging, Certificate incert, String username, String cafp, int status, int type,
            int certificateProfileId, String tag, long updateTime) {
        if (log.isTraceEnabled()) {
            log.trace(">storeCertificateNoAuth(" + username + ", " + cafp + ", " + status + ", " + type + ")");
        }
        final PublicKey pubk = enrichEcPublicKey(incert.getPublicKey(), cafp);
        // Create the certificate in one go with all parameters at once. This used to be important in EJB2.1 so the persistence layer only creates
        // *one* single
        // insert statement. If we do a home.create and the some setXX, it will create one insert and one update statement to the database.
        // Probably not important in EJB3 anymore
        final boolean useBase64CertTable = CesecoreConfiguration.useBase64CertTable();
        Base64CertData base64CertData = null;
        final CertificateProfile certificateProfile = certificateProfileSession.getCertificateProfile(certificateProfileId);
        final boolean storeCertificateData = certificateProfile==null || certificateProfile.getStoreCertificateData();
        if (useBase64CertTable && storeCertificateData) {
            // use special table for encoded data if told so.
            base64CertData = new Base64CertData(incert);
            entityManager.persist(new Base64CertData(incert));
        }
        final CertificateData certificateData = new CertificateData(incert, pubk, username, cafp, status, type, certificateProfileId, tag, updateTime, !useBase64CertTable && storeCertificateData);
        entityManager.persist(certificateData);
        final String serialNo = CertTools.getSerialNumberAsString(incert);
        final String msg = INTRES.getLocalizedMessage("store.storecert", username, certificateData.getFingerprint(), certificateData.getSubjectDN(), certificateData.getIssuerDN(), serialNo);
        final String caId = String.valueOf(CertTools.getIssuerDN(incert).hashCode());
        logSession.log(EventTypes.CERT_STORED, EventStatus.SUCCESS, ModuleTypes.CERTIFICATE, ServiceTypes.CORE, adminForLogging.toString(), caId,
                serialNo, username, msg);
        if (log.isTraceEnabled()) {
            log.trace("<storeCertificateNoAuth()");
        }
        return new CertificateDataWrapper(incert, certificateData, base64CertData);
    }

    /** Local interface only */
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public CertificateDataWrapper getCertificateData(final String fingerprint) {
        final CertificateData certificateData = CertificateData.findByFingerprint(entityManager, fingerprint);
        if (certificateData==null) {
            return null;
        }
        final Base64CertData base64CertData;
        if (CesecoreConfiguration.useBase64CertTable()) {
            base64CertData = Base64CertData.findByFingerprint(entityManager, fingerprint);
        } else {
            base64CertData = null;
        }
        return new CertificateDataWrapper(certificateData, base64CertData);
    }

    /** 
     * We need special handling here of CVC certificate with EC keys, because they lack EC parameters in all certs
     * except the Root certificate (CVCA)
     */
    private PublicKey enrichEcPublicKey(final PublicKey pubk, final String cafp) {
        PublicKey ret = pubk;
        if ((pubk instanceof PublicKeyEC)) {
            PublicKeyEC pkec = (PublicKeyEC) pubk;
            // The public key of IS and DV certificate (CVC) do not have any parameters so we have to do some magic to get a complete EC public key
            ECParameterSpec spec = pkec.getParams();
            if (spec == null) {
                // We need to enrich this public key with parameters
                try {
                    if (cafp != null) {
                        String cafingerp = cafp;
                        CertificateData cacert = CertificateData.findByFingerprint(entityManager, cafp);
                        if(cacert != null) {
                        String nextcafp = cacert.getCaFingerprint();
                        int bar = 0; // never go more than 5 rounds, who knows what strange things can exist in the CAFingerprint column, make sure we
                                     // never get stuck here
                        while ((!StringUtils.equals(cafingerp, nextcafp)) && (bar++ < 5)) {
                            cacert = CertificateData.findByFingerprint(entityManager, cafp);
                            if (cacert == null) {
                                break;
                            }
                            cafingerp = nextcafp;
                            nextcafp = cacert.getCaFingerprint();
                        }
                            if (cacert != null) {
                                // We found a root CA certificate, hopefully ?
                                PublicKey pkwithparams = cacert.getCertificate(this.entityManager).getPublicKey();
                                ret = KeyTools.getECPublicKeyWithParams(pubk, pkwithparams);
                            }
                        }
                    }
                }  catch (InvalidKeySpecException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Can not enrich EC public key with missing parameters: ", e);
                    }
                }
            }
        } // finished with ECC key special handling
        return ret;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean updateCertificateOnly(AuthenticationToken authenticationToken, Certificate certificate) {
        final String fingerprint = CertTools.getFingerprintAsString(certificate);
        final CertificateData certificateData = CertificateData.findByFingerprint(entityManager, fingerprint);
        if (certificateData==null || certificateData.getCertificate(entityManager) != null) {
            return false;
        }
        final boolean useBase64CertTable = CesecoreConfiguration.useBase64CertTable();
        if (useBase64CertTable) {
            // use special table for encoded data if told so.
            entityManager.persist(new Base64CertData(certificate));
        } else {
            try {
                certificateData.setBase64Cert(new String(Base64.encode(certificate.getEncoded())));
            } catch (CertificateEncodingException e) {
                log.error("Failed to encode certificate for fingerprint " + fingerprint, e);
                return false;
            }
        }
        final String username = certificateData.getUsername();
        final String serialNo = CertTools.getSerialNumberAsString(certificate);
        final String msg = INTRES.getLocalizedMessage("store.storecert", username, fingerprint, certificateData.getSubjectDN(),
                certificateData.getIssuerDN(), serialNo);
        Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        final String caId = String.valueOf(CertTools.getIssuerDN(certificate).hashCode());
        logSession.log(EventTypes.CERT_STORED, EventStatus.SUCCESS, ModuleTypes.CERTIFICATE, ServiceTypes.CORE, authenticationToken.toString(),
                caId, serialNo, username, details);
        return true;
    }

    @Override
    public Collection<String> listAllCertificates(String issuerdn) {
        if (log.isTraceEnabled()) {
            log.trace(">listAllCertificates()");
        }
        // This method was only used from CertificateDataTest and it didn't care about the expireDate, so it will only select fingerprints now.
        return CertificateData.findFingerprintsByIssuerDN(entityManager, CertTools.stringToBCDNString(StringTools.strip(issuerdn)));
    }

    @Override
    public Collection<RevokedCertInfo> listRevokedCertInfo(String issuerdn, long lastbasecrldate) {
        if (log.isTraceEnabled()) {
            log.trace(">listRevokedCertInfo()");
        }
        return CertificateData.getRevokedCertInfos(entityManager, CertTools.stringToBCDNString(StringTools.strip(issuerdn)), lastbasecrldate);
    }

    @Override
    public List<Certificate> findCertificatesBySubjectAndIssuer(String subjectDN, String issuerDN) {
        return findCertificatesBySubjectAndIssuer(subjectDN, issuerDN, false);
    }
    
    @Override
    public List<Certificate> findCertificatesBySubjectAndIssuer(String subjectDN, String issuerDN, boolean onlyActive) {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificatesBySubjectAndIssuer(), dn='" + subjectDN + "' and issuer='" + issuerDN + "'");
        }
        final List<Certificate> ret = new ArrayList<Certificate>();
        for (final CertificateDataWrapper cdw : getCertificateDatasBySubjectAndIssuer(subjectDN, issuerDN, onlyActive)) {
            ret.add(cdw.getCertificate());
        }
        if (log.isTraceEnabled()) {
            log.trace("<findCertificatesBySubjectAndIssuer(), dn='" + subjectDN + "' and issuer='" + issuerDN + "'");
        }
        return ret;
    }

    @Override
    public List<CertificateDataWrapper> getCertificateDatasBySubjectAndIssuer(String subjectDN, String issuerDN, boolean onlyActive) {
        // First make a DN in our well-known format
        final String dn = CertTools.stringToBCDNString(StringTools.strip(subjectDN));
        final String issuerdn = CertTools.stringToBCDNString(StringTools.strip(issuerDN));
        if (log.isDebugEnabled()) {
            log.debug("Looking for cert with (transformed)DN: " + dn);
        }
        final List<CertificateDataWrapper> ret = new ArrayList<CertificateDataWrapper>();
        final Query query;
        if (onlyActive) {
            query = entityManager.createQuery("SELECT a FROM CertificateData a WHERE " + "a.subjectDN=:subjectDN AND a.issuerDN=:issuerDN"
                    + " AND (a.status=:active OR a.status=:notifiedexpired OR (a.status=:revoked AND a.revocationReason=:onhold))" + "AND a.expireDate>:expireDate");
            query.setParameter("active", CertificateConstants.CERT_ACTIVE);
            query.setParameter("notifiedexpired", CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION);
            query.setParameter("revoked", CertificateConstants.CERT_REVOKED);
            query.setParameter("onhold", RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
            query.setParameter("expireDate", System.currentTimeMillis());
        } else {
            query = entityManager.createQuery("SELECT a FROM CertificateData a WHERE a.subjectDN=:subjectDN AND a.issuerDN=:issuerDN");
        }
        query.setParameter("subjectDN", dn);
        query.setParameter("issuerDN", issuerdn);
        for (final Object certificateDataObject : query.getResultList()) {
            final CertificateData certificateData = (CertificateData) certificateDataObject;
            ret.add(new CertificateDataWrapper(certificateData, Base64CertData.findByFingerprint(entityManager, certificateData.getFingerprint())));
        }
        return ret;
    }

    @Override
    public Set<String> findUsernamesByIssuerDNAndSubjectDN(String issuerDN, String subjectDN) {
        if (log.isTraceEnabled()) {
            log.trace(">findUsernamesByIssuerDNAndSubjectDN(), issuer='" + issuerDN + "'");
        }
        // First make a DN in our well-known format
        final String transformedIssuerDN = CertTools.stringToBCDNString(StringTools.strip(issuerDN));
        final String transformedSubjectDN = CertTools.stringToBCDNString(StringTools.strip(subjectDN));
        if (log.isDebugEnabled()) {
            log.debug("Looking for user with a certificate with issuer DN(transformed) '" + transformedIssuerDN + "' and subject DN(transformed) '"
                    + transformedSubjectDN + "'.");
        }
        try {
            return CertificateData.findUsernamesBySubjectDNAndIssuerDN(entityManager, transformedSubjectDN, transformedIssuerDN);                   
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<findUsernamesByIssuerDNAndSubjectDN(), issuer='" + issuerDN + "'");
            }
        }
    }

    @Override
    public Set<String> findUsernamesByIssuerDNAndSubjectKeyId(String issuerDN, byte[] subjectKeyId) {
        if (log.isTraceEnabled()) {
            log.trace(">findUsernamesByIssuerDNAndSubjectKeyId(), issuer='" + issuerDN + "'");
        }
        // First make a DN in our well-known format
        final String transformedIssuerDN = CertTools.stringToBCDNString(StringTools.strip(issuerDN));
        final String sSubjectKeyId = new String(Base64.encode(subjectKeyId, false));
        if (log.isDebugEnabled()) {
            log.debug("Looking for user with a certificate with issuer DN(transformed) '" + transformedIssuerDN + "' and SubjectKeyId '"
                    + sSubjectKeyId + "'.");
        }
        try {
            return CertificateData.findUsernamesByIssuerDNAndSubjectKeyId(entityManager, transformedIssuerDN, sSubjectKeyId);
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<findUsernamesByIssuerDNAndSubjectKeyId(), issuer='" + issuerDN + "'");
            }
        }
    }

    @Override
    public String findUsernameByIssuerDnAndSerialNumber(String issuerDn, BigInteger serialNumber) {
        return CertificateData.findUsernameByIssuerDnAndSerialNumber(entityManager, issuerDn, serialNumber.toString());
    }
    
    @SuppressWarnings("unchecked")
    @Override
    public String findUsernameByFingerprint(String fingerprint) {
        final Query query = entityManager.createQuery("SELECT a.username FROM CertificateData a WHERE a.fingerprint=:fingerprint");
        query.setParameter("fingerprint", fingerprint);
        final List<String> usernames = query.getResultList();
        if (usernames.isEmpty()) {
            return null;
        } else {
            return usernames.get(0);
        }
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean isOnlyUsernameForSubjectKeyIdOrDnAndIssuerDN(final String issuerDN, final byte subjectKeyId[], final String subjectDN, final String username) {
        if (log.isTraceEnabled()) {
            log.trace(">isOnlyUsernameForSubjectKeyIdOrDnAndIssuerDN(), issuer='" + issuerDN + "'");
        }
        // First make a DN in our well-known format
        final String transformedIssuerDN = CertTools.stringToBCDNString(StringTools.strip(issuerDN));
        final String sSubjectKeyId = new String(Base64.encode(subjectKeyId, false));
        final String transformedSubjectDN = CertTools.stringToBCDNString(StringTools.strip(subjectDN));
        if (log.isDebugEnabled()) {
            log.debug("Looking for user with a certificate with issuer DN(transformed) '" + transformedIssuerDN + "' and SubjectKeyId '"
                    + sSubjectKeyId + "' OR subject DN(transformed) '"+ transformedSubjectDN + "'.");
        }
        try {
            final Set<String> usernames = CertificateData.findUsernamesBySubjectKeyIdOrDnAndIssuer(entityManager, transformedIssuerDN, sSubjectKeyId, transformedSubjectDN);
            return usernames.size()==0 || (usernames.size()==1 && usernames.contains(username));
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<isOnlyUsernameForSubjectKeyIdOrDnAndIssuerDN(), issuer='" + issuerDN + "'");
            }
        }
    }

    @Override
    public List<Certificate> findCertificatesBySubject(final String subjectDN) {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificatesBySubject(), dn='" + subjectDN + "'");
        }
        // First make a DN in our well-known format
        final List<Certificate> ret = new ArrayList<Certificate>();
        for (final CertificateDataWrapper cdw : getCertificateDatasBySubject(subjectDN)) {
            ret.add(cdw.getCertificate());
        }
        if (log.isTraceEnabled()) {
            log.trace("<findCertificatesBySubject(), dn='" + subjectDN + "': "+ret.size());
        }
        return ret;
    }

    @Override
    public List<CertificateDataWrapper> getCertificateDatasBySubject(final String subjectDN) {
        // First make a DN in our well-known format
        final String dn = CertTools.stringToBCDNString(StringTools.strip(subjectDN));
        if (log.isDebugEnabled()) {
            log.debug("Looking for cert with (transformed) DN: " + dn);
        }
        final List<CertificateDataWrapper> ret = new ArrayList<CertificateDataWrapper>();
        for (final CertificateData certificateData : CertificateData.findBySubjectDN(entityManager, dn)) {
            ret.add(new CertificateDataWrapper(certificateData, Base64CertData.findByFingerprint(entityManager, certificateData.getFingerprint())));
        }
        return ret;
    }

    @Override
    public X509Certificate findLatestX509CertificateBySubject(String subjectDN) {
        return findLatestX509CertificateBySubject(subjectDN, null, false);
    }
    
    public X509Certificate findLatestX509CertificateBySubject(String subjectDN, Certificate rolloverCA, boolean findRollover) {
        final Collection<CertificateDataWrapper> certificateDatas = getCertificateDatasBySubject(subjectDN);
        X509Certificate result = null;
        Collection<Certificate> trustedChain = null;
        if (rolloverCA != null) {
            trustedChain = new ArrayList<Certificate>();
            trustedChain.add(rolloverCA);
        }

        // Find the newest certificate
        for (CertificateDataWrapper certDataWrapper : certificateDatas) {
            final int status = certDataWrapper.getCertificateData().getStatus();
            // Ignore rollover CA certificates unless explicitly requested
            if (status == CertificateConstants.CERT_ROLLOVERPENDING && !findRollover) {
                continue;
            }
            if (certDataWrapper.getCertificate() instanceof X509Certificate) {
                final X509Certificate x509Certificate = (X509Certificate) certDataWrapper.getCertificate();
                if (rolloverCA != null) {
                    try {
                        boolean isRollover = CertTools.verify(x509Certificate, trustedChain, CertTools.getNotBefore(x509Certificate));
                        if (isRollover != findRollover) {
                            continue;
                        }
                    } catch (Exception e) {
                        log.debug("failed to check if certificate was issed by a rollover CA", e);
                        continue;
                    }
                }
                if (result == null || CertTools.getNotBefore(x509Certificate).after(CertTools.getNotBefore(result))) {
                    result = x509Certificate;
                }
            }
        }

        return result;
    }

    @Override
    public List<Certificate> findCertificatesByExpireTimeWithLimit(Date expireTime) {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificatesByExpireTimeWithLimit(), time=" + expireTime);
        }
        // First make expiretime in well know format
        log.debug("Looking for certs that expire before: " + expireTime);
        List<CertificateData> coll = CertificateData.findByExpireDateWithLimit(entityManager, expireTime.getTime());
        if (log.isDebugEnabled()) {
            log.debug("Found " + coll.size() + " certificates that expire before " + expireTime);
        }
        List<Certificate> ret = new ArrayList<Certificate>();
        for(CertificateData certData : coll) {
            ret.add(certData.getCertificate(entityManager));
        }
        
        if (log.isTraceEnabled()) {
            log.trace("<findCertificatesByExpireTimeWithLimit(), time=" + expireTime);
        }
        return ret;
    }
    
    @Override
    public List<Certificate> findCertificatesByExpireTimeWithLimit(Date expireTime, int maxNumberOfResults) {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificatesByExpireTimeWithLimit(), time=" + expireTime + " - maxNumberOfResults=" + maxNumberOfResults);
        }
        if(log.isDebugEnabled()) {
            log.debug("Looking for certs that expire before: " + expireTime);
        }
        List<CertificateData> coll = CertificateData.findByExpireDateWithLimit(entityManager, expireTime.getTime(), maxNumberOfResults);
        if (log.isDebugEnabled()) {
            log.debug("Found " + coll.size() + " certificates that expire before " + expireTime);
        }
        List<Certificate> ret = new ArrayList<Certificate>();
        for(CertificateData certData : coll) {
            ret.add(certData.getCertificate(entityManager));
        }
        
        if (log.isTraceEnabled()) {
            log.trace("<findCertificatesByExpireTimeWithLimit(), time=" + expireTime + " - maxNumberOfResults=" + maxNumberOfResults);
        }
        return ret;
    }
    
    @Override
    public List<Certificate> findCertificatesByExpireTimeAndIssuerWithLimit(Date expireTime, String issuerDN) {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificatesByExpireTimeWithLimit(), time=" + expireTime + "  - issuerDN=" + issuerDN);
        }
        if(log.isDebugEnabled()) {
            log.debug("Looking for certs that expire before: " + expireTime);
        }
        List<CertificateData> coll = CertificateData.findByExpireDateAndIssuerWithLimit(entityManager, expireTime.getTime(), issuerDN);
        if (log.isDebugEnabled()) {
            log.debug("Found " + coll.size() + " certificates that expire before " + expireTime + " and issuerDN " + issuerDN);
        }
        List<Certificate> ret = new ArrayList<Certificate>(); 
        for(CertificateData certData : coll) {
            ret.add(certData.getCertificate(entityManager));
        }
        if (log.isTraceEnabled()) {
            log.trace("<findCertificatesByExpireTimeWithLimit(), time=" + expireTime + "  - issuerDN=" + issuerDN);
        }
        return ret;
    }
    
    @Override
    public List<Certificate> findCertificatesByExpireTimeAndIssuerWithLimit(Date expireTime, String issuerDN, int maxNumberOfResults) {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificatesByExpireTimeWithLimit(), time=" + expireTime + "  - issuerDN=" + issuerDN + "  - maxNumberOfResults=" + maxNumberOfResults);
        }
        if(log.isDebugEnabled()) {
            log.debug("Looking for certs that expire before: " + expireTime);
        }
        List<CertificateData> coll = CertificateData.findByExpireDateAndIssuerWithLimit(entityManager, expireTime.getTime(), issuerDN, maxNumberOfResults);
        if (log.isDebugEnabled()) {
            log.debug("Found " + coll.size() + " certificates that expire before " + expireTime + " and issuerDN " + issuerDN);
        }
        List<Certificate> ret = new ArrayList<Certificate>(); 
        for(CertificateData certData : coll) {
            ret.add(certData.getCertificate(entityManager));
        }
        if (log.isTraceEnabled()) {
            log.trace("<findCertificatesByExpireTimeWithLimit(), time=" + expireTime + "  issuerDN=" + issuerDN + "  - maxNumberOfResults=" + maxNumberOfResults);
        }
        return ret;
    }
    
    @Override
    public List<Certificate> findCertificatesByExpireTimeAndTypeWithLimit(Date expireTime, int certificateType) {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificatesByExpireTimeAndTypeWithLimit(), time=" + expireTime + "  - type=" + certificateType);
        }
        if(log.isDebugEnabled()) {
            log.debug("Looking for certs that expire before " + expireTime + " and of type " + certificateType);
        }
        List<CertificateData> coll = CertificateData.findByExpireDateAndTypeWithLimit(entityManager, expireTime.getTime(), certificateType);
        if (log.isDebugEnabled()) {
            log.debug("Found " + coll.size() + " certificates that expire before " + expireTime + " and of type " + certificateType);
        }
        List<Certificate> ret = new ArrayList<Certificate>();
        for(CertificateData certData : coll) {
            ret.add(certData.getCertificate(entityManager));
        }
        if (log.isTraceEnabled()) {
            log.trace("<findCertificatesByExpireTimeAndTypeWithLimit(), time=" + expireTime + "  - type=" + certificateType);
        }
        return ret;
    }
    
    @Override
    public List<Certificate> findCertificatesByExpireTimeAndTypeWithLimit(Date expireTime, int certificateType, int maxNumberOfResults) {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificatesByExpireTimeAndTypeWithLimit(), time=" + expireTime + "  - type=" + certificateType + "  - maxNumberOfResults=" + maxNumberOfResults);
        }
        if(log.isDebugEnabled()) {
            log.debug("Looking for certs that expire before " + expireTime + " and of type " + certificateType);
        }
        List<CertificateData> coll = CertificateData.findByExpireDateAndTypeWithLimit(entityManager, expireTime.getTime(), certificateType, maxNumberOfResults);
        if (log.isDebugEnabled()) {
            log.debug("Found " + coll.size() + " certificates that expire before " + expireTime + " and of type " + certificateType);
        }
        List<Certificate> ret = new ArrayList<Certificate>();
        for(CertificateData certData : coll) {
            ret.add(certData.getCertificate(entityManager));
        }
        if (log.isTraceEnabled()) {
            log.trace("<findCertificatesByExpireTimeAndTypeWithLimit(), time=" + expireTime + "  - type=" + certificateType + "  - maxNumberOfResults=" + maxNumberOfResults);
        }
        return ret;
    }

    @Override
    public Collection<String> findUsernamesByExpireTimeWithLimit(Date expiretime) {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificatesByExpireTimeWithLimit: " + expiretime);
        }
        return CertificateData.findUsernamesByExpireTimeWithLimit(entityManager, new Date().getTime(), expiretime.getTime());
    }

    @Override
    public Certificate findCertificateByIssuerAndSerno(String issuerDN, BigInteger serno) {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificateByIssuerAndSerno(), dn:" + issuerDN + ", serno=" + serno.toString(16));
        }
        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(StringTools.strip(issuerDN));
        if (log.isDebugEnabled()) {
            log.debug("Looking for cert with (transformed)DN: " + dn);
        }
        Collection<CertificateData> coll = CertificateData.findByIssuerDNSerialNumber(entityManager, dn, serno.toString());
        Certificate ret = null;
        if (coll.size() > 1) {
            String msg = INTRES.getLocalizedMessage("store.errorseveralissuerserno", issuerDN, serno.toString(16));
            log.error(msg);
        }
        Certificate cert = null;
        // There are several certs, we will try to find the latest issued one
        for(CertificateData certificateData : coll) {
            cert = certificateData.getCertificate(this.entityManager);
            if (ret != null) {
                if (CertTools.getNotBefore(cert).after(CertTools.getNotBefore(ret))) {
                    // cert is never than ret
                    ret = cert;
                }
            } else {
                ret = cert;
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<findCertificateByIssuerAndSerno(), dn:" + issuerDN + ", serno=" + serno.toString(16));
        }
        return ret;
    }
    
    @Override
    public CertificateDataWrapper getCertificateDataByIssuerAndSerno(String issuerDN, BigInteger serno) {
        // First make a DN in our well-known format
        final String dn = CertTools.stringToBCDNString(StringTools.strip(issuerDN));
        final List<CertificateData> certs = CertificateData.findByIssuerDNSerialNumber(entityManager, dn, serno.toString());
        if (log.isDebugEnabled()) {
            log.debug("Found "+certs.size()+" cert(s) with (transformed) DN: " + dn + " serialNumber: " + serno.toString());
        }
        if (certs.size() > 1) {
            log.error(INTRES.getLocalizedMessage("store.errorseveralissuerserno", issuerDN, serno.toString(16)));
        }
        if (certs.size()==0) {
            return null;
        }
        final List<CertificateDataWrapper> cdws = new ArrayList<CertificateDataWrapper>();
        for (final CertificateData certificateData : certs) {
            if (CesecoreConfiguration.useBase64CertTable()) {
                final Base64CertData base64CertData = Base64CertData.findByFingerprint(entityManager, certificateData.getFingerprint());
                cdws.add(new CertificateDataWrapper(certificateData, base64CertData));
            } else {
                cdws.add(new CertificateDataWrapper(certificateData, null));
            }
        }
        Collections.sort(cdws);
        return cdws.get(0);
    }
    
    @Override
    public CertificateInfo findFirstCertificateInfo(final String issuerDN, final BigInteger serno) {
        return CertificateData.findFirstCertificateInfo(entityManager, CertTools.stringToBCDNString(issuerDN), serno.toString());
    }

    @Override
    public Collection<Certificate> findCertificatesByIssuerAndSernos(String issuerDN, Collection<BigInteger> sernos) {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificateByIssuerAndSernos()");
        }
        List<Certificate> ret = null;
        if (null == issuerDN || issuerDN.length() <= 0 || null == sernos || sernos.isEmpty()) {
            ret = new ArrayList<Certificate>();
        } else {
            String dn = CertTools.stringToBCDNString(issuerDN);
            if (log.isDebugEnabled()) {
                log.debug("Looking for cert with (transformed)DN: " + dn);
            }
            ret = CertificateData.findCertificatesByIssuerDnAndSerialNumbers(entityManager, dn, sernos);
        }
        if (log.isTraceEnabled()) {
            log.trace("<findCertificateByIssuerAndSernos()");
        }
        return ret;
    }

    @Override
    public List<CertificateDataWrapper> getCertificateDataBySerno(final BigInteger serno) {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificatesBySerno(),  serno=" + serno);
        }
        final List<CertificateDataWrapper> ret = new ArrayList<CertificateDataWrapper>();
        final List<CertificateData> coll = CertificateData.findBySerialNumber(entityManager, serno.toString());
        for (final CertificateData certificateData : coll) {
            ret.add(new CertificateDataWrapper(certificateData, Base64CertData.findByFingerprint(entityManager, certificateData.getFingerprint())));
        }
        if (log.isTraceEnabled()) {
            log.trace("<findCertificatesBySerno(), serno=" + serno);
        }
        return ret;
    }

    @Override
    public String findUsernameByCertSerno(final BigInteger serno, final String issuerdn) {
        if (log.isTraceEnabled()) {
            log.trace(">findUsernameByCertSerno(), serno: " + serno.toString(16) + ", issuerdn: " + issuerdn);
        }
        final String ret = CertificateData.findLastUsernameByIssuerDNSerialNumber(entityManager, CertTools.stringToBCDNString(issuerdn), serno.toString());
        if (log.isTraceEnabled()) {
            log.trace("<findUsernameByCertSerno(), ret=" + ret);
        }
        return ret;
    }

    @Override
    public List<CertificateDataWrapper> getCertificateDataByUsername(String username) {
        final List<CertificateDataWrapper> ret = new ArrayList<CertificateDataWrapper>();
        final List<CertificateData> certificateDatas = CertificateData.findByUsernameOrdered(entityManager, username);
        for (final CertificateData certificateData : certificateDatas) {
            if (CesecoreConfiguration.useBase64CertTable()) {
                ret.add(new CertificateDataWrapper(certificateData, Base64CertData.findByFingerprint(entityManager, certificateData.getFingerprint())));
            } else {
                ret.add(new CertificateDataWrapper(certificateData, null));
            }
        }
        return ret;
    }

    @Override
    public List<Certificate> findCertificatesByUsername(String username) {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificatesByUsername(),  username=" + username);
        }
        // This method on the entity bean does the ordering in the database
        List<CertificateData> coll = CertificateData.findByUsernameOrdered(entityManager, username);
        ArrayList<Certificate> ret = new ArrayList<Certificate>();
        Iterator<CertificateData> iter = coll.iterator();
        while (iter.hasNext()) {
            ret.add(iter.next().getCertificate(this.entityManager));
        }
        if (log.isTraceEnabled()) {
            log.trace("<findCertificatesByUsername(), username=" + username);
        }
        return ret;
    }

    @Override
    public Collection<Certificate> findCertificatesByUsernameAndStatus(String username, int status) {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificatesByUsernameAndStatus(),  username=" + username);
        }
        ArrayList<Certificate> ret = new ArrayList<Certificate>();
        // This method on the entity bean does the ordering in the database
        Collection<CertificateData> coll = CertificateData.findByUsernameAndStatus(entityManager, username, status);
        Iterator<CertificateData> iter = coll.iterator();
        while (iter.hasNext()) {
            ret.add(iter.next().getCertificate(this.entityManager));
        }
        if (log.isTraceEnabled()) {
            log.trace("<findCertificatesByUsernameAndStatus(), username=" + username);
        }
        return ret;
    }

    @Override
    public CertificateInfo getCertificateInfo(String fingerprint) {
        if (log.isTraceEnabled()) {
            log.trace(">getCertificateInfo(): " + fingerprint);
        }
        if (fingerprint == null) {
            return null;
        }
        return CertificateData.getCertificateInfo(entityManager, fingerprint);
    }

    @Override
    public Certificate findCertificateByFingerprint(String fingerprint) {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificateByFingerprint()");
        }
        Certificate ret = null;
        try {
            CertificateData res = CertificateData.findByFingerprint(entityManager, fingerprint);
            if (res != null) {
                ret = res.getCertificate(this.entityManager);
            }
        } catch (Exception e) {
            log.error("Error finding certificate with fp: " + fingerprint);
            throw new EJBException(e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<findCertificateByFingerprint()");
        }
        return ret;
    }
    
    @SuppressWarnings("unchecked")
    @Override
    public Collection<Certificate> findCertificatesBySubjectKeyId(byte[] subjectKeyId) {
        final Query query = entityManager.createQuery("SELECT a FROM CertificateData a WHERE a.subjectKeyId=:subjectKeyId");
        query.setParameter("subjectKeyId", new String(Base64.encode(subjectKeyId, false)));
        
        Collection<Certificate> result = new ArrayList<Certificate>();
        for(CertificateData certificateData : (Collection<CertificateData>) query.getResultList()) {
            result.add(certificateData.getCertificate(this.entityManager));
        }
        return result;
    }

    @Override
    public Collection<Certificate> findCertificatesByType(int type, String issuerDN) throws IllegalArgumentException {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificatesByType()");
        }
        if (type <= 0
                || type > CertificateConstants.CERTTYPE_SUBCA + CertificateConstants.CERTTYPE_ENDENTITY + CertificateConstants.CERTTYPE_ROOTCA) {
            throw new IllegalArgumentException();
        }
        Collection<Integer> ctypes = new ArrayList<Integer>();
        if ((type & CertificateConstants.CERTTYPE_SUBCA) > 0) {
            ctypes.add(CertificateConstants.CERTTYPE_SUBCA);
        }
        if ((type & CertificateConstants.CERTTYPE_ENDENTITY) > 0) {
            ctypes.add(CertificateConstants.CERTTYPE_ENDENTITY);
        }
        if ((type & CertificateConstants.CERTTYPE_ROOTCA) > 0) {
            ctypes.add(CertificateConstants.CERTTYPE_ROOTCA);
        }
        List<Certificate> ret;
        if (null != issuerDN && issuerDN.length() > 0) {
            ret = CertificateData.findActiveCertificatesByTypeAndIssuer(entityManager, ctypes, CertTools.stringToBCDNString(issuerDN));
        } else {
            ret = CertificateData.findActiveCertificatesByType(entityManager, ctypes);
        }
        if (log.isTraceEnabled()) {
            log.trace("<findCertificatesByType()");
        }
        return ret;
    }
    
    @Override
    public List<Certificate> getCertificateChain(final CertificateInfo certinfo) {
        final List<Certificate> chain = new ArrayList<Certificate>();
        final Set<String> seenFingerprints = new HashSet<String>();
        
        CertificateInfo certInChain = certinfo;
        do {
            final String fingerprint = certInChain.getFingerprint();
            final Certificate thecert = findCertificateByFingerprint(fingerprint);
            if (!seenFingerprints.add(fingerprint) || thecert == null) {
                break; // detected loop or missing cert. should not happen
            }
            chain.add(thecert);
            // roots are self-signed
            if (certInChain.getCAFingerprint().equals(fingerprint)) {
                break;
            }
            // proceed with issuer
            certInChain = getCertificateInfo(certInChain.getCAFingerprint());
        } while (certInChain != null); // should not happen
        return chain;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Deprecated // Only used by tests
    public boolean setRevokeStatus(AuthenticationToken admin, String issuerdn, BigInteger serno, Date revokedDate, int reason) throws CertificateRevokeException, AuthorizationDeniedException {
        // authorization is handled by setRevokeStatus(admin, certificate, reason, userDataDN);
        final CertificateDataWrapper cdw = getCertificateDataByIssuerAndSerno(issuerdn, serno);
        if (cdw == null) {
        	String msg = INTRES.getLocalizedMessage("store.errorfindcertserno", null, serno);
        	log.info(msg);
        	throw new CertificateRevokeException(msg);
        }
        return setRevokeStatus(admin, cdw, revokedDate, reason);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Deprecated // Only used by tests
    public boolean setRevokeStatus(AuthenticationToken admin, Certificate certificate, Date revokedDate, int reason) throws CertificateRevokeException, AuthorizationDeniedException {
        // Must be authorized to CA in order to change status is certificates issued by the CA
        if (certificate == null) {
            throw new IllegalArgumentException("Passed certificate may not be null.");
        }
        final int caid = CertTools.getIssuerDN(certificate).hashCode();
        authorizedToCA(admin, caid);
        final String fingerprint = CertTools.getFingerprintAsString(certificate);
        final CertificateData certificateData = CertificateData.findByFingerprint(entityManager, fingerprint);
        if (certificateData == null) {
            final String serialNumber = CertTools.getSerialNumberAsString(certificate);
            String msg = INTRES.getLocalizedMessage("store.errorfindcertfp", fingerprint, serialNumber);
            log.info(msg);
            throw new CertificateRevokeException(msg);
        }
        return setRevokeStatusNoAuth(admin, certificateData, revokedDate, reason);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean setRevokeStatus(AuthenticationToken admin, CertificateDataWrapper cdw, Date revokedDate, int reason) throws CertificateRevokeException, AuthorizationDeniedException {
        if (cdw == null) {
            throw new IllegalArgumentException("Passed certificate data may not be null.");
        }
        final CertificateData certificateData = cdw.getCertificateData();
        final int caid = certificateData.getIssuerDN().hashCode();
        authorizedToCA(admin, caid);
        return setRevokeStatusNoAuth(admin, certificateData, revokedDate, reason);
    }

    @Override
    public boolean setRevokeStatusNoAuth(AuthenticationToken admin, CertificateData certificateData, Date revokeDate, int reason) throws CertificateRevokeException {
        String serialNumber = "unknown";
        try {
            // This will work for X.509
            serialNumber = new BigInteger(certificateData.getSerialNumber(), 10).toString(16).toUpperCase();
        } catch (NumberFormatException e) {
            serialNumber = certificateData.getSerialNumber();
        }
        final String issuerDn = certificateData.getIssuerDN();
        final int caid = issuerDn.hashCode();
        final String username = certificateData.getUsername();
        final Date now = new Date();

        boolean returnVal = false;
        // A normal revocation
        if ( (certificateData.getStatus()!=CertificateConstants.CERT_REVOKED || certificateData.getRevocationReason()==RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD) &&
                reason!=RevokedCertInfo.NOT_REVOKED && reason!=RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL ) {
            if ( certificateData.getStatus()!=CertificateConstants.CERT_REVOKED ) {
                certificateData.setStatus(CertificateConstants.CERT_REVOKED);
                certificateData.setRevocationDate(revokeDate); // keep date if certificate on hold.
            }
            certificateData.setUpdateTime(now.getTime());
            certificateData.setRevocationReason(reason);
            
            final String msg = INTRES.getLocalizedMessage("store.revokedcert", username, certificateData.getFingerprint(), Integer.valueOf(reason), certificateData.getSubjectDN(), certificateData.getIssuerDN(), serialNumber);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            logSession.log(EventTypes.CERT_REVOKED, EventStatus.SUCCESS, ModuleTypes.CERTIFICATE, ServiceTypes.CORE, admin.toString(), String.valueOf(caid), serialNumber, username, details);
            returnVal = true; // we did change status
        } else if (((reason == RevokedCertInfo.NOT_REVOKED) || (reason == RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL))
                && (certificateData.getRevocationReason() == RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD)) {
            // Unrevoke, can only be done when the certificate was previously revoked with reason CertificateHold
            // Only allow unrevocation if the certificate is revoked and the revocation reason is CERTIFICATE_HOLD
            int status = CertificateConstants.CERT_ACTIVE;
            certificateData.setStatus(status);
            // long revocationDate = -1L; // A null Date to setRevocationDate will result in -1 stored in long column
            certificateData.setRevocationDate(null);
            certificateData.setUpdateTime(now.getTime());
            certificateData.setRevocationReason(RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL);
            
            final String msg = INTRES.getLocalizedMessage("store.unrevokedcert", username, certificateData.getFingerprint(), Integer.valueOf(reason), certificateData.getSubjectDN(), certificateData.getIssuerDN(), serialNumber);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            logSession.log(EventTypes.CERT_REVOKED, EventStatus.SUCCESS, ModuleTypes.CERTIFICATE, ServiceTypes.CORE, admin.toString(), String.valueOf(caid), serialNumber, username, details);            
            returnVal = true; // we did change status
        } else {
            final String msg = INTRES.getLocalizedMessage("store.ignorerevoke", serialNumber, Integer.valueOf(certificateData.getStatus()), Integer.valueOf(reason));
            log.info(msg);
            returnVal = false; // we did _not_ change status in the database
        }
        if (returnVal) {
            // Persist changes
            entityManager.merge(certificateData);
        }
        if (log.isTraceEnabled()) {
            log.trace("<private setRevokeStatusNoAuth(), issuerdn=" + issuerDn + ", serno=" + serialNumber);
        }
        return returnVal;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void revokeAllCertByCA(AuthenticationToken admin, String issuerdn, int reason) throws AuthorizationDeniedException {
        int revoked = 0;
        
        // Must be authorized to CA in order to change status is certificates issued by the CA
        String bcdn = CertTools.stringToBCDNString(issuerdn);
    	int caid = bcdn.hashCode();
        authorizedToCA(admin, caid);

        try {
            final int maxRows = 10000;
            int firstResult = 0;
            // Revoking all non revoked certificates.
            
            // Update 10000 records at a time
            firstResult = 0;
            List<CertificateData> list = CertificateData.findAllNonRevokedCertificates(entityManager, bcdn, firstResult, maxRows);
            while (list.size() > 0) {
            	for (int i = 0; i<list.size(); i++) {
                	CertificateData d = list.get(i);
                	d.setStatus(CertificateConstants.CERT_REVOKED);
                	d.setRevocationDate(System.currentTimeMillis());
                	d.setRevocationReason(reason);
                	revoked++;
            	}
            	firstResult += maxRows;
            	list = CertificateData.findAllNonRevokedCertificates(entityManager, bcdn, firstResult, maxRows);
            }
            final String msg = INTRES.getLocalizedMessage("store.revokedallbyca", issuerdn, Integer.valueOf(revoked), Integer.valueOf(reason));
    		Map<String, Object> details = new LinkedHashMap<String, Object>();
    		details.put("msg", msg);
    		logSession.log(EventTypes.CERT_REVOKED, EventStatus.SUCCESS, ModuleTypes.CERTIFICATE, ServiceTypes.CORE, admin.toString(), String.valueOf(caid), null, null, details);            
        } catch (Exception e) {
            final String msg = INTRES.getLocalizedMessage("store.errorrevokeallbyca", issuerdn);
            log.info(msg);
            throw new EJBException(e);
        }
    }

    @Override
    public boolean isRevoked(String issuerDN, BigInteger serno) {
        if (log.isTraceEnabled()) {
            log.trace(">isRevoked(), dn:" + issuerDN + ", serno=" + serno.toString(16));
        }
        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(issuerDN);
        boolean ret = false;
        try {
            Collection<CertificateData> coll = CertificateData.findByIssuerDNSerialNumber(entityManager, dn, serno.toString());
            if (coll.size() > 0) {
                if (coll.size() > 1) {
                    final String msg = INTRES.getLocalizedMessage("store.errorseveralissuerserno", issuerDN, serno.toString(16));
                    log.error(msg);
                }
                Iterator<CertificateData> iter = coll.iterator();
                while (iter.hasNext()) {
                    CertificateData data = iter.next();
                    // if any of the certificates with this serno is revoked, return true
                    if (data.getStatus() == CertificateConstants.CERT_REVOKED) {
                        ret = true;
                        break;
                    }
                }
            } else {
                // If there are no certificates with this serial number, return true (=revoked). Better safe than sorry!
                ret = true;
                if (log.isTraceEnabled()) {
                    log.trace("isRevoked() did not find certificate with dn " + dn + " and serno " + serno.toString(16));
                }
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<isRevoked() returned " + ret);
        }
        return ret;
    }

    @Override
    public CertificateStatus getStatus(String issuerDN, BigInteger serno) {
        if (log.isTraceEnabled()) {
            log.trace(">getStatus(), dn:" + issuerDN + ", serno=" + serno.toString(16));
        }
        // First make a DN in our well-known format
        final String dn = CertTools.stringToBCDNString(issuerDN);

        try {
            Collection<CertificateData> coll = CertificateData.findByIssuerDNSerialNumber(entityManager, dn, serno.toString());
            if (coll.size() > 1) {
                final String msg = INTRES.getLocalizedMessage("store.errorseveralissuerserno", issuerDN, serno.toString(16));
                log.error(msg);
            }
           
            for(CertificateData data : coll) {
                final CertificateStatus result = CertificateStatusHelper.getCertificateStatus(data);
                if (log.isTraceEnabled()) {
                    log.trace("<getStatus() returned " + result + " for cert number " + serno.toString(16));
                }
                return result;
            }
            if (log.isTraceEnabled()) {
                log.trace("<getStatus() did not find certificate with dn " + dn + " and serno " + serno.toString(16));
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }
        return CertificateStatus.NOT_AVAILABLE;
    }

    @Override
    public CertificateStatusHolder getCertificateAndStatus(String issuerDN, BigInteger serno) {
        if (log.isTraceEnabled()) {
            log.trace(">getCertificateAndStatus(), dn:" + issuerDN + ", serno=" + serno.toString(16));
        }
        // First make a DN in our well-known format
        final String dn = CertTools.stringToBCDNString(issuerDN);
        Collection<CertificateData> collection = CertificateData.findByIssuerDNSerialNumber(entityManager, dn, serno.toString());
        if (collection.size() > 1) {
            final String msg = INTRES.getLocalizedMessage("store.errorseveralissuerserno", issuerDN, serno.toString(16));
            log.error(msg);
        }     
        for (CertificateData data : collection) {
            final CertificateStatus result = CertificateStatusHelper.getCertificateStatus(data);
            if (log.isTraceEnabled()) {
                log.trace("<getStatus() returned " + result + " for cert number " + serno.toString(16));
            }
            return new CertificateStatusHolder(data.getCertificate(entityManager), result);
        }
        if (log.isTraceEnabled()) {
            log.trace("<getCertificateAndStatus() did not find certificate with dn " + dn + " and serno " + serno.toString(16));
        }
        return new CertificateStatusHolder(null, CertificateStatus.NOT_AVAILABLE);
    }

    @Override
    public List<Object[]> findExpirationInfo(Collection<String> cas, Collection<Integer> certificateProfiles, long activeNotifiedExpireDateMin,
            long activeNotifiedExpireDateMax, long activeExpireDateMin) {
        return CertificateData.findExpirationInfo(entityManager, cas, certificateProfiles, activeNotifiedExpireDateMin, activeNotifiedExpireDateMax,
                activeExpireDateMin);
    }
    
    private void changeStatus(AuthenticationToken admin, CertificateData certificateData, int status) throws AuthorizationDeniedException {
        if (log.isDebugEnabled()) {
            log.debug("Set status " + status + " for certificate with fp: " + certificateData.getFingerprint());
        }
        
        // Must be authorized to CA in order to change status is certificates issued by the CA
        String bcdn = CertTools.stringToBCDNString(certificateData.getIssuerDN());
        int caid = bcdn.hashCode();
        authorizedToCA(admin, caid);

        certificateData.setStatus(status);
        final Certificate certificate = certificateData.getCertificate(this.entityManager);
        String serialNo;
        if (certificate==null) {
            serialNo = certificateData.getSerialNumberHex();
        } else {
            serialNo = CertTools.getSerialNumberAsString(certificate);
        }
        final String msg = INTRES.getLocalizedMessage("store.setstatus", certificateData.getUsername(), certificateData.getFingerprint(), status, certificateData.getSubjectDN(), certificateData.getIssuerDN(), serialNo);
        Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        logSession.log(EventTypes.CERT_CHANGEDSTATUS, EventStatus.SUCCESS, ModuleTypes.CERTIFICATE, ServiceTypes.CORE, admin.toString(), String.valueOf(caid), serialNo, certificateData.getUsername(), details);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean setStatus(AuthenticationToken admin, String fingerprint, int status) throws IllegalArgumentException, AuthorizationDeniedException {
        
        if (status == CertificateConstants.CERT_REVOKED || status == CertificateConstants.CERT_ACTIVE) {
            final String msg = INTRES.getLocalizedMessage("store.errorsetstatusargument", fingerprint, status);
            throw new IllegalArgumentException(msg);
        }
    	CertificateData certificateData = CertificateData.findByFingerprint(entityManager, fingerprint);
    	if (certificateData != null) {
    	    changeStatus(admin, certificateData, status);            
    	} else {
            if (log.isDebugEnabled()) {
                final String msg = INTRES.getLocalizedMessage("store.setstatusfailed", fingerprint, status);
                log.debug(msg);
            }    		
    	}
        return (certificateData != null);
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void setRolloverDoneStatus(AuthenticationToken admin, String fingerprint) throws IllegalArgumentException, AuthorizationDeniedException {

        CertificateData certificateData = CertificateData.findByFingerprint(entityManager, fingerprint);
        if (certificateData == null) {
            throw new IllegalStateException("CA certificate with fingerprint '"+fingerprint+"' does not exist.");
        }
        
        final int prevStatus = certificateData.getStatus();
        if (prevStatus == CertificateConstants.CERT_ACTIVE) {
            return; // Nothing to do
        }
        
        if (prevStatus != CertificateConstants.CERT_ROLLOVERPENDING) {
            throw new IllegalStateException("Certificate was not in the CERT_ROLLOVERPENDING state");
        }
        changeStatus(admin, certificateData, CertificateConstants.CERT_ACTIVE);          
    }
    
    private void authorizedToCA(final AuthenticationToken admin, final int caid) throws AuthorizationDeniedException {
        if (!accessSession.isAuthorized(admin, StandardRules.CAACCESS.resource() + caid)) {
        	final String msg = INTRES.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caid);
            throw new AuthorizationDeniedException(msg);
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Certificate findMostRecentlyUpdatedActiveCertificate(byte[] subjectKeyId) {
        Certificate certificate = null;
        final String subjectKeyIdString = new String(Base64.encode(subjectKeyId, false));
        log.debug("Searching for subjectKeyIdString " + subjectKeyIdString);
        final Query query = this.entityManager.createQuery("SELECT a FROM CertificateData a WHERE a.subjectKeyId=:subjectKeyId AND a.status=:status ORDER BY a.updateTime DESC");
        query.setParameter("subjectKeyId", subjectKeyIdString);
        query.setParameter("status", CertificateConstants.CERT_ACTIVE);
        query.setMaxResults(1);
        @SuppressWarnings("unchecked")
        final List<CertificateData> resultList = query.getResultList();
        if (resultList.size() == 1) {
            certificate = resultList.get(0).getCertificate(this.entityManager);
            if (certificate==null && log.isDebugEnabled()) {
                log.debug("Reference to an issued certificate with subjectKeyId "+subjectKeyId+" found, but the certificate is not stored in the database.");
            }
        }
        return certificate;
    }
    

    @Override
    public String getCADnFromRequest(final RequestMessage req) {
        String dn = req.getIssuerDN();
        if (log.isDebugEnabled()) {
            log.debug("Got an issuerDN: " + dn);
        }
        // If we have issuer and serialNo, we must find the CA certificate, to get the CAs subject name
        // If we don't have a serialNumber, we take a chance that it was actually the subjectDN (for example a RootCA)
        final BigInteger serno = req.getSerialNo();
        if (serno != null) {
            if (log.isDebugEnabled()) {
                log.debug("Got a serialNumber: " + serno.toString(16));
            }

            final Certificate cert = findCertificateByIssuerAndSerno(dn, serno);
            if (cert != null) {
                dn = CertTools.getSubjectDN(cert);
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Using DN: " + dn);
        }
        return dn;
    }

    // 
    // Classes for checking Unique issuerDN/serialNumber index in the database. If we have such an index, we can allow
    // certificate serial number override, where user specifies the serial number to be put in the certificate.
    //

    @Override
    public void resetUniqueCertificateSerialNumberIndex() {
        log.info("Resetting isUniqueCertificateSerialNumberIndex to null.");
        UniqueSernoHelper.setIsUniqueCertificateSerialNumberIndex(null);
    }

    @Override
    public void setUniqueCertificateSerialNumberIndex(final Boolean value) {
        log.info("Setting isUniqueCertificateSerialNumberIndex to: "+value);
        UniqueSernoHelper.setIsUniqueCertificateSerialNumberIndex(value);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean isUniqueCertificateSerialNumberIndex() {
        // Must always run in a transaction in order to store certificates, EntityManager requires use within a transaction
        if (UniqueSernoHelper.getIsUniqueCertificateSerialNumberIndex() == null) {
            // Only create new transactions to store certificates and call this, if the variable is not initialized.
            // If it is already set we don't have to waste time creating a new transaction
            
            // Sets variables (but only once) that can be checked with isUniqueCertificateSerialNumberIndex().
            // This part must be called first (at least once).
            final String userName = "checkUniqueIndexTestUserNotToBeUsed_fjasdfjsdjfsad"; // This name should only be used for this test. Made complex so that no one else will use the same.
            // Loading two dummy certificates. These certificates has same serial number and issuer.
            // It should not be possible to store both of them in the DB.
            final X509Certificate cert1 = UniqueSernoHelper.getTestCertificate1();
            final X509Certificate cert2 = UniqueSernoHelper.getTestCertificate2();
            final Certificate c1 = findCertificateByFingerprint(CertTools.getFingerprintAsString(cert1));
            final Certificate c2 = findCertificateByFingerprint(CertTools.getFingerprintAsString(cert2));
            if ( (c1 != null) && (c2 != null) ) {
                // already proved that not checking index for serial number.
                UniqueSernoHelper.setIsUniqueCertificateSerialNumberIndex(Boolean.FALSE);
            }
            final AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Internal database constraint test"));
            if (c1 == null) {// storing initial certificate if no test certificate created.
                try {
                    // needs to call using "certificateStoreSession." in order to honor the transaction annotations
                    certificateStoreSession.checkForUniqueCertificateSerialNumberIndexInTransaction(admin, cert1, userName, "abcdef0123456789", CertificateConstants.CERT_INACTIVE, 0, 0, "", new Date().getTime());
                } catch (Throwable e) { // NOPMD, we really need to catch all, never crash
                    throw new RuntimeException("It should always be possible to store initial dummy certificate.", e);
                }
            }
            UniqueSernoHelper.setIsUniqueCertificateSerialNumberIndex(Boolean.FALSE);           
            if (c2 == null) { // storing a second certificate with same issuer 
                try { 
                    // needs to call using "certificateStoreSession." in order to honor the transaction annotations
                    certificateStoreSession.checkForUniqueCertificateSerialNumberIndexInTransaction(admin, cert2, userName, "fedcba9876543210", CertificateConstants.CERT_INACTIVE, 0, 0, "", new Date().getTime());
                } catch (Throwable e) { // NOPMD, we really need to catch all, never crash
                    log.info("certificateStoreSession.checkForUniqueCertificateSerialNumberIndexInTransaction threw Throwable (normal if there is a unique issuerDN/serialNumber index): "+e.getMessage());
                    log.info("Unique index in CertificateData table for certificate serial number");
                    // Exception is thrown when unique index is working and a certificate with same serial number is in the database.
                    UniqueSernoHelper.setIsUniqueCertificateSerialNumberIndex(Boolean.TRUE);
                }
            }
            if (!UniqueSernoHelper.getIsUniqueCertificateSerialNumberIndex().booleanValue()) {
                // It was possible to store a second certificate with same serial number. Unique number not working.
                log.info( INTRES.getLocalizedMessage("createcert.not_unique_certserialnumberindex") );
            }
            // Remove potentially stored certificates so anyone can create the unique index if wanted
            try { 
                certificateStoreSession.removeUniqueCertificateSerialNumberTestCertificates();
                log.info("Removed rows used during test for unique certificate serial number database constraint.");
            } catch (Throwable e) { // NOPMD, we really need to catch all, never crash
                log.debug("Unable to clean up database rows used during test for unique certificate serial number."+
                        " This is expected if DELETE is not granted to the EJBCA database user.", e);
            }
        }
        return UniqueSernoHelper.getIsUniqueCertificateSerialNumberIndex()!=null && UniqueSernoHelper.getIsUniqueCertificateSerialNumberIndex().booleanValue();
    }


    // We want each storage of a certificate to run in a new transactions, so we can catch errors as they happen..
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public void checkForUniqueCertificateSerialNumberIndexInTransaction(AuthenticationToken admin, Certificate incert, String username, String cafp, int status, int type,
            int certificateProfileId, String tag, long updateTime) throws AuthorizationDeniedException {
        storeCertificate(admin, incert, username, cafp, status, type, certificateProfileId, tag, updateTime);
    }

    // We want deletion of a certificates to run in a new transactions, so we can catch errors as they happen..
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public void removeUniqueCertificateSerialNumberTestCertificates() {
        final X509Certificate x509Certificate1 = UniqueSernoHelper.getTestCertificate1();
        final X509Certificate x509Certificate2 = UniqueSernoHelper.getTestCertificate2();
        final String fingerprint1 = CertTools.getFingerprintAsString(x509Certificate1);
        final String fingerprint2 = CertTools.getFingerprintAsString(x509Certificate2);
        entityManager.createNativeQuery("DELETE FROM Base64CertData WHERE fingerprint IN ('"+fingerprint1+"', '"+fingerprint2+"')").executeUpdate();
        entityManager.createNativeQuery("DELETE FROM CertificateData WHERE fingerprint IN ('"+fingerprint1+"', '"+fingerprint2+"')").executeUpdate();
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void updateLimitedCertificateDataStatus(final AuthenticationToken admin, final int caId, final String issuerDn, final BigInteger serialNumber,
            final Date revocationDate, final int reasonCode, final String caFingerprint) throws AuthorizationDeniedException {
        if (!accessSession.isAuthorizedNoLogging(admin, StandardRules.CAACCESS.resource() + caId)) {
            final String msg = INTRES.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caId);
            throw new AuthorizationDeniedException(msg);
        }
        final String limitedFingerprint = getLimitedCertificateDataFingerprint(issuerDn, serialNumber);
        final CertificateDataWrapper cdw = getCertificateDataByIssuerAndSerno(issuerDn, serialNumber);
        if (cdw==null) {
            if (reasonCode==RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL) {
                deleteLimitedCertificateData(limitedFingerprint);
            } else {
                // Create a limited entry
                final CertificateData limitedCertificateData = new CertificateData();
                limitedCertificateData.setFingerprint(limitedFingerprint);
                limitedCertificateData.setSerialNumber(serialNumber.toString());
                limitedCertificateData.setIssuer(issuerDn);
                // The idea is to set SubjectDN to an empty string. However, since Oracle treats an empty String as NULL, 
                // and since CertificateData.SubjectDN has a constraint that it should not be NULL, we are setting it to 
                // "CN=limited" instead of an empty string
                limitedCertificateData.setSubjectDN("CN=limited");
                limitedCertificateData.setCertificateProfileId(new Integer(CertificateProfileConstants.CERTPROFILE_NO_PROFILE));
                limitedCertificateData.setStatus(CertificateConstants.CERT_REVOKED);
                limitedCertificateData.setRevocationReason(reasonCode);
                limitedCertificateData.setRevocationDate(revocationDate);
                limitedCertificateData.setUpdateTime(Long.valueOf(System.currentTimeMillis()));
                limitedCertificateData.setCaFingerprint(caFingerprint);
                log.info("Adding limited CertificateData entry with fingerprint=" + limitedFingerprint + ", serialNumber=" + serialNumber.toString(16).toUpperCase()+", issuerDn='"+issuerDn+"'");
                entityManager.persist(limitedCertificateData);
            }
        } else if (limitedFingerprint.equals(cdw.getCertificateData().getFingerprint())) {
        	if (reasonCode==RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL) {
                deleteLimitedCertificateData(limitedFingerprint);
        	} else {
        	    final CertificateData limitedCertificateData = cdw.getCertificateData();
        	    if (cdw.getCertificateData().getRevocationDate()!=revocationDate.getTime() || cdw.getCertificateData().getRevocationReason()!=reasonCode) {
                    // Update the limited entry
                    log.info("Updating limited CertificateData entry with fingerprint=" + limitedFingerprint + ", serialNumber=" + serialNumber.toString(16).toUpperCase()+", issuerDn='"+issuerDn+"'");
                    limitedCertificateData.setStatus(CertificateConstants.CERT_REVOKED);
                    limitedCertificateData.setRevocationReason(reasonCode);
                    limitedCertificateData.setRevocationDate(revocationDate);
                    limitedCertificateData.setUpdateTime(Long.valueOf(System.currentTimeMillis()));
                    entityManager.merge(limitedCertificateData);
        	    } else {
        	        if (log.isDebugEnabled()) {
                        log.debug("Limited CertificateData entry with fingerprint=" + limitedFingerprint + ", serialNumber=" + serialNumber.toString(16).toUpperCase()+", issuerDn='"+issuerDn+"' was already up to date.");
        	        }
        	    }
        	}
        } else {
            // Refuse to update a normal entry with this method
        	throw new UnsupportedOperationException("Only limited certificate entries can be updated using this method.");
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS) 
    public void reloadCaCertificateCache() {
        log.info("Reloading CA certificate cache.");
        Collection<Certificate> certs = certificateStoreSession.findCertificatesByType(CertificateConstants.CERTTYPE_SUBCA +
                CertificateConstants.CERTTYPE_ROOTCA, null);
        CaCertificateCache.INSTANCE.loadCertificates(certs);
    }

    /**
     * When a timer expires, this method will update
     * 
     * According to JSR 220 FR (18.2.2), this method may not throw any exceptions.
     * 
     * @param timer The timer whose expiration caused this notification.
     */
    @Timeout
    /* Glassfish 2.1.1:
     * "Timeout method ....timeoutHandler(javax.ejb.Timer)must have TX attribute of TX_REQUIRES_NEW or TX_REQUIRED or TX_NOT_SUPPORTED"
     * JBoss 5.1.0.GA: We cannot mix timer updates with our EJBCA DataSource transactions. 
     */
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void timeoutHandler(Timer timer) {
        if (log.isTraceEnabled()) {
            log.trace(">timeoutHandler: " + timer.getInfo().toString());
        }
        if (timer.getInfo() instanceof Integer) {
            final int currentTimerId = ((Integer)timer.getInfo()).intValue();
            if (currentTimerId==TIMERID_CACERTIFICATECACHE) {
            	reloadCaCertificateCacheAndSetTimeout();
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<timeoutHandler");
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void reloadCaCertificateCacheAndSetTimeout() {
        if (log.isTraceEnabled()) {
            log.trace(">timeOutReloadCaCertificateCache");
        }
        // Cancel any waiting timers of this type
        @SuppressWarnings("unchecked")
        final Collection<Timer> timers = timerService.getTimers();
        for (final Timer timer : timers) {
            if (timer.getInfo() instanceof Integer) {
                final int currentTimerId = ((Integer)timer.getInfo()).intValue();
                if (currentTimerId==TIMERID_CACERTIFICATECACHE) {
                    timer.cancel();
                }
            }
        }
        try {      
            certificateStoreSession.reloadCaCertificateCache();
        } finally {
            // Schedule a new timer of this type
            final long interval = OcspConfiguration.getSigningCertsValidTimeInMilliseconds();
            if (interval > 0) {
                timerService.createTimer(interval, Integer.valueOf(TIMERID_CACERTIFICATECACHE));
            }
        }
    }

    /** @return the number of timers where TimerInfo is an Integer and hold the specified value */
    private int getTimerCount(final int id) {
        if (log.isTraceEnabled()) {
            log.trace(">getTimerCount");
        }
        int count = 0;
        @SuppressWarnings("unchecked")
        final Collection<Timer> timers = timerService.getTimers();
        for (final Timer timer : timers) {
            if (timer.getInfo() instanceof Integer) {
                final int currentTimerId = ((Integer)timer.getInfo()).intValue();
                if (currentTimerId==id) {
                    count++;
                }
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<getTimerCount, timers: " + count);
        }
        return count;
    }

    /** @return something that looks like a normal certificate fingerprint and is unique for each certificate entry */
    private String getLimitedCertificateDataFingerprint(final String issuerDn, final BigInteger serialNumber) {
        return CertTools.getFingerprintAsString((issuerDn+";"+serialNumber).getBytes());
    }

    /** Remove limited CertificateData by fingerprint (and ensures that this is not a full entry by making sure that subjectKeyId is NULL */
    private boolean deleteLimitedCertificateData(final String fingerprint) {
        log.info("Removing CertificateData entry with fingerprint=" + fingerprint + " and no subjectKeyId is defined.");
        final Query query = entityManager.createQuery("DELETE FROM CertificateData a WHERE a.fingerprint=:fingerprint AND subjectKeyId IS NULL");
        query.setParameter("fingerprint", fingerprint);
        final int deletedRows = query.executeUpdate();
        if (log.isDebugEnabled()) {
            log.debug("Deleted "+deletedRows+" rows with fingerprint " + fingerprint);
        }
        return deletedRows == 1;
    }
}
