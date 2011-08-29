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
import java.security.cert.X509Certificate;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ejb.CreateException;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.Stateless;
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
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.cvc.PublicKeyEC;

/**
 * Based on EJBCA version: CertificateStoreSessionBean.java 11170 2011-01-12 17:08:32Z anatom
 * 
 * @version $Id: CertificateStoreSessionBean.java 1026 2011-08-23 15:00:31Z mikek $
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CertificateStoreSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class CertificateStoreSessionBean implements CertificateStoreSessionRemote, CertificateStoreSessionLocal {

    private final static Logger log = Logger.getLogger(CertificateStoreSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @EJB
    private AccessControlSessionLocal accessSession;
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean storeCertificate(AuthenticationToken admin, Certificate incert, String username, String cafp, int status, int type,
            int certificateProfileId, String tag, long updateTime) throws CreateException, AuthorizationDeniedException {
    	// Check that user is authorized to the CA that issued this certificate
    	int caid = CertTools.getIssuerDN(incert).hashCode();
        authorizedToCA(admin, caid);
        
    	return storeCertificateNoAuth(admin, incert, username, cafp, status, type, certificateProfileId, tag, updateTime);
    }
    
    /** Local interface only */
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean storeCertificateNoAuth(AuthenticationToken adminForLogging, Certificate incert, String username, String cafp, int status, int type,
            int certificateProfileId, String tag, long updateTime) throws CreateException {
        if (log.isTraceEnabled()) {
            log.trace(">storeCertificateNoAuth(" + username + ", " + cafp + ", " + status + ", " + type + ")");
        }
        // Strip dangerous chars
        username = StringTools.strip(username);

        // We need special handling here of CVC certificate with EC keys, because they lack EC parameters in all certs except the Root certificate
        // (CVCA)
        PublicKey pubk = incert.getPublicKey();
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
                        if (cacert == null) {
                            throw new FinderException();
                        }
                        String nextcafp = cacert.getCaFingerprint();
                        int bar = 0; // never go more than 5 rounds, who knows what strange things can exist in the CAFingerprint column, make sure we
                                     // never get stuck here
                        while ((!StringUtils.equals(cafingerp, nextcafp)) && (bar++ < 5)) {
                            cacert = CertificateData.findByFingerprint(entityManager, cafp);
                            if (cacert == null) {
                                throw new FinderException();
                            }
                            cafingerp = nextcafp;
                            nextcafp = cacert.getCaFingerprint();
                        }
                        // We found a root CA certificate, hopefully ?
                        PublicKey pkwithparams = cacert.getCertificate().getPublicKey();
                        pubk = KeyTools.getECPublicKeyWithParams(pubk, pkwithparams);
                    }
                } catch (FinderException e) {
                    log.info("Can not find CA certificate with fingerprint: " + cafp);
                } catch (Exception e) {
                    // This catches NoSuchAlgorithmException, NoSuchProviderException and InvalidKeySpecException and possibly something else (NPE?)
                    // because we want to continue anyway
                    if (log.isDebugEnabled()) {
                        log.debug("Can not enrich EC public key with missing parameters: ", e);
                    }
                }
            }
        } // finished with ECC key special handling

        // Create the certificate in one go with all parameters at once. This used to be important in EJB2.1 so the persistence layer only creates
        // *one* single
        // insert statement. If we do a home.create and the some setXX, it will create one insert and one update statement to the database.
        // Probably not important in EJB3 anymore
        CertificateData data1 = new CertificateData(incert, pubk, username, cafp, status, type, certificateProfileId, tag, updateTime);
        try {
            entityManager.persist(data1);
        } catch (Exception e) {
            // For backward compatibility. We should drop the throw entirely and rely on the return value.
            CreateException ce = new CreateException();
            ce.setStackTrace(e.getStackTrace());
            throw ce;
        }
        final String serialNo = CertTools.getSerialNumberAsString(incert);
		final String msg = INTRES.getLocalizedMessage("store.storecert", username, data1.getFingerprint(), data1.getSubjectDN(), data1.getIssuerDN(), serialNo);
		Map<String, Object> details = new LinkedHashMap<String, Object>();
		details.put("msg", msg);
		final String caId = Integer.valueOf(CertTools.getIssuerDN(incert).hashCode()).toString();
		logSession.log(EventTypes.CERT_STORED, EventStatus.SUCCESS, ModuleTypes.CERTIFICATE, ServiceTypes.CORE, adminForLogging.toString(), caId, serialNo, username, details);
        if (log.isTraceEnabled()) {
            log.trace("<storeCertificateNoAuth()");
        }
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
    public Collection<Certificate> findCertificatesBySubjectAndIssuer(String subjectDN, String issuerDN) {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificatesBySubjectAndIssuer(), dn='" + subjectDN + "' and issuer='" + issuerDN + "'");
        }
        // First make a DN in our well-known format
        String dn = StringTools.strip(subjectDN);
        dn = CertTools.stringToBCDNString(dn);
        String issuerdn = StringTools.strip(issuerDN);
        issuerdn = CertTools.stringToBCDNString(issuerdn);
        log.debug("Looking for cert with (transformed)DN: " + dn);
        Collection<Certificate> ret = new ArrayList<Certificate>();
        Collection<CertificateData> coll = CertificateData.findBySubjectDNAndIssuerDN(entityManager, dn, issuerdn);
        Iterator<CertificateData> iter = coll.iterator();
        while (iter.hasNext()) {
            ret.add(iter.next().getCertificate());
        }
        if (log.isTraceEnabled()) {
            log.trace("<findCertificatesBySubjectAndIssuer(), dn='" + subjectDN + "' and issuer='" + issuerDN + "'");
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
    public Set<String> findUsernamesByIssuerDNAndSubjectKeyId(String issuerDN, byte subjectKeyId[]) {
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
    public Collection<Certificate> findCertificatesBySubject(String subjectDN) {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificatesBySubject(), dn='" + subjectDN + "'");
        }
        // First make a DN in our well-known format
        String dn = StringTools.strip(subjectDN);
        dn = CertTools.stringToBCDNString(dn);
        if (log.isDebugEnabled()) {
            log.debug("Looking for cert with (transformed)DN: " + dn);
        }
        Collection<Certificate> ret = new ArrayList<Certificate>();
        for (CertificateData certificate : CertificateData.findBySubjectDN(entityManager, dn)) {
            ret.add(certificate.getCertificate());
        }
        if (log.isTraceEnabled()) {
            log.trace("<findCertificatesBySubject(), dn='" + subjectDN + "'");
        }
        return ret;
    }

    @Override
    public X509Certificate findLatestX509CertificateBySubject(String subjectDN) {
        Collection<Certificate> certificates = findCertificatesBySubject(subjectDN);

        X509Certificate result = null;

        /**
         * Iterate through all certificates, find the X509Certificate with the newest date.
         */
        for (Certificate certificate : certificates) {
            if (certificate instanceof X509Certificate) {
                X509Certificate x509Certificate = (X509Certificate) certificate;
                if (result == null || CertTools.getNotBefore(x509Certificate).after(CertTools.getNotBefore(result))) {
                    result = x509Certificate;
                }
            }
        }

        return result;
    }

    @Override
    public Collection<Certificate> findCertificatesByExpireTimeWithLimit(Date expireTime) {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificatesByExpireTimeWithLimit(), time=" + expireTime);
        }
        // First make expiretime in well know format
        log.debug("Looking for certs that expire before: " + expireTime);
        Collection<CertificateData> coll = CertificateData.findByExpireDateWithLimit(entityManager, expireTime.getTime());
        Collection<Certificate> ret = new ArrayList<Certificate>();
        if (log.isDebugEnabled()) {
            log.debug("Found " + coll.size() + " certificates that expire before " + expireTime);
        }
        Iterator<CertificateData> iter = coll.iterator();
        while (iter.hasNext()) {
            ret.add(iter.next().getCertificate());
        }
        if (log.isTraceEnabled()) {
            log.trace("<findCertificatesByExpireTimeWithLimit(), time=" + expireTime);
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
        Iterator<CertificateData> iter = coll.iterator();
        Certificate cert = null;
        // There are several certs, we will try to find the latest issued one
        while (iter.hasNext()) {
            cert = iter.next().getCertificate();
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
    public Collection<Certificate> findCertificatesBySerno(BigInteger serno) {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificatesBySerno(),  serno=" + serno);
        }
        ArrayList<Certificate> ret = new ArrayList<Certificate>();
        Collection<CertificateData> coll = CertificateData.findBySerialNumber(entityManager, serno.toString());
        Iterator<CertificateData> iter = coll.iterator();
        while (iter.hasNext()) {
            ret.add(iter.next().getCertificate());
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
    public Collection<Certificate> findCertificatesByUsername(String username) {
        if (log.isTraceEnabled()) {
            log.trace(">findCertificatesByUsername(),  username=" + username);
        }
        // Strip dangerous chars
        username = StringTools.strip(username);
        // This method on the entity bean does the ordering in the database
        Collection<CertificateData> coll = CertificateData.findByUsernameOrdered(entityManager, username);
        ArrayList<Certificate> ret = new ArrayList<Certificate>();
        Iterator<CertificateData> iter = coll.iterator();
        while (iter.hasNext()) {
            ret.add(iter.next().getCertificate());
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
        // Strip dangerous chars
        username = StringTools.strip(username);
        // This method on the entity bean does the ordering in the database
        Collection<CertificateData> coll = CertificateData.findByUsernameAndStatus(entityManager, username, status);
        Iterator<CertificateData> iter = coll.iterator();
        while (iter.hasNext()) {
            ret.add(iter.next().getCertificate());
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
                ret = res.getCertificate();
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
            result.add(certificateData.getCertificate());
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
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean setRevokeStatus(AuthenticationToken admin, String issuerdn, BigInteger serno, int reason, String userDataDN)
            throws CertificateRevokeException, AuthorizationDeniedException {
        return setRevokeStatus(admin, issuerdn, serno, new Date(), reason, userDataDN);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean setRevokeStatus(AuthenticationToken admin, String issuerdn, BigInteger serno, Date revokedDate, int reason, String userDataDN)
            throws CertificateRevokeException, AuthorizationDeniedException {
        // authorization is handled by setRevokeStatus(admin, certificate, reason, userDataDN);
        Certificate certificate = findCertificateByIssuerAndSerno(issuerdn, serno);
        if (certificate == null) {
        	String msg = INTRES.getLocalizedMessage("store.errorfindcertserno", null, serno);
        	log.info(msg);
        	throw new CertificateRevokeException(msg);
        }
        return setRevokeStatus(admin, certificate, revokedDate, reason, userDataDN);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean setRevokeStatus(AuthenticationToken admin, Certificate certificate, int reason, String userDataDN) throws CertificateRevokeException,
            AuthorizationDeniedException {
        return setRevokeStatus(admin, certificate, new Date(), reason, userDataDN);
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean setRevokeStatus(AuthenticationToken admin, Certificate certificate, Date revokedDate, int reason, String userDataDN)
            throws CertificateRevokeException, AuthorizationDeniedException {
        if (certificate == null) {
            return false;
        }
        
        // Must be authorized to CA in order to change status is certificates issued by the CA
    	int caid = CertTools.getIssuerDN(certificate).hashCode();
        authorizedToCA(admin, caid);
        
        return setRevokeStatusNoAuth(admin, certificate, revokedDate, reason, userDataDN);
    }
    
    /** Local interface only */
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean setRevokeStatusNoAuth(AuthenticationToken admin, Certificate certificate, Date revokeDate, int reason, String userDataDN)
            throws CertificateRevokeException, AuthorizationDeniedException {
        if (certificate == null) {
            return false;
        }
        if (log.isTraceEnabled()) {
            log.trace(">private setRevokeStatusNoAuth(Certificate), issuerdn=" + CertTools.getIssuerDN(certificate) + ", serno="
                    + CertTools.getSerialNumberAsString(certificate));
        }
        
    	int caid = CertTools.getIssuerDN(certificate).hashCode(); // used for logging

        String fp = CertTools.getFingerprintAsString(certificate);
        CertificateData rev = CertificateData.findByFingerprint(entityManager, fp);
        if (rev == null) {
            String msg = INTRES.getLocalizedMessage("store.errorfindcertserno",fp,  CertTools.getSerialNumberAsString(certificate));
            log.info(msg);
            throw new CertificateRevokeException(msg);
        }
        String username = rev.getUsername();
        Date now = new Date();
        String serialNo = CertTools.getSerialNumberAsString(certificate); // for logging

        boolean returnVal = false;
        // A normal revocation
        if ((rev.getStatus() != CertificateConstants.CERT_REVOKED) && (reason != RevokedCertInfo.NOT_REVOKED)
                && (reason != RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL)) {
            rev.setStatus(CertificateConstants.CERT_REVOKED);
            rev.setRevocationDate(revokeDate);
            rev.setUpdateTime(now.getTime());
            rev.setRevocationReason(reason);
            
    		final String msg = INTRES.getLocalizedMessage("store.revokedcert", username, rev.getFingerprint(), Integer.valueOf(reason), rev.getSubjectDN(), rev.getIssuerDN(), serialNo);
    		Map<String, Object> details = new LinkedHashMap<String, Object>();
    		details.put("msg", msg);
    		logSession.log(EventTypes.CERT_REVOKED, EventStatus.SUCCESS, ModuleTypes.CERTIFICATE, ServiceTypes.CORE, admin.toString(), Integer.valueOf(caid).toString(), serialNo, username, details);
    		returnVal = true; // we did change status
        } else if (((reason == RevokedCertInfo.NOT_REVOKED) || (reason == RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL))
                && (rev.getRevocationReason() == RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD)) {
            // Unrevoke, can only be done when the certificate was previously revoked with reason CertificateHold
            // Only allow unrevocation if the certificate is revoked and the revocation reason is CERTIFICATE_HOLD
            int status = CertificateConstants.CERT_ACTIVE;
            rev.setStatus(status);
            // long revocationDate = -1L; // A null Date to setRevocationDate will result in -1 stored in long column
            rev.setRevocationDate(null);
            rev.setUpdateTime(now.getTime());
            int revocationReason = RevokedCertInfo.NOT_REVOKED;
            rev.setRevocationReason(revocationReason);
            
    		final String msg = INTRES.getLocalizedMessage("store.unrevokedcert", username, rev.getFingerprint(), Integer.valueOf(reason), rev.getSubjectDN(), rev.getIssuerDN(), serialNo);
    		Map<String, Object> details = new LinkedHashMap<String, Object>();
    		details.put("msg", msg);
    		logSession.log(EventTypes.CERT_REVOKED, EventStatus.SUCCESS, ModuleTypes.CERTIFICATE, ServiceTypes.CORE, admin.toString(), Integer.valueOf(caid).toString(), serialNo, username, details);            
    		returnVal = true; // we did change status
        } else {
            final String msg = INTRES.getLocalizedMessage("store.ignorerevoke", serialNo, Integer.valueOf(rev.getStatus()), Integer.valueOf(reason));
            log.info(msg);
    		returnVal = false; // we did _not_ change status in the database
        }
        if (log.isTraceEnabled()) {
            log.trace("<private setRevokeStatusNoAuth(), issuerdn=" + CertTools.getIssuerDN(certificate) + ", serno="
                    + CertTools.getSerialNumberAsString(certificate));
        }
        return returnVal;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void revokeAllCertByCA(AuthenticationToken admin, String issuerdn, int reason) throws AuthorizationDeniedException {
        int temprevoked = 0;
        int revoked = 0;
        
        // Must be authorized to CA in order to change status is certificates issued by the CA
        String bcdn = CertTools.stringToBCDNString(issuerdn);
    	int caid = bcdn.hashCode();
        authorizedToCA(admin, caid);

        try {
            final int maxRows = 10000;
            int firstResult = 0;
            // Change all temporary revoked certificates to permanently revoked certificates
            List<CertificateData> list = CertificateData.findAllOnHold(entityManager, bcdn, firstResult, maxRows);
            while (list.size() > 0) {
            	for (int i = 0; i<list.size(); i++) {
                	CertificateData d = list.get(i);
                	d.setStatus(CertificateConstants.CERT_REVOKED);
            	}
            	firstResult += maxRows;
            	list = CertificateData.findAllNonRevokedCertificates(entityManager, bcdn, firstResult, maxRows);
            }
            //temprevoked = CertificateData.revokeOnHoldPermanently(entityManager, bcdn);
            // Revoking all non revoked certificates.
            
            // Update 10000 records at a time
            firstResult = 0;
            list = CertificateData.findAllNonRevokedCertificates(entityManager, bcdn, firstResult, maxRows);
            while (list.size() > 0) {
            	for (int i = 0; i<list.size(); i++) {
                	CertificateData d = list.get(i);
                	d.setStatus(CertificateConstants.CERT_REVOKED);
                	d.setRevocationDate(System.currentTimeMillis());
                	d.setRevocationReason(reason);
            	}
            	firstResult += maxRows;
            	list = CertificateData.findAllNonRevokedCertificates(entityManager, bcdn, firstResult, maxRows);
            }
            final String msg = INTRES.getLocalizedMessage("store.revokedallbyca", issuerdn, Integer.valueOf(revoked + temprevoked), Integer.valueOf(reason));
    		Map<String, Object> details = new LinkedHashMap<String, Object>();
    		details.put("msg", msg);
    		logSession.log(EventTypes.CERT_REVOKED, EventStatus.SUCCESS, ModuleTypes.CERTIFICATE, ServiceTypes.CORE, admin.toString(), Integer.valueOf(caid).toString(), null, null, details);            
        } catch (Exception e) {
            final String msg = INTRES.getLocalizedMessage("store.errorrevokeallbyca", issuerdn);
            log.info(msg);
            throw new EJBException(e);
        }
    }

    @Override
    public boolean checkIfAllRevoked(String username) {
        boolean returnval = true;
        Certificate certificate = null;
        // Strip dangerous chars
        username = StringTools.strip(username);
        Collection<Certificate> certs = findCertificatesByUsername(username);
        // Revoke all certs
        if (!certs.isEmpty()) {
            Iterator<Certificate> j = certs.iterator();
            while (j.hasNext()) {
                certificate = j.next();
                String fingerprint = CertTools.getFingerprintAsString(certificate);
                CertificateInfo info = getCertificateInfo(fingerprint);
                if (info != null && info.getStatus() != CertificateConstants.CERT_REVOKED) {
                    returnval = false;
                    break;
                }
            }
        }
        return returnval;
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
            Iterator<CertificateData> iter = coll.iterator();
            if (iter.hasNext()) {
                final CertificateData data = iter.next();
                final CertificateStatus result = getCertificateStatus(data);
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

    /**
     * Algorithm: if status is CERT_REVOKED the certificate is revoked and reason and date is picked up if status is CERT_ARCHIVED and reason is _NOT_
     * REMOVEFROMCRL or NOT_REVOKED the certificate is revoked and reason and date is picked up if status is CERT_ARCHIVED and reason is REMOVEFROMCRL
     * or NOT_REVOKED the certificate is NOT revoked if status is neither CERT_REVOKED or CERT_ARCHIVED the certificate is NOT revoked
     * 
     * @param data
     * @return CertificateStatus, can be compared (==) with CertificateStatus.OK, CertificateStatus.REVOKED and CertificateStatus.NOT_AVAILABLE
     */
    private CertificateStatus getCertificateStatus(CertificateData data) {
        if (data == null) {
            return CertificateStatus.NOT_AVAILABLE;
        }
        final int pId;
        {
            final Integer tmp = data.getCertificateProfileId();
            pId = tmp != null ? tmp.intValue() : CertificateProfileConstants.CERTPROFILE_NO_PROFILE;
        }
        final int status = data.getStatus();
        if (status == CertificateConstants.CERT_REVOKED) {
            return new CertificateStatus(data.getRevocationDate(), data.getRevocationReason(), pId);
        }
        if (status != CertificateConstants.CERT_ARCHIVED) {
            return new CertificateStatus(CertificateStatus.OK.toString(), pId);
        }
        // If the certificate have status ARCHIVED, BUT revocationReason is REMOVEFROMCRL or NOTREVOKED, the certificate is OK
        // Otherwise it is a revoked certificate that has been archived and we must return REVOKED
        final int revReason = data.getRevocationReason(); // Read revocationReason from database if we really need to..
        if (revReason == RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL || revReason == RevokedCertInfo.NOT_REVOKED) {
            return new CertificateStatus(CertificateStatus.OK.toString(), pId);
        }
        return new CertificateStatus(data.getRevocationDate(), revReason, pId);
    }

    @Override
    public List<Object[]> findExpirationInfo(Collection<String> cas, long activeNotifiedExpireDateMin, long activeNotifiedExpireDateMax,
            long activeExpireDateMin) {
        return CertificateData.findExpirationInfo(entityManager, cas, activeNotifiedExpireDateMin, activeNotifiedExpireDateMax,
                activeExpireDateMin);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean setStatus(AuthenticationToken admin, String fingerprint, int status) throws IllegalArgumentException, AuthorizationDeniedException {

    	if ( (status == CertificateConstants.CERT_REVOKED) || (status == CertificateConstants.CERT_ACTIVE) ) {
            final String msg = INTRES.getLocalizedMessage("store.errorsetstatusargument", fingerprint, status);
    		throw new IllegalArgumentException(msg);
    	}
    	CertificateData data = CertificateData.findByFingerprint(entityManager, fingerprint);
    	if (data != null) {
            if (log.isDebugEnabled()) {
                log.debug("Set status " + status + " for certificate with fp: " + fingerprint);
            }
            
            // Must be authorized to CA in order to change status is certificates issued by the CA
            String bcdn = CertTools.stringToBCDNString(data.getIssuerDN());
            int caid = bcdn.hashCode();
            authorizedToCA(admin, caid);

        	data.setStatus(status);
        	final String serialNo = CertTools.getSerialNumberAsString(data.getCertificate());
            final String msg = INTRES.getLocalizedMessage("store.setstatus", data.getUsername(), fingerprint, status, data.getSubjectDN(), data.getIssuerDN(), serialNo);
    		Map<String, Object> details = new LinkedHashMap<String, Object>();
    		details.put("msg", msg);
    		logSession.log(EventTypes.CERT_CHANGEDSTATUS, EventStatus.SUCCESS, ModuleTypes.CERTIFICATE, ServiceTypes.CORE, admin.toString(), Integer.valueOf(caid).toString(), serialNo, data.getUsername(), details);            
    	} else {
            if (log.isDebugEnabled()) {
                final String msg = INTRES.getLocalizedMessage("store.setstatusfailed", fingerprint, status);
                log.debug(msg);
            }    		
    	}
        return (data != null);
    }
    
    private void authorizedToCA(final AuthenticationToken admin, final int caid) throws AuthorizationDeniedException {
        if (!accessSession.isAuthorized(admin, StandardRules.CAACCESS.resource() + caid)) {
        	final String msg = INTRES.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caid);
            throw new AuthorizationDeniedException(msg);
        }
    }

}
