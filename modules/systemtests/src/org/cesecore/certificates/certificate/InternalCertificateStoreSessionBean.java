/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.crl.CRLData;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.CertTools;
import org.ejbca.util.DatabaseIndexUtil;
import org.ejbca.util.DatabaseIndexUtil.DatabaseIndex;
import org.ejbca.util.JDBCUtil;

/**
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "InternalCertificateStoreSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class InternalCertificateStoreSessionBean implements InternalCertificateStoreSessionRemote {

    /** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();
    private static final Logger log = Logger.getLogger(InternalCertificateStoreSessionBean.class);

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CertificateDataSessionLocal certificateDataSession;
    @EJB
    private CertificateStoreSessionLocal certStore;
    @EJB
    private NoConflictCertificateDataSessionLocal noConflictCertificateDataSession;
    @EJB
    private NoConflictCertificateStoreSessionLocal noConflictCertificateStoreSession;
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;
    @EJB
    private IncompleteIssuanceJournalDataSessionLocal incompleteIssuanceJournalDataSession;

    @Override
    public void removeCertificate(BigInteger serno) {
        if ( serno==null ) {
            return;
        }
        final Collection<CertificateData> coll = certificateDataSession.findBySerialNumber(serno.toString());
        for (CertificateData certificateData : coll) {
            this.entityManager.remove(certificateData);
            final Base64CertData b64cert = Base64CertData.findByFingerprint(this.entityManager, certificateData.getFingerprint());
            if ( b64cert!=null ) {
                this.entityManager.remove(b64cert);
            }
        }
        
        final Collection<NoConflictCertificateData> noConflictCertDatas = noConflictCertificateDataSession.findBySerialNumber(serno.toString());
        for (final NoConflictCertificateData certificateData : noConflictCertDatas) {
            this.entityManager.remove(certificateData);
        }
    }

    private int deleteRow(final String tableName, final String fingerPrint) {
        // This is done as a native query because we do not want to be depending on rowProtection validating
        // correctly, since publisher tests inserts directly in the database with null rowProtection.
        // NOTE: the below native query uses direct String insertion instead of a parameterized query. 
        // This is because in PostgreSQL we otherwise bet an error "ERROR: operator does not exist: text = bytea".
        // Do NOT use SQL like below in production code (this is only test code), since it is vulnerable to SQL injection.
        final Query query = this.entityManager.createNativeQuery("DELETE from "+tableName+" where fingerprint='"+fingerPrint+"'");
        return query.executeUpdate();
    }

    @Override
    public int removeCertificate(String fingerPrint) {
        deleteRow("CertificateData", fingerPrint);
        return deleteRow("Base64CertData", fingerPrint);
    }

    @Override
    public int removeCertificate(Certificate certificate) {
        if ( certificate==null ) {
            return 0;
        }
        final String fingerprint = CertTools.getFingerprintAsString(certificate);
        return removeCertificate(fingerprint);
    }

    @Override
    public void removeCertificatesBySubject(final String subjectDN) {
        Collection<Certificate> certs = certStore.findCertificatesBySubject(subjectDN);
        for (Certificate certificate : certs) {
            removeCertificate(certificate);
        }
    }
    
    @Override
    public void removeCertificatesByUsername(final String username) {
        Query query = entityManager.createQuery("DELETE FROM CertificateData a WHERE a.username=:username");
        query.setParameter("username", username);
        query.executeUpdate();
        query = entityManager.createQuery("DELETE FROM NoConflictCertificateData a WHERE a.username=:username");
        query.setParameter("username", username);
        query.executeUpdate();
    }
    
    @Override
    public void removeLimitedCertificatesByIssuer(final String issuerDN) {
        Query query = entityManager.createQuery("DELETE FROM CertificateData a WHERE a.issuerDN=:issuerDN AND a.subjectDN=:subjectDN");
        query.setParameter("issuerDN", issuerDN);
        query.setParameter("subjectDN", "CN=limited");
        query.executeUpdate();
        query = entityManager.createQuery("DELETE FROM NoConflictCertificateData a WHERE a.issuerDN=:issuerDN AND a.subjectDN=:subjectDN");
        query.setParameter("issuerDN", issuerDN);
        query.setParameter("subjectDN", "CN=limited");
        query.executeUpdate();
    }

    @Override
    public void removeCertificatesByIssuer(String issuerDN) {
        Query query = entityManager.createQuery("DELETE FROM CertificateData a WHERE a.issuerDN=:issuerDN ");
        query.setParameter("issuerDN", issuerDN);
        query.executeUpdate();
        query = entityManager.createQuery("DELETE FROM NoConflictCertificateData a WHERE a.issuerDN=:issuerDN ");
        query.setParameter("issuerDN", issuerDN);
        query.executeUpdate();
    }

    @Override
    public void removeFromIncompleteIssuanceJournal(final int caId, final BigInteger serialNumber) {
        if (log.isDebugEnabled()) {
            log.debug("Cleaning up journal data after test. An \"unexpectedly disappeared\" message is fine.");
        }
        incompleteIssuanceJournalDataSession.removeFromJournal(caId, serialNumber);
    }

    @Override
    public boolean presentInIncompleteIssuanceJournal(final int caId, final BigInteger serialNumber) {
        return incompleteIssuanceJournalDataSession.presentInJournal(caId, serialNumber);
    }

    @Override
    public List<Object[]> findExpirationInfo(Collection<String> cas, long activeNotifiedExpireDateMin, long activeNotifiedExpireDateMax,
            long activeExpireDateMin) {
        return certStore.findExpirationInfo(cas, new ArrayList<Integer>(), activeNotifiedExpireDateMin, activeNotifiedExpireDateMax,
                activeExpireDateMin);
    }

	@SuppressWarnings("unchecked")
	@Override
	public Collection<Certificate> findCertificatesByIssuer(String issuerDN) {
		if (null == issuerDN || issuerDN.length() <= 0) {
			return new ArrayList<>();
		}
		final Query query = this.entityManager.createQuery("SELECT a FROM CertificateData a WHERE a.issuerDN=:issuerDN");
		query.setParameter("issuerDN", issuerDN);
		return certificateDataSession.getCertificateList(query.getResultList());
	}

	@Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeCRL(final AuthenticationToken admin, final String fingerprint) throws AuthorizationDeniedException {
        final CRLData crld = CRLData.findByFingerprint(entityManager, fingerprint);
        if (crld == null) {
            if (log.isDebugEnabled()) {
                log.debug("Trying to remove a CRL that does not exist: " + fingerprint);
            }
        } else {
            entityManager.remove(crld);
        }
    }
	
	@Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeCRLs(final AuthenticationToken admin, final String issuerDN) throws AuthorizationDeniedException {
        List<CRLData> crls = CRLData.findByIssuerDN(entityManager, issuerDN);
        for(CRLData crl : crls){
            entityManager.remove(crl);
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean setStatus(AuthenticationToken admin, String fingerprint, int status) throws IllegalArgumentException, AuthorizationDeniedException {
        CertificateData data = certificateDataSession.findByFingerprint(fingerprint);
        if (data != null) {
            if (log.isDebugEnabled()) {
                log.debug("Set status " + status + " for certificate with fp: " + fingerprint);
            }
            
            // Must be authorized to CA in order to change status is certificates issued by the CA
            String bcdn = CertTools.stringToBCDNString(data.getIssuerDN());
            int caid = bcdn.hashCode();
            authorizedToCA(admin, caid);

            data.setStatus(status);
            final String serialNo = CertTools.getSerialNumberAsString(data.getCertificate(this.entityManager));
            final String msg = INTRES.getLocalizedMessage("store.setstatus", data.getUsername(), fingerprint, status, data.getSubjectDnNeverNull(), data.getIssuerDN(), serialNo);
            logSession.log(EventTypes.CERT_CHANGEDSTATUS, EventStatus.SUCCESS, ModuleTypes.CERTIFICATE, ServiceTypes.CORE, admin.toString(), String.valueOf(caid), serialNo, data.getUsername(), msg);
        } else {
            if (log.isDebugEnabled()) {
                final String msg = INTRES.getLocalizedMessage("store.setstatusfailed", fingerprint, status);
                log.debug(msg);
            }           
        }
        return (data != null);
    }
    
    private void authorizedToCA(final AuthenticationToken admin, final int caid) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(admin, StandardRules.CAACCESS.resource() + caid)) {
            final String msg = INTRES.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caid);
            throw new AuthorizationDeniedException(msg);
        }
    }

    @Override
    public void setUniqueSernoIndexTrue() {
        log.info("Setting unique serno check to TRUE, i.e. force EJBCA to believe we have a unique issuerDN/SerialNo index in the database");
        certStore.setUniqueCertificateSerialNumberIndex(Boolean.TRUE);
    }

    @Override
    public void setUniqueSernoIndexFalse() {
        log.info("Setting unique serno check to FALSE, i.e. force EJBCA to believe we have a unique issuerDN/SerialNo index in the database");
        certStore.setUniqueCertificateSerialNumberIndex(Boolean.FALSE);
    }

    @Override
    public boolean existsUniqueSernoIndex() {
        certStore.resetUniqueCertificateSerialNumberIndex();        
        return certStore.isUniqueCertificateSerialNumberIndex();
    }

    @Override
    public void resetUniqueSernoCheck() {
        log.info("Resetting unique serno check");
        certStore.resetUniqueCertificateSerialNumberIndex();        
    }

    @Override
    public void reloadCaCertificateCache() {
        certStore.reloadCaCertificateCache();
    }

    @Override
    public void updateLimitedCertificateDataStatus(AuthenticationToken admin, int caId, String issuerDn, BigInteger serialNumber,
            Date revocationDate, int reasonCode, String caFingerprint) throws AuthorizationDeniedException {
        certStore.updateLimitedCertificateDataStatus(admin, caId, issuerDn, serialNumber, revocationDate, reasonCode, caFingerprint);
    }
    
    @Override
    public void updateLimitedCertificateDataStatus(AuthenticationToken admin, int caId, String issuerDn, String subjectDn, String username, BigInteger serialNumber,
            int status, Date revocationDate, int reasonCode, String caFingerprint) throws AuthorizationDeniedException {
        certStore.updateLimitedCertificateDataStatus(admin, caId, issuerDn, subjectDn, username, serialNumber, status, revocationDate, reasonCode, caFingerprint);
    }

    @Override
    public CertificateDataWrapper storeCertificateNoAuth(AuthenticationToken adminForLogging, Certificate incert, String username, String cafp, int status, int type,
            int certificateProfileId, final int endEntityProfileId, final int crlPartitionIndex, String tag, long updateTime) {
        return certStore.storeCertificateNoAuth(adminForLogging, incert, username, cafp, null, status, type, certificateProfileId, endEntityProfileId, 
                crlPartitionIndex, tag, updateTime, null);
    }

    @Override
    public CertificateData getCertificateData(final String fingerprint) {
        final Query query = this.entityManager.createQuery("SELECT a FROM CertificateData a WHERE a.fingerprint=:fingerprint");
        query.setParameter("fingerprint", fingerprint);
        @SuppressWarnings("unchecked")
        final List<CertificateData> results = query.getResultList();
        if (results.size()!=1) {
            return null;
        }
        return results.get(0);
    }

    @Override
    public Base64CertData getBase64CertData(final String fingerprint) {
        final Query query = this.entityManager.createQuery("SELECT a FROM Base64CertData a WHERE a.fingerprint=:fingerprint");
        query.setParameter("fingerprint", fingerprint);
        @SuppressWarnings("unchecked")
        final List<Base64CertData> results = query.getResultList();
        if (results.size()!=1) {
            return null;
        }
        return results.get(0);
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean setRevokeStatus(AuthenticationToken admin, String issuerdn, BigInteger serno, Date revokedDate, int reason) throws CertificateRevokeException, AuthorizationDeniedException {
        // authorization is handled by setRevokeStatus(admin, certificate, reason, userDataDN);
        final CertificateDataWrapper cdw = certStore.getCertificateDataByIssuerAndSerno(issuerdn, serno);
        if (cdw == null) {
            String msg = INTRES.getLocalizedMessage("store.errorfindcertserno", null, serno);
            log.info(msg);
            throw new CertificateRevokeException(msg);
        }
        return certStore.setRevokeStatus(admin, cdw, revokedDate, reason);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean setRevokeStatus(AuthenticationToken admin, Certificate certificate, Date revokedDate, int reason) throws CertificateRevokeException, AuthorizationDeniedException {
        // Must be authorized to CA in order to change status is certificates issued by the CA
        if (certificate == null) {
            throw new IllegalArgumentException("Passed certificate may not be null.");
        }
        final int caid = CertTools.getIssuerDN(certificate).hashCode();
        authorizedToCA(admin, caid);
        final String fingerprint = CertTools.getFingerprintAsString(certificate);
        final CertificateData certificateData = certificateDataSession.findByFingerprint(fingerprint);
        final CertificateDataWrapper cdw;
        if (certificateData == null) {
            final String issuerDN = CertTools.getIssuerDN(certificate);
            if (noConflictCertificateStoreSession.canRevokeNonExisting(issuerDN)) {
                if (log.isDebugEnabled()) {
                    log.debug("Setting revoke status of non-existing certificate.");
                }
                cdw = noConflictCertificateStoreSession.getCertificateDataByIssuerAndSerno(issuerDN, CertTools.getSerialNumber(certificate));
            } else {
                final String serialNumber = CertTools.getSerialNumberAsString(certificate);
                String msg = INTRES.getLocalizedMessage("store.errorfindcertfp", fingerprint, serialNumber);
                log.info(msg);
                throw new CertificateRevokeException(msg);
            }
        } else {
            cdw = new CertificateDataWrapper(certificateData, null);
        }
        return noConflictCertificateStoreSession.setRevokeStatus(admin, cdw, revokedDate, reason);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public List<DatabaseIndex> getDatabaseIndexFromTable(final String tableName, final boolean requireUnique) {
        try {
            return DatabaseIndexUtil.getDatabaseIndexFromTable(JDBCUtil.getDataSourceOrNull(), tableName, requireUnique);
        } catch (SQLException e) {
            log.info("getDatabaseIndexFromTable failed: " + e.getMessage());
            log.debug("getDatabaseIndexFromTable failed: " + e.getMessage(), e);
            return null;
        }
    }
}
