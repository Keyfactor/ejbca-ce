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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.crl.CRLData;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.CertTools;

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
    private AccessControlSessionLocal accessSession;
    @EJB
    private CertificateStoreSessionLocal certStore;
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;

    @Override
    public void removeCertificate(BigInteger serno) {
        if ( serno==null ) {
            return;
        }
        final Collection<CertificateData> coll = CertificateData.findBySerialNumber(this.entityManager, serno.toString());
        for (CertificateData certificateData : coll) {
            this.entityManager.remove(certificateData);
            final Base64CertData b64cert = Base64CertData.findByFingerprint(this.entityManager, certificateData.getFingerprint());
            if ( b64cert!=null ) {
                this.entityManager.remove(b64cert);
            }
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
    public List<Object[]> findExpirationInfo(Collection<String> cas, long activeNotifiedExpireDateMin, long activeNotifiedExpireDateMax,
            long activeExpireDateMin) {
        return certStore.findExpirationInfo(cas, new ArrayList<Integer>(), activeNotifiedExpireDateMin, activeNotifiedExpireDateMax,
                activeExpireDateMin);
    }

	@SuppressWarnings("unchecked")
	@Override
	public Collection<Certificate> findCertificatesByIssuer(String issuerDN) {
		if (null == issuerDN || issuerDN.length() <= 0) {
			return new ArrayList<Certificate>();
		}
		final Query query = this.entityManager.createQuery("SELECT a FROM CertificateData a WHERE a.issuerDN=:issuerDN");
		query.setParameter("issuerDN", issuerDN);
		return CertificateData.getCertificateList( query.getResultList(), this.entityManager );
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
    public boolean setStatus(AuthenticationToken admin, String fingerprint, int status) throws IllegalArgumentException, AuthorizationDeniedException {

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
            final String serialNo = CertTools.getSerialNumberAsString(data.getCertificate(this.entityManager));
            final String msg = INTRES.getLocalizedMessage("store.setstatus", data.getUsername(), fingerprint, status, data.getSubjectDN(), data.getIssuerDN(), serialNo);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            logSession.log(EventTypes.CERT_CHANGEDSTATUS, EventStatus.SUCCESS, ModuleTypes.CERTIFICATE, ServiceTypes.CORE, admin.toString(), String.valueOf(caid), serialNo, data.getUsername(), details);            
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
}
