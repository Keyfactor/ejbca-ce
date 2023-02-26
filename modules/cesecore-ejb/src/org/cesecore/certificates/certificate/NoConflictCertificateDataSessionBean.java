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

import java.util.Collection;
import java.util.List;
import java.util.TimeZone;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import javax.persistence.TypedQuery;

import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.util.ValidityDate;

/**
 * Low level CRUD functions to access NoConflictCertificateData 
 */
@Stateless // Local only bean, no remote interface
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class NoConflictCertificateDataSessionBean extends BaseCertificateDataSessionBean implements NoConflictCertificateDataSessionLocal {

    private final static Logger log = Logger.getLogger(NoConflictCertificateDataSessionBean.class);

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;
    
    @Override
    protected EntityManager getEntityManager() {
        return entityManager;
    }
    
    //
    // Search functions.
    //
    @Override
    public List<NoConflictCertificateData> findByFingerprint(final String fingerprint) {
        final TypedQuery<NoConflictCertificateData> query = entityManager.createQuery("SELECT a FROM NoConflictCertificateData a WHERE a.fingerprint=:fingerprint", NoConflictCertificateData.class);
        query.setParameter("fingerprint", fingerprint);
        final List<NoConflictCertificateData> result = query.getResultList();
        if (log.isTraceEnabled()) {
            log.trace("findByFingerprint(" + fingerprint + ") yielded " + result.size() + " results.");
        }
        return result;
    }
    
    @Override
    public List<NoConflictCertificateData> findBySerialNumber(final String serialNumber) {
        final TypedQuery<NoConflictCertificateData> query = entityManager.createQuery("SELECT a FROM NoConflictCertificateData a WHERE a.serialNumber=:serialNumber", NoConflictCertificateData.class);
        query.setParameter("serialNumber", serialNumber);
        final List<NoConflictCertificateData> result = query.getResultList();
        if (log.isTraceEnabled()) {
            log.trace("findBySerialNumber(" + serialNumber + ") yielded " + result.size() + " results.");
        }
        return result;
    }
    
    @Override
    public List<NoConflictCertificateData> findByIssuerDNSerialNumber(final String issuerDN, final String serialNumber) {
        final String sql = "SELECT a FROM NoConflictCertificateData a WHERE a.issuerDN=:issuerDN AND a.serialNumber=:serialNumber";
        final TypedQuery<NoConflictCertificateData> query = entityManager.createQuery(sql, NoConflictCertificateData.class);
        query.setParameter("issuerDN", issuerDN);
        query.setParameter("serialNumber", serialNumber);
        final List<NoConflictCertificateData> result = query.getResultList();
        if (log.isTraceEnabled()) {
            log.trace("findByIssuerDNSerialNumber(" + issuerDN + ", " + serialNumber + ") yielded " + result.size() + " results.");
        }
        return result;
    }
    
    @Override
    public Collection<RevokedCertInfo> getRevokedCertInfosWithDuplicates(final String issuerDN, final boolean deltaCrl, final int crlPartitionIndex, final long lastBaseCrlDate, 
            final boolean keepExpiredCertsOnCrl, final boolean allowInvalidityDate) {
        if (log.isDebugEnabled()) {
            log.debug("Querying for revoked certificates in append-only table. IssuerDN: '" + issuerDN + "'" +
                    ", Delta CRL: " + deltaCrl +
                    ", Last Base CRL Date: " +  FastDateFormat.getInstance(ValidityDate.ISO8601_DATE_FORMAT, TimeZone.getTimeZone("GMT")).format(lastBaseCrlDate) +
                    ", Keep expired certificates on CRL: " + keepExpiredCertsOnCrl);
        }
        final String crlPartitionExpression;
        final String excludeExpiredExpression;
        final String ordering;
        final Query query;
        if (crlPartitionIndex != 0) {
            crlPartitionExpression = " AND crlPartitionIndex = :crlPartitionIndex";
        } else {
            crlPartitionExpression = " AND (crlPartitionIndex = :crlPartitionIndex OR crlPartitionIndex IS NULL)";
        }
        if (keepExpiredCertsOnCrl) {
            excludeExpiredExpression = "";
        } else {
            excludeExpiredExpression = " AND a.expireDate >= :expiredAfter";
        }
        if (CesecoreConfiguration.getDatabaseRevokedCertInfoFetchOrdered()) {
            ordering = " ORDER BY revocationDate, fingerprint ASC";
        } else {
            ordering = "";
        }
        /*if (allowInvalidityDate && deltaCrl) {
            // Delta CRL with invalidity date
            query = getEntityManager().createNativeQuery(
                    "SELECT a.fingerprint as fingerprint, a.serialNumber as serialNumber, a.expireDate as expireDate, a.revocationDate as revocationDate, a.revocationReason as revocationReason, a.invalidityDate as invalidityDate FROM NoConflictCertificateData a WHERE "
                            + "a.issuerDN=:issuerDN AND a.revocationDate>:revocationDate AND a.updateTime>:lastBaseCrlDate AND (a.status=:status1 OR a.status=:status2 OR a.status=:status3)"
                            + crlPartitionExpression + ordering,
                    "RevokedCertInfoSubset");
            query.setParameter("lastBaseCrlDate", lastBaseCrlDate);   
            query.setParameter("revocationDate", -1L);
        }
        else if (deltaCrl) {*/
        if (deltaCrl) {
            // Delta CRL
            query = getEntityManager().createNativeQuery(
                    "SELECT a.fingerprint as fingerprint, a.serialNumber as serialNumber, a.expireDate as expireDate, a.revocationDate as revocationDate, a.revocationReason as revocationReason, a.invalidityDate as invalidityDate FROM NoConflictCertificateData a WHERE "
                            + "a.issuerDN=:issuerDN AND a.revocationDate>:revocationDate AND (a.status=:status1 OR a.status=:status2 OR a.status=:status3)"
                            + crlPartitionExpression + ordering,
                    "RevokedCertInfoSubset");
            query.setParameter("revocationDate", lastBaseCrlDate);
        } else {
            // Base CRL
            query = getEntityManager().createNativeQuery(
                    "SELECT a.fingerprint as fingerprint, a.serialNumber as serialNumber, a.expireDate as expireDate, a.revocationDate as revocationDate, a.revocationReason as revocationReason, a.invalidityDate as invalidityDate FROM NoConflictCertificateData a WHERE "
                            + "a.issuerDN=:issuerDN AND (a.status=:status1 OR a.status=:status2 OR a.status=:status3)"
                            + crlPartitionExpression + excludeExpiredExpression + ordering,
                    "RevokedCertInfoSubset");
            if (!keepExpiredCertsOnCrl) {
                query.setParameter("expiredAfter", lastBaseCrlDate);
            }
        }
        query.setParameter("issuerDN", issuerDN);
        query.setParameter("crlPartitionIndex", crlPartitionIndex);
        query.setParameter("status1", CertificateConstants.CERT_REVOKED);
        query.setParameter("status2", CertificateConstants.CERT_ACTIVE); // in case the certificate has been changed from on hold, we need to include it as "removeFromCRL" in the Delta CRL
        query.setParameter("status3", CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION); // could happen if a cert is re-activated just before expiration
        return getRevokedCertInfosInternal(query, allowInvalidityDate);
    }
    
}
