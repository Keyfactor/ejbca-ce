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
import javax.persistence.TypedQuery;

import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.util.ValidityDate;

/**
 * Low level CRUD functions to access NoConflictCertificateData 
 *  
 * @version $Id$
 */
@Stateless // Local only bean, no remote interface
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class NoConflictCertificateDataSessionBean extends BaseCertificateDataSessionBean implements NoConflictCertificateDataSessionLocal {

    private final static Logger log = Logger.getLogger(NoConflictCertificateDataSessionBean.class);

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;
    
    @Override
    protected String getTableName() {
        return "NoConflictCertificateData";
    }
    
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
    public Collection<RevokedCertInfo> getRevokedCertInfosWithDuplicates(final String issuerDN, final int crlPartitionIndex, final long lastbasecrldate) {
        if (log.isDebugEnabled()) {
            log.debug("Quering for revoked certificates in append-only table. IssuerDN: '" + issuerDN + "', Last Base CRL Date: " +  FastDateFormat.getInstance(ValidityDate.ISO8601_DATE_FORMAT, TimeZone.getTimeZone("GMT")).format(lastbasecrldate));
        }
        return getRevokedCertInfosInternal(issuerDN, crlPartitionIndex, lastbasecrldate, true);
    }
    
}
