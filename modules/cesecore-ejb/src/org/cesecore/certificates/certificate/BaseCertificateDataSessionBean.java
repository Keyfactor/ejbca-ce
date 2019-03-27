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
import java.util.Collection;
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.Query;

import org.apache.log4j.Logger;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.util.CompressedCollection;
import org.cesecore.util.ValueExtractor;

/**
 * Contains common function for CertificateDataSessionBean and NoConflictCertificateDataSessionBean.
 * 
 * @version $Id$
 */
public abstract class BaseCertificateDataSessionBean {

    private static final Logger log = Logger.getLogger(CertificateDataSessionBean.class);
    
    /** Returns the name of the table in the database. Either "CertificateData" or "NoConflictCertificateData" */
    protected abstract String getTableName();
    
    /** Returns the entity manager to use. */
    protected abstract EntityManager getEntityManager();
    
    /**
     * Returns a list with information about revoked certificates. Depending on the table, the result can
     * either contain at most one entry per certificate, or it may contain duplicates.
     */
    protected Collection<RevokedCertInfo> getRevokedCertInfosInternal(final String issuerDN, final int crlPartitionIndex, final long lastbasecrldate, final boolean forceGetAll) {
        final String tableName = getTableName();
        final String crlPartitionExpression;
        final Query query;
        if (crlPartitionIndex != 0) {
            crlPartitionExpression = " AND crlPartitionIndex = :crlPartitionIndex";
        } else {
            crlPartitionExpression = " AND (crlPartitionIndex = :crlPartitionIndex OR crlPartitionIndex IS NULL)";
        }
        if (lastbasecrldate > 0) {
            // Delta CRL
            query = getEntityManager().createNativeQuery(
                    "SELECT a.fingerprint as fingerprint, a.serialNumber as serialNumber, a.expireDate as expireDate, a.revocationDate as revocationDate, a.revocationReason as revocationReason FROM " + tableName + " a WHERE "
                            + "a.issuerDN=:issuerDN AND a.revocationDate>:revocationDate AND (a.status=:status1 OR a.status=:status2 OR a.status=:status3)" + crlPartitionExpression,
                    "RevokedCertInfoSubset");
            query.setParameter("revocationDate", lastbasecrldate);
            query.setParameter("status1", CertificateConstants.CERT_REVOKED);
            query.setParameter("status2", CertificateConstants.CERT_ACTIVE); // in case the certificate has been changed from on hold, we need to include it as "removeFromCRL" in the Delta CRL
            query.setParameter("status3", CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION); // could happen if a cert is re-activated just before expiration
        } else if (forceGetAll) {
            // Base CRL
            query = getEntityManager().createNativeQuery(
                    "SELECT a.fingerprint as fingerprint, a.serialNumber as serialNumber, a.expireDate as expireDate, a.revocationDate as revocationDate, a.revocationReason as revocationReason FROM " + tableName + " a WHERE "
                            + "a.issuerDN=:issuerDN AND (a.status=:status1 OR a.status=:status2 OR a.status=:status3)" + crlPartitionExpression,
                    "RevokedCertInfoSubset");
            query.setParameter("status1", CertificateConstants.CERT_REVOKED);
            query.setParameter("status2", CertificateConstants.CERT_ACTIVE); // in case the certificate has been changed from on hold, we need to include it as "removeFromCRL" in the Delta CRL
            query.setParameter("status3", CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION); // could happen if a cert is re-activated just before expiration
        } else {
            // Base CRL
            query = getEntityManager().createNativeQuery(
                    "SELECT a.fingerprint as fingerprint, a.serialNumber as serialNumber, a.expireDate as expireDate, a.revocationDate as revocationDate, a.revocationReason as revocationReason FROM " + tableName + " a WHERE "
                            + "a.issuerDN=:issuerDN AND a.status=:status" + crlPartitionExpression,
                    "RevokedCertInfoSubset");
            query.setParameter("status", CertificateConstants.CERT_REVOKED);
        }
        query.setParameter("issuerDN", issuerDN);
        query.setParameter("crlPartitionIndex", crlPartitionIndex);
        return getRevokedCertInfosInternal(query);
    }
    
    private Collection<RevokedCertInfo> getRevokedCertInfosInternal(final Query query) {
        final int maxResults = CesecoreConfiguration.getDatabaseRevokedCertInfoFetchSize();
        query.setMaxResults(maxResults);
        int firstResult = 0;
        final CompressedCollection<RevokedCertInfo> revokedCertInfos = new CompressedCollection<>();
        while (true) {
            query.setFirstResult(firstResult);
            @SuppressWarnings("unchecked")
            final List<Object[]> incompleteCertificateDatas = query.getResultList();
            if (incompleteCertificateDatas.size()==0) {
                break;
            }
            if (log.isDebugEnabled()) {
                log.debug("Read batch of " + incompleteCertificateDatas.size() + " RevokedCertInfo.");
            }
            for (final Object[] current : incompleteCertificateDatas) {
                // The order of the results are defined by the SqlResultSetMapping annotation
                final byte[] fingerprint = ((String)current[0]).getBytes();
                final byte[] serialNumber = new BigInteger((String)current[1]).toByteArray();
                final long expireDate = ValueExtractor.extractLongValue(current[2]);
                final long revocationDate = ValueExtractor.extractLongValue(current[3]);
                int revocationReason = ValueExtractor.extractIntValue(current[4]);
                if (revocationReason == -1) {
                    revocationReason = RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL;
                }
                revokedCertInfos.add(new RevokedCertInfo(fingerprint, serialNumber, revocationDate, revocationReason, expireDate));
            }
            firstResult += maxResults;
        }
        revokedCertInfos.closeForWrite();
        return revokedCertInfos;
    }
    
}
