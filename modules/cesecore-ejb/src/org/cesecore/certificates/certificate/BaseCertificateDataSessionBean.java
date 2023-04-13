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
 */
public abstract class BaseCertificateDataSessionBean {

    private static final Logger log = Logger.getLogger(CertificateDataSessionBean.class);
    
    /** Returns the entity manager to use. */
    protected abstract EntityManager getEntityManager();
    
    protected Collection<RevokedCertInfo> getRevokedCertInfosInternal(final Query query, final boolean allowInvalidityDate) {
        final int maxResults = CesecoreConfiguration.getDatabaseRevokedCertInfoFetchSize();
        query.setMaxResults(maxResults);
        int firstResult = 0;
        final CompressedCollection<RevokedCertInfo> revokedCertInfos = new CompressedCollection<>(RevokedCertInfo.class);
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
                if (allowInvalidityDate) {
                    final Long invalidityDate = ValueExtractor.extractLongValue(current[5]) == -1L ? null : ValueExtractor.extractLongValue(current[5]);
                    revokedCertInfos.add(new RevokedCertInfo(fingerprint, serialNumber, revocationDate, revocationReason, expireDate, invalidityDate));
                } else {
                    revokedCertInfos.add(new RevokedCertInfo(fingerprint, serialNumber, revocationDate, revocationReason, expireDate));
                }
            }
            firstResult += maxResults;
        }
        revokedCertInfos.closeForWrite();
        return revokedCertInfos;
    }
    
}
