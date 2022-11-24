/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.ocsp;

import java.util.List;
import java.util.stream.Collectors;

import javax.ejb.Asynchronous;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;
import javax.persistence.Query;

import org.apache.log4j.Logger;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.oscp.OcspResponseData;

/**
 * 
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "OcspDataSessionRemote") // Do we need remote interface?
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class OcspDataSessionBean implements OcspDataSessionLocal, OcspDataSessionRemote {

    private static final Logger log = Logger.getLogger(OcspDataSessionBean.class);

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @Override
    @Asynchronous
    public void storeOcspData(final OcspResponseData responseData) {
        log.trace(">persistOcspData");
        this.entityManager.persist(responseData);
        log.trace("<persistOcspData");
    }

    @Override
    public List<OcspResponseData> findOcspDataByCaId(final Integer caId) {
        log.trace(">findOcspDataByCaId");
        final TypedQuery<OcspResponseData> query = this.entityManager.createNamedQuery("findOcspDataByCaId", OcspResponseData.class);
        query.setParameter("caId", caId);
        final List<OcspResponseData> result = query.getResultList();
        if (log.isTraceEnabled()) {
            log.trace("findOcspDataByCaId(" + caId + ") yielded " + result.size() + " results.");
        }
        log.trace("<findOcspDataByCaId");
        return result;
    }

    @Override
    public List<OcspResponseData> findOcspDataBySerialNumber(final String serialNumber) {
        log.trace(">findOcspDataBySerialNumber");
        final TypedQuery<OcspResponseData> query = this.entityManager.createNamedQuery("findOcspDataBySerialNumber", OcspResponseData.class);
        query.setParameter("serialNumber", serialNumber);
        final List<OcspResponseData> result = query.getResultList();
        if (log.isTraceEnabled()) {
            log.trace("findOcspDataBySerialNumber(" + serialNumber + ") yielded " + result.size() + " results.");
        }
        log.trace("<findOcspDataBySerialNumber");
        return result;
    }

    @Override
    public OcspResponseData findOcspDataByCaIdSerialNumber(final Integer caId, final String serialNumber) {
        log.trace(">findOcspDataByCaIdSerialNumber");
        final OcspResponseData result = getOcspResponseDataByCaIdSerialNumber(caId, serialNumber);
        if (log.isTraceEnabled()) {
            log.trace("findOcspDataByCaIdSerialNumber(" + caId + ", " + serialNumber + ")");
        }
        log.trace("<findOcspDataByCaIdSerialNumber");
        return result;
    }

    @Override
    public OcspResponseData findOcspDataById(final String id) {
        log.trace(">findOcspDataById");
        final TypedQuery<OcspResponseData> query = this.entityManager.createNamedQuery("findOcspDataById", OcspResponseData.class);

        query.setParameter("id", id);
        query.setMaxResults(1);

        log.trace("<findOcspDataById");
        return query.getResultList().isEmpty() ? null : query.getResultList().get(0);
    }
    
    @Override
    public List<String> findExpiringOcpsData(final Integer caId, final long expirationDate, final int maxNumberOfResults, final int offset) {
        log.trace(">findExpiringOcpsData");

        final TypedQuery<OcspResponseData> query = this.entityManager.createNamedQuery(OcspResponseData.FIND_EXPIRING_OCPS_DATA_BY_CAID, OcspResponseData.class);
        query.setParameter("caId", caId);
        query.setParameter("expirationDate", expirationDate);
        query.setMaxResults(maxNumberOfResults);
        query.setFirstResult(offset);

        log.trace("<findExpiringOcpsData");

        return query.getResultList()
                           .stream()
                           .map(response -> response.getSerialNumber())
                           .collect(Collectors.toList());
    }
    
    @Override
    public void deleteOcspDataByCaId(final Integer caId) {
        log.trace(">deleteOcspDataByCaId");
        final Query query = this.entityManager.createNamedQuery("deleteOcspDataByCaId");
        query.setParameter("caId", caId);
        final int rowsDeleted = query.executeUpdate();
        if (log.isTraceEnabled()) {
            log.trace("deleteOcspDataByCaId(" + caId + ") yielded the " + rowsDeleted + " rows deleted! ");
        }
        log.trace("<deleteOcspDataByCaId");
    }

    @Override
    public void deleteOcspDataBySerialNumber(final String serialNumber) {
        log.trace(">deleteOcspDataBySerialNumber");
        final Query query = this.entityManager.createNamedQuery("deleteOcspDataBySerialNumber");
        query.setParameter("serialNumber", serialNumber);
        final int rowsDeleted = query.executeUpdate();
        if (log.isTraceEnabled()) {
            log.trace("deleteOcspDataBySerialNumber(" + serialNumber + ") yielded the " + rowsDeleted + " rows deleted! ");
        }
        log.trace("<deleteOcspDataBySerialNumber");
    }

    @Override
    public void deleteOcspDataByCaIdSerialNumber(final Integer caId, final String serialNumber) {
        log.trace(">deleteOcspDataByCaIdSerialNumber");
        final Query query = this.entityManager.createNamedQuery("deleteOcspDataByCaIdSerialNumber");
        query.setParameter("caId", caId);
        query.setParameter("serialNumber", serialNumber);
        final int rowsDeleted = query.executeUpdate();
        if (log.isTraceEnabled()) {
            log.trace("deleteOcspDataByCaIdSerialNumber(" + caId + ", " + serialNumber + ") yielded the " + rowsDeleted + " rows deleted! ");
        }
        log.trace("<deleteOcspDataByCaIdSerialNumber");
    }

    @Override
    public int deleteOldOcspDataByCaId(final Integer caId) {
        log.trace(">deleteOldOcspDataByCaId");

        final Query query = this.entityManager.createNamedQuery(OcspResponseData.DELETE_OLD_OCSP_DATA_BY_CAID);
        query.setParameter("caId", caId);
        query.setParameter("cutoffTime", getCleanupCutoffTime());

        final int rowsDeleted = query.executeUpdate();
        if (log.isTraceEnabled()) {
            log.trace("deleteOldOcspDataByCaId(" + caId + ") yielded the " + rowsDeleted + " rows deleted! ");
        }

        log.trace("<deleteOldOcspDataByCaId");
        return rowsDeleted;
    }

    @Override
    public int deleteOldOcspData() {
        log.trace(">deleteOldOcspData");

        final Query query = this.entityManager.createNamedQuery(OcspResponseData.DELETE_OLD_OCSP_DATA);
        query.setParameter("cutoffTime", getCleanupCutoffTime());

        final int rowsDeleted = query.executeUpdate();
        if (log.isTraceEnabled()) {
            log.trace("deleteOldOcspData() yielded the " + rowsDeleted + " rows deleted! ");
        }

        log.trace("<deleteOldOcspData");
        return rowsDeleted;
    }

    private OcspResponseData getOcspResponseDataByCaIdSerialNumber(final Integer caId, final String serialNumber) {
        final TypedQuery<OcspResponseData> query = this.entityManager.createNamedQuery("findOcspDataByCaIdSerialNumber", OcspResponseData.class);
        query.setParameter("caId", caId);
        query.setParameter("serialNumber", serialNumber);
        query.setMaxResults(1);
        return query.getResultList().isEmpty() ? null : query.getResultList().get(0);
    }

    /**
     * Cutoff time for old OCSP response data cleanup.
     *
     * @return the difference in milliseconds, between time at beginning of current second and midnight, January 1, 1970 UTC.
    */
    private long getCleanupCutoffTime() {
        long currentTimeMillis = System.currentTimeMillis();
        // OCSP response data is stored without millisecond values, therefore to avoid deletion of responses generated
        // after start of the cleanup job, we need to process records that were saved till beginning of current second.
        return currentTimeMillis - currentTimeMillis % 1000;
    }
}
