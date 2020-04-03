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
package org.cesecore.certificates.ocsp;

import java.util.ArrayList;
import java.util.List;

import javax.ejb.Asynchronous;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

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
    public List<String> findExpiringOcpsData(final Integer caId, final long expirationDate, final int maxNumberOfResults, final int offset) {
        log.trace(">findExpiringOcpsData");
        final TypedQuery<Object[]> query = entityManager
                .createQuery("SELECT a.serialNumber, MAX(a.nextUpdate) FROM OcspResponseData a WHERE a.caId=:caId GROUP BY a.serialNumber", Object[].class);
        query.setParameter("caId", caId);
        query.setMaxResults(maxNumberOfResults);
        query.setFirstResult(offset);
        final List<String> distinctSerialNumbers = new ArrayList<>();
        for (Object[] result : query.getResultList()) {
            if ((long)result[1] <= expirationDate) {
                distinctSerialNumbers.add((String) result[0]);
            }
        }
        log.trace("<findExpiringOcpsData");
        return distinctSerialNumbers;
    }
    
    @Override
    public void deleteOcspDataByCaId(final Integer caId) {
        log.trace(">deleteOcspDataByCaId");
        final TypedQuery<OcspResponseData> query = this.entityManager.createNamedQuery("deleteOcspDataByCaId", OcspResponseData.class);
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
        final TypedQuery<OcspResponseData> query = this.entityManager.createNamedQuery("deleteOcspDataBySerialNumber", OcspResponseData.class);
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
        final TypedQuery<OcspResponseData> query = this.entityManager.createQuery("deleteOcspDataByCaIdSerialNumber", OcspResponseData.class);
        query.setParameter("caId", caId);
        query.setParameter("serialNumber", serialNumber);
        final int rowsDeleted = query.executeUpdate();
        if (log.isTraceEnabled()) {
            log.trace("deleteOcspDataByCaIdSerialNumber(" + caId + ", " + serialNumber + ") yielded the " + rowsDeleted + " rows deleted! ");
        }
        log.trace("<deleteOcspDataByCaIdSerialNumber");
    }

    private OcspResponseData getOcspResponseDataByCaIdSerialNumber(final Integer caId, final String serialNumber) {
        final TypedQuery<OcspResponseData> query = this.entityManager.createNamedQuery("findOcspDataByCaIdSerialNumber", OcspResponseData.class);
        long now = System.currentTimeMillis();
        query.setParameter("caId", caId);
        query.setParameter("serialNumber", serialNumber);
        query.setParameter("currentTime", now);
        query.setMaxResults(1);
        return query.getResultList().get(0);
    }

}
