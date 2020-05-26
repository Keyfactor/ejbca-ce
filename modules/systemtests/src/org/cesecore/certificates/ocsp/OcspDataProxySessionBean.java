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
package org.cesecore.certificates.ocsp;

import javax.ejb.Asynchronous;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.cesecore.jndi.JndiConstants;
import org.cesecore.oscp.OcspResponseData;
import org.ejbca.core.ejb.ocsp.OcspDataSessionLocal;

/**
 * Provide access to EntityManager, and OcspDataSessionLocal methods for convenient call
 * with EjbRemoteHelper in Ocsp related system tests.
 *
 * See OcspDataSessionBeanTest.java
 *
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "OcspDataProxySessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class OcspDataProxySessionBean implements OcspDataProxySessionRemote {

    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    @EJB
    private OcspDataSessionLocal ocspDataSessionLocal;

    @Override
    @Asynchronous
    public void storeOcspData(OcspResponseData responseData) {
        ocspDataSessionLocal.storeOcspData(responseData);
    }

    @Override
    public void deleteOcspDataByCaId(final Integer caId) {
        ocspDataSessionLocal.deleteOcspDataByCaId(caId);
    }

    @Override
    public void deleteOcspDataBySerialNumber(final String serialNumber) {
        ocspDataSessionLocal.deleteOcspDataBySerialNumber(serialNumber);
    }

    @Override
    public void deleteOcspDataByCaIdSerialNumber(final Integer caId, final String serialNumber) {
        ocspDataSessionLocal.deleteOcspDataByCaIdSerialNumber(caId, serialNumber);
    }

    @Override
    public int deleteOldOcspDataByCaId(final Integer caId) {
        return ocspDataSessionLocal.deleteOldOcspDataByCaId(caId);
    }

    @Override
    public int deleteOldOcspData() {
        return ocspDataSessionLocal.deleteOldOcspData();
    }
}
