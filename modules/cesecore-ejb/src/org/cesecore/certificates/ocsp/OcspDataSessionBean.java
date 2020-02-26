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

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.oscp.OcspResponseData;
import org.cesecore.oscp.ResponsePK;

/**
 * 
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "OcspDataSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class OcspDataSessionBean implements OcspDataSessionLocal, OcspDataSessionRemote {

    private static final Logger log = Logger.getLogger(OcspDataSessionBean.class);

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void storeOcspData(final OcspResponseData responseData) {
        log.trace(">persistOcspData");
        this.entityManager.persist(responseData);
        log.trace("<persistOcspData");
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public OcspResponseData fetchOcspData(final ResponsePK key) {
        log.trace(">fetchOcspData");
        final OcspResponseData ocspResponseData = this.entityManager.find(OcspResponseData.class, key);
        log.trace("<fetchOcspData");
        return ocspResponseData != null ? ocspResponseData : null;
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public byte[] fetchOcspResponse(ResponsePK key) {
        log.trace(">fetchOcspResponse");
        final OcspResponseData ocspResponseData = this.entityManager.find(OcspResponseData.class, key);
        log.trace("<fetchOcspResponse");
        return ocspResponseData != null ? ocspResponseData.getOcspResponse() : null;
    }
    
}
