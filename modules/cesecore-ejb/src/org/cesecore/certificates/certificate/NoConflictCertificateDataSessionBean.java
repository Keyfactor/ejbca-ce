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

import java.util.List;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

import org.apache.log4j.Logger;
import org.cesecore.config.CesecoreConfiguration;

/**
 * Low level CRUD functions to access NoConflictCertificateData 
 *  
 * @version $Id$
 */
@Stateless //(mappedName = JndiConstants.APP_JNDI_PREFIX + "NoConfliictCertificateDataSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class NoConflictCertificateDataSessionBean extends BaseCertificateDataSessionBean implements NoConflictCertificateDataSessionLocal {

//    private final static Logger log = Logger.getLogger(NoConflictCertificateDataSessionBean.class);

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;
    
    //
    // Search functions.
    //
    @Override
    public List<NoConflictCertificateData> findByFingerprint(final String fingerprint) {
        final TypedQuery<NoConflictCertificateData> query = entityManager.createQuery("SELECT a FROM NoConflictCertificateData a WHERE a.fingerprint=:fingerprint", NoConflictCertificateData.class);
        query.setParameter("fingerprint", fingerprint);
        return query.getResultList();
    }
    
    @Override
    public List<NoConflictCertificateData> findBySerialNumber(final String serialNumber) {
        final TypedQuery<NoConflictCertificateData> query = entityManager.createQuery("SELECT a FROM NoConflictCertificateData a WHERE a.serialNumber=:serialNumber", NoConflictCertificateData.class);
        query.setParameter("serialNumber", serialNumber);
        return query.getResultList();
    }
    
    @Override
    public List<NoConflictCertificateData> findByIssuerDNSerialNumber(final String issuerDN, final String serialNumber) {
        final String sql = "SELECT a FROM NoConflictCertificateData a WHERE a.issuerDN=:issuerDN AND a.serialNumber=:serialNumber";
        final TypedQuery<NoConflictCertificateData> query = entityManager.createQuery(sql, NoConflictCertificateData.class);
        query.setParameter("issuerDN", issuerDN);
        query.setParameter("serialNumber", serialNumber);
        return query.getResultList();
    }
    
}
