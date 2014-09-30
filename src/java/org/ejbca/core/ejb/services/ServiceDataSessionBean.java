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
package org.ejbca.core.ejb.services;

import java.util.List;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.QueryResultWrapper;
import org.ejbca.core.model.services.ServiceConfiguration;

/**
 * Session bean for the Service Data table.
 *
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "ServiceDataSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class ServiceDataSessionBean implements ServiceDataSessionLocal, ServiceDataSessionRemote {

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @Override
    public void addServiceData(Integer id, String name, ServiceConfiguration serviceConfiguration) {
        entityManager.persist(new ServiceData(id, name, serviceConfiguration));
    }
    
    /* 
     * This method need "RequiresNew" transaction handling, because we want to
     * make sure that the timer runs the next time even if the execution fails.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public boolean updateServiceConfiguration(String name, ServiceConfiguration serviceConfiguration) {
    	ServiceData serviceData = findByName(name);
    	if (serviceData != null) {
        	serviceData.setServiceConfiguration(serviceConfiguration);
    		return true;
    	}
    	return false;
    }
    
    @Override
    public void removeServiceData(Integer id) {
    	ServiceData sd = findById(id);
    	if (sd != null) {
    		entityManager.remove(sd);
    	}
    }

    @Override
    public ServiceData findByName(String name) {
        final Query query = entityManager.createQuery("SELECT a FROM ServiceData a WHERE a.name=:name");
        query.setParameter("name", name);
        return (ServiceData) QueryResultWrapper.getSingleResult(query);
    }

    @Override
    public ServiceData findById(Integer id) {
        return entityManager.find(ServiceData.class, id);
    }
    
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public String findNameById(Integer id) {
        final Query query = entityManager.createQuery("SELECT a.name FROM ServiceData a WHERE a.id=:id");
        query.setParameter("id", id);
        return (String) QueryResultWrapper.getSingleResult(query);
    }
    
    @SuppressWarnings("unchecked")
    @Override
    public List<ServiceData> findAll() {
        Query query = entityManager.createQuery("SELECT a FROM ServiceData a");
        return query.getResultList();
    }
 
    @Override
	public boolean updateTimestamps(Integer serviceId, long oldRunTimeStamp, long oldNextRunTimeStamp, long newRunTimeStamp, long newNextRunTimeStamp) {
    	return ServiceData.updateTimestamps(entityManager, serviceId, oldRunTimeStamp, oldNextRunTimeStamp, newRunTimeStamp, newNextRunTimeStamp);
    }
}
