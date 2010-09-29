/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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
import javax.persistence.NoResultException;
import javax.persistence.NonUniqueResultException;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.model.services.ServiceConfiguration;

/**
 * Session bean for the Service Data table.
 * 
 * @author mikek
 * 
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "ServiceDataSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class ServiceDataSessionBean implements ServiceDataSessionLocal, ServiceDataSessionRemote {

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    /**
     * Adds a new ServiceData object with the given parameters to persistence.
     * 
     * @param id
     * @param name
     * @param serviceConfiguration
     */
    public void addServiceData(Integer id, String name, ServiceConfiguration serviceConfiguration) {
        entityManager.persist(new ServiceData(id, name, serviceConfiguration));
    }
    
    /**
     * Update the named ServiceData entity with a new ServiceConfiguration.
     * @return true if the ServiceData exists and was updated.
     */
    /* 
     * This method need "RequiresNew" transaction handling, because we want to
     * make sure that the timer runs the next time even if the execution fails.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public boolean updateServiceConfiguration(String name, ServiceConfiguration serviceConfiguration) {
    	ServiceData serviceData = findByName(name);
    	if (serviceData != null) {
        	serviceData.setServiceConfiguration(serviceConfiguration);
    		return true;
    	}
    	return false;
    }
    
    /**
     * Removes given parameter from persistence.
     * 
     * @param serviceData
     */
    public void removeServiceData(ServiceData serviceData) {
        serviceData = entityManager.merge(serviceData);
        entityManager.remove(serviceData);
    }
    
    /**
     * @throws NonUniqueResultException
     *             if more than one entity with the name exists
     * @return the found entity instance or null if the entity does not exist
     */
    public ServiceData findByName(String name) {
        ServiceData ret = null;
        try {
            Query query = entityManager.createQuery("SELECT a FROM ServiceData a WHERE a.name=:name");
            query.setParameter("name", name);
            ret = (ServiceData) query.getSingleResult();
        } catch (NoResultException e) {
        }
        return ret;
    }

    /** @return the found entity instance or null if the entity does not exist */
    public ServiceData findById(Integer id) {
        return entityManager.find(ServiceData.class, id);
    }
    
    /** @return return the query results as a List. */
    public List<ServiceData> findAll() {
        Query query = entityManager.createQuery("SELECT a FROM ServiceData a");
        return query.getResultList();
    }
}
