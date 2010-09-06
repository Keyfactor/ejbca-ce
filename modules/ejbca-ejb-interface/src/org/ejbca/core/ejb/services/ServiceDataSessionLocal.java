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

import javax.ejb.Local;
import javax.persistence.NonUniqueResultException;

import org.ejbca.core.model.services.ServiceConfiguration;

/**
 * @author mikek
 * 
 */
@Local
public interface ServiceDataSessionLocal extends ServiceDataSession {

    /**
     * @throws NonUniqueResultException
     *             if more than one entity with the name exists
     * @return the found entity instance or null if the entity does not exist
     */
    ServiceData findByName(String name);



    /** @return return the query results as a List. */
    List<ServiceData> findAll();

    /**
     * Adds a new ServiceData object with the given parameters to persistence.
     * 
     * @param id
     * @param name
     * @param serviceConfiguration
     */
    void addServiceData(Integer id, String name, ServiceConfiguration serviceConfiguration);
    
    /**
     * Removes given parameter from persistence.
     * 
     * @param serviceData
     */
     void removeServiceData(ServiceData serviceData);
}
