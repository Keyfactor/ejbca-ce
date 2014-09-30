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

import javax.ejb.Local;

import org.ejbca.core.model.services.ServiceConfiguration;

/**
 * @author mikek
 * @version $Id$
 */
@Local
public interface ServiceDataSessionLocal extends ServiceDataSession {

    /**
     * @throws javax.persistence.NonUniqueResultException
     *             if more than one entity with the name exists
     * @return the found entity instance or null if the entity does not exist
     */
    ServiceData findByName(String name);

    /** @return the name of the service with the given id */
    public String findNameById(Integer id);

    /** @return return the query results as a List. */
    List<ServiceData> findAll();

    /** Adds a new ServiceData object with the given parameters to persistence. */
    void addServiceData(Integer id, String name, ServiceConfiguration serviceConfiguration);

    /**
     * Update the named ServiceData entity with a new ServiceConfiguration.
     * @return true if the ServiceData exists and was updated.
     */
    boolean updateServiceConfiguration(String name, ServiceConfiguration serviceConfiguration);

    /**
     * Removes given parameter from persistence.
     * @param serviceData
     */
     void removeServiceData(Integer id);

    /**
     * Updates a database row with the matching values. This way we can ensure atomic operation for acquiring the semaphore for a service,
     * independent of the underlying database isolation level.
     * @return true if 1 row was updated
     */
     public boolean updateTimestamps(Integer serviceId, long oldRunTimeStamp, long oldNextRunTimeStamp, long newRunTimeStamp, long newNextRunTimeStamp);
}
