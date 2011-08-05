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

import java.util.Collection;

import javax.ejb.EJBException;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.core.model.services.ServiceExistsException;

/**
 * @version $Id$
 */
public interface ServiceSession {

    /**
     * Adds a Service to the database.
     * @throws ServiceExistsException if service already exists.
     */
    public void addService(AuthenticationToken admin, String name, ServiceConfiguration serviceConfiguration) throws ServiceExistsException;

    /**
     * Adds a service to the database. Used for importing and exporting profiles
     * from xml-files.
     * 
     * @throws ServiceExistsException if service already exists.
     */
    public void addService(AuthenticationToken admin, int id, String name, ServiceConfiguration serviceConfiguration) throws ServiceExistsException;

    /**
     * Adds a service with the same content as the original.
     * @throws ServiceExistsException if service already exists.
     */
    public void cloneService(AuthenticationToken admin, String oldname, String newname) throws ServiceExistsException;

    /** Removes a service from the database. */
    public boolean removeService(AuthenticationToken admin, String name);

    /**
     * Renames a service.
     * @throws ServiceExistsException if service already exists.
     */
    public void renameService(AuthenticationToken admin, String oldname, String newname) throws ServiceExistsException;

    /**
     * Retrieves a Collection of id:s (Integer) to visible authorized services.
     * Currently is the only check if the superadmin can see them all
     * 
     * @return Collection of id:s (Integer)
     */
    public Collection<Integer> getAuthorizedVisibleServiceIds(AuthenticationToken admin);

    /**
     * Retrieves a named service.
     * @returns the service configuration or null if it doesn't exist.
     */
    public org.ejbca.core.model.services.ServiceConfiguration getService(AuthenticationToken admin, String name);

    /**
     * Returns a service id, given it's service name
     * @return the id or 0 if the service cannot be found.
     */
    public int getServiceId(AuthenticationToken admin, String name);

    /**
     * Activates the timer for a named service. The service must already be
     * previously added.
     * 
     * @param admin The administrator performing the action
     * @param name the name of the service for which to activate the timer
     */
    public void activateServiceTimer(AuthenticationToken admin, java.lang.String name);

    /**
     * Returns a Service name given its id.
     * @return the name or null if id doesn't exists
     */
    public String getServiceName(AuthenticationToken admin, int id);

 
    /** Loads and activates all the services from database that are active. */
    public void load();

    /** Cancels all existing timers a unload. */
    public void unload();
    
    /**
     * Updates service configuration, but does not re-set the timer
     * @param noLogging if true no logging (to the database will be done
     */
    public void changeService(AuthenticationToken admin, String name, ServiceConfiguration serviceConfiguration, boolean noLogging);
    
    /**
     * Finds a service configuration by id.
     * 
     * @returns the service configuration or null if it doesn't exist.
     * @throws EJBException if a communication or other error occurs.
     */
    public ServiceConfiguration getServiceConfiguration(AuthenticationToken admin, int id);

}
