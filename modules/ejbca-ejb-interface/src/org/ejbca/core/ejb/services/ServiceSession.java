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

import java.util.Collection;
import java.util.List;

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
    void addService(AuthenticationToken admin, String name, ServiceConfiguration serviceConfiguration) throws ServiceExistsException;

    /**
     * Adds a service to the database. Used for importing and exporting profiles
     * from xml-files.
     * 
     * @throws ServiceExistsException if service already exists.
     */
    void addService(AuthenticationToken admin, int id, String name, ServiceConfiguration serviceConfiguration) throws ServiceExistsException;

    /**
     * Adds a service with the same content as the original.
     * @throws ServiceExistsException if service already exists.
     */
    void cloneService(AuthenticationToken admin, String oldname, String newname) throws ServiceExistsException;

    /** Removes a service from the database. */
    boolean removeService(AuthenticationToken admin, String name);

    /**
     * Renames a service.
     * @throws ServiceExistsException if service already exists.
     */
     void renameService(AuthenticationToken admin, String oldname, String newname) throws ServiceExistsException;

    /**
     * Retrieves a Collection of id:s (Integer) to visible authorized services.
     * Currently is the only check if the superadmin can see them all
     * 
     * @return Collection of id:s (Integer)
     */
    Collection<Integer> getAuthorizedVisibleServiceIds(AuthenticationToken admin);

    /**
     * Retrieves a named service.
     * @returns the service configuration or null if it doesn't exist.
     */
    ServiceConfiguration getService(String name);

    /**
     * Returns a service id, given it's service name
     * @return the id or 0 if the service cannot be found.
     */
    int getServiceId(String name);

    /**
     * Activates the timer for a named service. The service must already be
     * previously added.
     * 
     * @param admin The administrator performing the action
     * @param name the name of the service for which to activate the timer
     */
     void activateServiceTimer(AuthenticationToken admin, String name);

    /**
     * Returns a Service name given its id.
     * @return the name or null if id does not exist
     */
    String getServiceName(int id);

    /**
     * Checks if a list of certificate profiles is used by any service.
     * 
     * @param certificateProfileId IDs of the certificate profile to check
     * @return a list of ServiceData objects using the given ID, or an empty list if nothing is found
     */
    List<String> getServicesUsingCertificateProfile(Integer certificateProfileId);
 
    /** Loads and activates all the services from database that are active. */
    void load();

    /** Cancels all existing timers a unload. */
    void unload();
    
    /**
     * Updates service configuration, but does not re-set the timer
     * @param noLogging if true no logging (to the database will be done
     */
    void changeService(AuthenticationToken admin, String name, ServiceConfiguration serviceConfiguration, boolean noLogging);
    
    /**
     * Finds a service configuration by id.
     * 
     * @returns the service configuration or null if it doesn't exist.
     */
    ServiceConfiguration getServiceConfiguration(AuthenticationToken admin, int id);

}
