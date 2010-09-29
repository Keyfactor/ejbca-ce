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

import javax.ejb.EJBException;

import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.core.model.services.ServiceExistsException;

public interface ServiceSession {
    /**
     * Adds a Service to the database.
     * 
     * @throws ServiceExistsException
     *             if service already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void addService(org.ejbca.core.model.log.Admin admin, java.lang.String name, org.ejbca.core.model.services.ServiceConfiguration serviceConfiguration)
            throws org.ejbca.core.model.services.ServiceExistsException;

    /**
     * Adds a service to the database. Used for importing and exporting profiles
     * from xml-files.
     * 
     * @throws ServiceExistsException
     *             if service already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void addService(org.ejbca.core.model.log.Admin admin, int id, java.lang.String name,
            org.ejbca.core.model.services.ServiceConfiguration serviceConfiguration) throws org.ejbca.core.model.services.ServiceExistsException;



    /**
     * Adds a service with the same content as the original.
     * 
     * @throws ServiceExistsException
     *             if service already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void cloneService(org.ejbca.core.model.log.Admin admin, java.lang.String oldname, java.lang.String newname)
            throws org.ejbca.core.model.services.ServiceExistsException;

    /**
     * Removes a service from the database.
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public boolean removeService(org.ejbca.core.model.log.Admin admin, java.lang.String name);

    /**
     * Renames a service
     * 
     * @throws ServiceExistsException
     *             if service already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void renameService(org.ejbca.core.model.log.Admin admin, java.lang.String oldname, java.lang.String newname)
            throws org.ejbca.core.model.services.ServiceExistsException;

    /**
     * Retrieves a Collection of id:s (Integer) to visible authorized services.
     * Currently is the only check if the superadmin can see them all
     * 
     * @return Collection of id:s (Integer)
     */
    public java.util.Collection<Integer> getAuthorizedVisibleServiceIds(org.ejbca.core.model.log.Admin admin);

    /**
     * Retrives a named service.
     * 
     * @returns the service configuration or null if it doesn't exist.
     */
    public org.ejbca.core.model.services.ServiceConfiguration getService(org.ejbca.core.model.log.Admin admin, java.lang.String name);

    /**
     * Returns a service id, given it's service name
     * 
     * @return the id or 0 if the service cannot be found.
     */
    public int getServiceId(org.ejbca.core.model.log.Admin admin, java.lang.String name);



    /**
     * Activates the timer for a named service. The service must already be
     * previously added.
     * 
     * @param admin
     *            The administrator performing the action
     * @param name
     *            the name of the service for which to activate the timer
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void activateServiceTimer(org.ejbca.core.model.log.Admin admin, java.lang.String name);
    

    /**
     * Returns a Service name given its id.
     * 
     * @return the name or null if id doesnt exists
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public String getServiceName(Admin admin, int id);

 
    /**
     * Loads and activates all the services from database that are active
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void load();

    /**
     * Cancels all existing timers a unload
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void unload();
    
    /**
     * Updates service configuration, but does not re-set the timer
     * 
     * @param noLogging
     *            if true no logging (to the database will be done
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void changeService(Admin admin, String name, ServiceConfiguration serviceConfiguration, boolean noLogging);
    
    /**
     * Finds a service configuration by id.
     * 
     * @returns the service configuration or null if it doesn't exist.
     */
    public ServiceConfiguration getServiceConfiguration(Admin admin, int id);

}
