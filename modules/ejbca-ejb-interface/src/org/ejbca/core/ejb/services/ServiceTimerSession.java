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

public interface ServiceTimerSession {
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
     * Adds a timer to the bean, and cancels all existing timeouts for this id.
     * 
     * @param id
     *            the id of the timer
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void addTimer(long interval, java.lang.Integer id);

    /**
     * cancels a timer with the given Id
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void cancelTimer(java.lang.Integer id);
}
