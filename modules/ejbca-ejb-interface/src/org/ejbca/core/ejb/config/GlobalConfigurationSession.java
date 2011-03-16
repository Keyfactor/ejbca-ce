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
package org.ejbca.core.ejb.config;

import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.log.Admin;

/** 
 * Session bean to handle global configuration and such.
 * 
 * @version $Id$
 */
public interface GlobalConfigurationSession {

    /**
     * Flushes the cached GlobalConfiguration value and reads the current one
     * from persistence.
     * 
     * @return a fresh GlobalConfiguration from persistence, or null of no such
     *         configuration exists.
     */
    GlobalConfiguration flushCache();
    
    /**
     * Retrieves the cached GlobalConfiguration. This cache is updated from
     * persistence either by the time specified by
     * {@link #MIN_TIME_BETWEEN_GLOBCONF_UPDATES} or when {@link #flushCache()}
     * is executed. This method should be used in all cases where a quick
     * response isn't necessary, otherwise use {@link #flushCache()}.
     * 
     * @return the cached GlobalConfiguration value.
     */
    GlobalConfiguration getCachedGlobalConfiguration(Admin admin);

    /** Saves the GlobalConfiguration. */
    void saveGlobalConfiguration(Admin admin, GlobalConfiguration globconf);

    /** Clear and load global configuration cache. */
    void flushGlobalConfigurationCache();


}
