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
package org.ejbca.core.ejb.config;

import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.GlobalConfiguration;

/**
 * Class Holding cache variable for global configuration. Needed because EJB spec does not allow volatile, non-final 
 * fields in session beans.
 * This is a trivial cache, too trivial, it needs manual handling of setting the cache variable, this class does not keep track on if
 * the cache variable is null or not, the using class must ensure that it does not try to use a null value. 
 * Only the method "needsUpdate will return true of the cache variable is null. 
 * 
 * @version $Id$
 */
public final class GlobalConfigurationCache {

    /**
     * Cache variable containing the global configuration. This cache may be
     * unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Set volatile to make it thread friendly.
     */
    private volatile GlobalConfiguration globalconfigurationCache = null;
    /** help variable used to control that GlobalConfiguration update isn't performed to often. */
    private volatile long lastupdatetime = -1;  

	public GlobalConfigurationCache() {
		// Do nothing
	}

	public GlobalConfiguration getGlobalconfiguration() {
		return globalconfigurationCache;
	}

	public void setGlobalconfiguration(final GlobalConfiguration globalconfiguration) {
		globalconfigurationCache = globalconfiguration;
        lastupdatetime = System.currentTimeMillis();
	}

	public boolean needsUpdate() {
        if (globalconfigurationCache != null && lastupdatetime + EjbcaConfiguration.getCacheGlobalConfigurationTime() > System.currentTimeMillis()) {
        	return false;
        }
        return true;
	}
	
	public void clearCache() {
		globalconfigurationCache = null;
	}
}
