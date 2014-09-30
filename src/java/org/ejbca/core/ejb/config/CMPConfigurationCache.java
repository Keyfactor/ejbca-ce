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

import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.EjbcaConfiguration;

/**
 * Class Holding cache variable for cmp configuration. Needed because EJB spec does not allow volatile, non-final 
 * fields in session beans.
 * This is a trivial cache, too trivial, it needs manual handling of setting the cache variable, this class does not keep track on if
 * the cache variable is null or not, the using class must ensure that it does not try to use a null value. 
 * Only the method "needsUpdate will return true of the cache variable is null. 
 * 
 * @version $Id$
 */
public final class CMPConfigurationCache {

    /**
     * Cache variable containing the cmp configuration. This cache may be
     * unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Set volatile to make it thread friendly.
     */
    private volatile CmpConfiguration cmpconfigurationCache = null;
    /** help variable used to control that CmpConfiguration update isn't performed to often. */
    private volatile long lastupdatetime = -1;  

    public CMPConfigurationCache() {
        // Do nothing
    }

    public CmpConfiguration getCMPConfiguration() {
        return cmpconfigurationCache;
    }

    public void setCMPConfiguration(final CmpConfiguration cmpconfiguration) {
        cmpconfigurationCache = cmpconfiguration;
        lastupdatetime = System.currentTimeMillis();
    }

    public boolean needsUpdate() {
        if (cmpconfigurationCache != null && lastupdatetime + EjbcaConfiguration.getCacheGlobalConfigurationTime() > System.currentTimeMillis()) {
            return false;
        }
        return true;
    }
    
    public void clearCache() {
        cmpconfigurationCache = null;
    }
}
