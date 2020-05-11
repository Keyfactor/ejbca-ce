/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.configuration;

import java.util.HashSet;
import java.util.Set;

import org.cesecore.internal.UpgradeableDataHashMap;

/**
 * 
 * @version $Id$
 *
 */

public abstract class ConfigurationBase extends UpgradeableDataHashMap {

    private static final long serialVersionUID = 4886872276324915327L;

    public static final float LATEST_VERSION = 3f;
    
    @Override
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    @Override
    public abstract void upgrade();
    
    public abstract String getConfigurationId();

    /**
     * Allows the implementing class to have dynamically configured custom classes to be serialized.
     * 
     * @return a set of class or package names.
     */
    public Set<String> getCustomClassesWhitelist() {
        return new HashSet<>();
    }

    /**
     * Allows the implementing class to have dynamically configured custom classes to be serialized.
     * 
     * @param whitelist a set of class or package names.
     */
    public void setCustomClassesWhitelist(Set<String> whitelist) {
        
    }

}
