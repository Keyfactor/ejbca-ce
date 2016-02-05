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
package org.cesecore.config;

import org.cesecore.configuration.ConfigurationBase;

/**
 * Handles global CESeCore configuration values. 
 * 
 * @version $Id$
 *
 */
public class GlobalCesecoreConfiguration extends ConfigurationBase {

    private static final long serialVersionUID = 1L;
    public static final String CESECORE_CONFIGURATION_ID = "GLOBAL_CESECORE_CONFIGURATION";
    
    private static final String MAXIMUM_QUERY_COUNT_KEY = "maximum.query.count";
    
    @Override
    public void upgrade() {

    }

    @Override
    public String getConfigurationId() {
        return CESECORE_CONFIGURATION_ID;
    }
    
    /** @return the maximum size of the result from SQL select queries */
    public int getMaximumQueryCount() {
        Object num = data.get(MAXIMUM_QUERY_COUNT_KEY);
        if(num == null){
            return 500;
        } else {
            return ((Integer) num).intValue();
        }
    }
    
    public void setMaximumQueryCount(int maximumQueryCount){ 
        data.put(MAXIMUM_QUERY_COUNT_KEY, Integer.valueOf(maximumQueryCount));
    }

}
