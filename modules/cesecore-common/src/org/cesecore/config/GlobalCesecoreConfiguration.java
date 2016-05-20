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
import org.cesecore.internal.InternalResources;

/**
 * Handles global CESeCore configuration values. 
 * 
 * @version $Id$
 *
 */
public class GlobalCesecoreConfiguration extends ConfigurationBase {
    
    private static final long serialVersionUID = 1L;
    
    private static final InternalResources intres = InternalResources.getInstance();
    
    /** A fixed maximum value to ensure that  */
    private static final int FIXED_MAXIMUM_QUERY_COUNT = 25_000;
    
    public static final String CESECORE_CONFIGURATION_ID = "CESECORE_CONFIGURATION";
    
    private static final String MAXIMUM_QUERY_COUNT_KEY = "maximum.query.count";
    private static final String MAXIMUM_QUERY_TIMEOUT_KEY = "maximum.query.timeout";
    
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
    
    /**
     * Set's the maximum query count
     * 
     * @param maximumQueryCount the maximum query count
     * @throws InvalidConfigurationException if value was negative or above the limit set by {@link GlobalCesecoreConfiguration#MAXIMUM_QUERY_COUNT_KEY}
     */
    public void setMaximumQueryCount(int maximumQueryCount) throws InvalidConfigurationException { 
        if (maximumQueryCount > FIXED_MAXIMUM_QUERY_COUNT) {
            throw new InvalidConfigurationException(intres.getLocalizedMessage("globalconfig.error.querysizetoolarge", maximumQueryCount, FIXED_MAXIMUM_QUERY_COUNT));
        }
        if (maximumQueryCount < 1) {
            throw new InvalidConfigurationException(intres.getLocalizedMessage("globalconfig.error.querysizetoolow"));
        }
        data.put(MAXIMUM_QUERY_COUNT_KEY, Integer.valueOf(maximumQueryCount));
    }

    /** @return database dependent query timeout hint in milliseconds or 0 if this is disabled. */
    public long getMaximumQueryTimeout() {
        final Object num = data.get(MAXIMUM_QUERY_TIMEOUT_KEY);
        return num==null ? 10000L : ((Long) num).longValue();
    }

    /** Set's the database dependent query timeout hint in milliseconds or 0 if this is disabled. */
    public void setMaximumQueryTimeout(final long maximumQueryTimeoutMs) throws InvalidConfigurationException { 
        data.put(MAXIMUM_QUERY_TIMEOUT_KEY, Long.valueOf(maximumQueryTimeoutMs < 0L ? 0L : maximumQueryTimeoutMs));
    }
}
