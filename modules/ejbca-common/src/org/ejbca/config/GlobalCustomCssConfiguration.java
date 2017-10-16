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


package org.ejbca.config;

import java.util.LinkedHashMap;
import java.util.Map;

import org.cesecore.config.RaStyleInfo;
import org.cesecore.configuration.ConfigurationBase;

/**
 * This class handles configuration of custom RA Css files
 * @version $Id$
 */
public class GlobalCustomCssConfiguration extends ConfigurationBase {
    
    public static final String CSS_CONFIGURATION_ID = "CUSTOM_CSS";
    private static final long serialVersionUID = 1L;

    // Default custom RA CSS
    private static final LinkedHashMap<Integer, RaStyleInfo> RA_CUSTOM_CSS_DEFAULT   = new LinkedHashMap<>();

    private static final String RA_CUSTOM_CSS_REFERENCE = "racustomcss";
    
    
    public void setRaStyle(LinkedHashMap<Integer, RaStyleInfo> raStyleInfo) {
        data.put(RA_CUSTOM_CSS_REFERENCE, raStyleInfo);
    }
    
    /** 
     * Updates a RaStyleInfo archive referenced by Id of raStyleInfo
     * @param style info to update
     */
    public void updateRaStyle(RaStyleInfo raStyleInfo) {
        Map<Integer, RaStyleInfo> mapToUpdate = getRaStyleInfo();
        mapToUpdate.put(raStyleInfo.getArchiveId(), raStyleInfo);
        data.put(RA_CUSTOM_CSS_REFERENCE, mapToUpdate);
    }
    
    @SuppressWarnings("unchecked")
    public LinkedHashMap<Integer, RaStyleInfo> getRaStyleInfo() {
        final Map<Integer, RaStyleInfo> ret = (Map<Integer,RaStyleInfo>)data.get(RA_CUSTOM_CSS_REFERENCE);
        return ret == null ? RA_CUSTOM_CSS_DEFAULT : new LinkedHashMap<>(ret);
    }
    
    @Override
    public void upgrade() {
        if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
            data.put(VERSION,  Float.valueOf(LATEST_VERSION));          
        }
    }

    @Override
    public String getConfigurationId() {
        return CSS_CONFIGURATION_ID;
    }
}
