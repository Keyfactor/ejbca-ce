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

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;

import org.cesecore.configuration.ConfigurationBase;


/**
 * This file handles configuration of available protocols
 * 
 * @version $Id$
 *
 */
public class AvailableProtocolsConfiguration extends ConfigurationBase implements Serializable {
    private static final long serialVersionUID = 1L;
    public final static String CONFIGURATION_ID = "AVAILABLE_PROTOCOLS";
    public final static String[] SUPPORTED_PROTOCOLS = {"ACME", "EST", "CMP", "OCSP", "SCEP", "WS"};
    

    /**
     * Initializes the configuration. All protocols will be enabled by default
     */
    public AvailableProtocolsConfiguration() {
        super();
        if(!isDataInitialized()) {
            initialize();
        }
    }
    
    /** All protocols will be enabled by default */
    private void initialize() {
        for (String protocol : SUPPORTED_PROTOCOLS) {
            setProtocolStatus(protocol, true);
        }
    }
    
    /**
     * Checks whether protocol is enabled / disabled
     * @param protocol to check status of
     * @return true if protocol is enabled, false otherwise
     */
    public boolean getProtocolStatus(String protocol) {
        return (Boolean)data.get(protocol);
    }
    
    public void setProtocolStatus(String protocol, boolean status) {
        data.put(protocol, status);
    }
    
    private boolean isDataInitialized() {
        boolean ret = data != null && data.size() > 1 && (getAllProtocolsAndStatus().size() == SUPPORTED_PROTOCOLS.length);
        return ret;
    }
    
    @SuppressWarnings("unchecked")
    public LinkedHashMap<String, Boolean> getAllProtocolsAndStatus() {
        Map<String, Boolean> protocolStatusMap = (Map<String, Boolean>) data.clone();
        if (protocolStatusMap != null) {
            if (protocolStatusMap.containsKey("version")) {
                protocolStatusMap.remove("version");
            }
            return new LinkedHashMap<>(protocolStatusMap);
        }
        return new LinkedHashMap<>();
    }
    
    @Override
    public String getConfigurationId() {
        return CONFIGURATION_ID;
    }

    @Override
    public void upgrade() {
        if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
            data.put(VERSION,  Float.valueOf(LATEST_VERSION));          
        }
    }
}
