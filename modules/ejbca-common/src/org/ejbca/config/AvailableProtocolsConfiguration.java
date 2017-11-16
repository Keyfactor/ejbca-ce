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

import org.apache.log4j.Logger;
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

    private static final Logger log = Logger.getLogger(AvailableProtocolsConfiguration.class);
    
    /** Protocols currently supported by Ejbca */
    public enum AvailableProtocols{
        ACME("ACME"), 
        CMP("CMP"), 
        EST("EST"), 
        OCSP("OCSP"), 
        SCEP("SCEP"), 
        WS("Web Service");
        
        private String resource;
        private AvailableProtocols(String resource) {
            this.resource = resource;
        }
        
        public String getResource() {
            return this.resource;
        }
    };

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
        for (int i = 0; i < AvailableProtocols.values().length; i++) {
            setProtocolStatus(AvailableProtocols.values()[i].getResource(), true);
        }
    }
    
    /** 
     * Checks whether protocol is enabled / disabled locally and from incoming Peer connection. Disabled status
     * from peer or local configuration will always override enable.
     * @param protocol to check status of
     * @return true if protocol is enabled and incoming peer allows the protocol, false otherwise
     */
    public boolean getProtocolStatus(String protocol) {
        return (Boolean)data.get(protocol) && AvailableProtocolsPeerCache.INSTANCE.isProtocolEnabled(protocol);
    }
    
    public void setProtocolStatus(String protocol, boolean status) {
        data.put(protocol, status);
    }
    
    private boolean isDataInitialized() {
        boolean ret = data != null && data.size() > 1 && (getAllProtocolsAndStatus().size() == AvailableProtocols.values().length);
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
