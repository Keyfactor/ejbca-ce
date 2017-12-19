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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;

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
    private static final Logger log = Logger.getLogger(AvailableProtocolsConfiguration.class);
    
    public final static String CONFIGURATION_ID = "AVAILABLE_PROTOCOLS";

    /**
     * Protocols currently supporting enable/disable configuration by EJBCA
     */
    public enum AvailableProtocols {
        PUBLIC_WEB("Public Web", "/ejbca"),
        ACME("ACME", "/ejbca/acme"),
        CMP("CMP", "/ejbca/publicweb"),
        // TODO Fill in CRL and certificate webdist
        CERTSTORE("Certificate Store", ""),
        CRLSTORE("CRL Store", ""),
        // TODO Fill in context path for EST
        EST("EST", ""),
        OCSP("OCSP", "/ejbca/publicweb/status"),
        SCEP("SCEP", "/ejbca/publicweb/appl"),
        WS("Web Service", "/ejbca/ejbcaws");

        private final String name;
        private final String contextPath;
        private final Map<String, String[]> parameterMap;

        private AvailableProtocols(final String name, final String contextPath) {
            this(name, contextPath, Collections.<String, String[]> emptyMap());
        }

        private AvailableProtocols(final String name, final String contextPath, final Map<String, String[]> parameterMap) {
            this.name = name;
            this.contextPath = contextPath;
            this.parameterMap = parameterMap;
        }

        /** @return user friendly name of protocol */
        public String getName() {
            return name;
        }

        public String getContextPath() {
            return contextPath;
        }

        public Map<String, String[]> getParameterMap() {
            return parameterMap;
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
            setProtocolStatus(AvailableProtocols.values()[i].getName(), true);
        }
    }

    /**
     * Checks whether protocol is enabled / disabled locally
     * @param protocol to check status of @see {@link AvailableProtocols}
     * @return true if protocol is enabled, false otherwise
     */
    public boolean getProtocolStatus(String protocol) {
        return (Boolean)data.get(protocol);
    }

    public void setProtocolStatus(String protocol, boolean status) {
        data.put(protocol, status);
    }

    private boolean isDataInitialized() {
        boolean ret = !getAllProtocolsAndStatus().isEmpty();
        return ret;
    }

    public LinkedHashMap<String, Boolean> getAllProtocolsAndStatus() {
        LinkedHashMap<String, Boolean> protocolStatusMap = new LinkedHashMap<>();//(Map<String, Boolean>) data.clone();
        
        for (Entry<Object, Object> entry : data.entrySet()) {
            if (entry.getKey().equals("version")) {
                continue;
            }
            protocolStatusMap.put((String)entry.getKey(), (Boolean)entry.getValue());
        }
        return protocolStatusMap;
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
