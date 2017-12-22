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
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;

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

    /**
     * Protocols currently supporting enable/disable configuration by EJBCA
     */
    public enum AvailableProtocols {
        CERT_STORE("Certstore", "/certificates"),
        CMP("CMP", "/ejbca/publicweb/cmp"),
        CRL_STORE("CRLstore", "/crls"),
        EST("EST", "/.well-known/est"),
        OCSP("OCSP", "/ejbca/publicweb/status/ocsp"),
        PUBLIC_WEB("Public Web", "/ejbca"),
        SCEP("SCEP", "/ejbca/publicweb/apply/scep"),
        RA_WEB("RA Web", "/ejbca/ra"),
        WEB_DIST("Webdist", "/ejbca/publicweb/webdist"),
        WS("Web Service", "/ejbca/ejbcaws");

        private final String name;
        private final String url;
        private static final Map<String, String> reverseLookupMap = new HashMap<>();
        
        static {
            for (final AvailableProtocols protocol : AvailableProtocols.values()) {
                reverseLookupMap.put(protocol.getName(), protocol.getUrl());
            }
        }
        
        /**
         * Creates a new instance of an available protocol enum.
         * @param name the name of the enum, same as the "serviceName" from web.xml
         * @param url the URL to the servlet
         */
        private AvailableProtocols(final String name, final String url) {
            this.name = name;
            this.url = url;
        }

        /** @return user friendly name of protocol */
        public String getName() {
            return name;
        }

        public String getUrl() {
            return url;
        }
        
        public static String getContextPathByName(String name) {
            return reverseLookupMap.get(name);
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
            boolean defaultValue = true;
            setProtocolStatus(AvailableProtocols.values()[i].getName(), defaultValue);
        }
        // All protocols added > 6.11.0 should be set to false (disabled) by default
        setProtocolStatus(AvailableProtocols.EST.getName(), false);
    }

    /**
     * Checks whether protocol is enabled / disabled locally
     * @param protocol to check status of @see {@link AvailableProtocols}
     * @return true if protocol is enabled, false otherwise
     */
    public boolean getProtocolStatus(String protocol) {
        Boolean ret = (Boolean)data.get(protocol);
        return ret == null ? true : ret;
    }

    public void setProtocolStatus(String protocol, boolean status) {
        data.put(protocol, status);
    }

    private boolean isDataInitialized() {
        boolean ret = !getAllProtocolsAndStatus().isEmpty();
        return ret;
    }

    public LinkedHashMap<String, Boolean> getAllProtocolsAndStatus() {
        LinkedHashMap<String, Boolean> protocolStatusMap = new LinkedHashMap<>();

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
