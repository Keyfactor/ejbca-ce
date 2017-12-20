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
        PUBLIC_WEB("Public Web", "/ejbca"),
        ADMIN_WEB("Admin Web", "/ejbca/adminweb"),
        RA_WEB("RA Web", "/ejbca/ra"),
        ACME("ACME", "/ejbca/acme"),
        CMP("CMP", "/ejbca/publicweb"),
        EST("EST", "/.well-known/est"),
        OCSP("OCSP", "/ejbca/publicweb/status"),
        SCEP("SCEP", "/ejbca/publicweb/appl"),
        WS("Web Service", "/ejbca/ejbcaws"),
        CERT_DIST("Webdist", "/ejbca/publicweb/webdist"),
        CRL_DIST("CRLdist", "/ejbca/publicweb/webdist"),
        // TODO Fill in context path
        CERT_STORE("Certstore", ""),
        CRL_STORE("CRLstore", "");

        private final String name;
        private final String contextPath;

        /**
         * Creates a new instance of an available protocol enum.
         * @param name the name of the enum, same as the "serviceName" from web.xml
         * @param contextPath the URL to the servlet
         */
        private AvailableProtocols(final String name, final String contextPath) {
            this.name = name;
            this.contextPath = contextPath;
        }

        /** @return user friendly name of protocol */
        public String getName() {
            return name;
        }

        public String getContextPath() {
            return contextPath;
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
