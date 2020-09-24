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

import org.cesecore.configuration.ConfigurationBase;


/**
 * Handles configuration of protocols supporting enable / disable
 *
 * @version $Id$
 *
 */
public class AvailableProtocolsConfiguration extends ConfigurationBase implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final float LATEST_VERSION = 2f;

    public final static String CONFIGURATION_ID = "AVAILABLE_PROTOCOLS";

    /**
     * Protocols currently supporting enable/disable configuration by EJBCA
     */
    public enum AvailableProtocols {
        // If you add a protocol > 6.11.0 it should be disabled by default
        ACME("ACME", "/ejbca/acme"),
        CERT_STORE("Certstore", WebConfiguration.DEFAULT_CERTSTORE_CONTEXTROOT),
        CMP("CMP", "/ejbca/publicweb/cmp"),
        CRL_STORE("CRLstore", WebConfiguration.DEFAULT_CRLSTORE_CONTEXTROOT),
        EST("EST", "/.well-known/est"),
        OCSP("OCSP", "/ejbca/publicweb/status/ocsp"),
        PUBLIC_WEB("Public Web", "/ejbca"),
        SCEP("SCEP", "/ejbca/publicweb/apply/scep"),
        RA_WEB("RA Web", "/ejbca/ra"),
        REST_CA_MANAGEMENT("REST CA Management", "/ejbca/ejbca-rest-api/v1/ca_management"),
        REST_CERTIFICATE_MANAGEMENT("REST Certificate Management", "/ejbca/ejbca-rest-api/v1/ca<br/>/ejbca/ejbca-rest-api/v1/certificate"),
        REST_CRYPTOTOKEN_MANAGEMENT("REST Crypto Token Management", "/ejbca/ejbca-rest-api/v1/cryptotoken"),
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

    /** Initializes the configuration */
    public AvailableProtocolsConfiguration() {
        super();
    }

    /**
     * Checks whether protocol is enabled / disabled locally
     * @param protocol to check status of @see {@link AvailableProtocols}
     * @return true if protocol is enabled, false otherwise
     */
    public boolean getProtocolStatus(String protocol) {
        Boolean ret = (Boolean)data.get(protocol);
        // All protocols added > 6.11.0 should be disabled by default
        if (ret == null && (
                protocol.equals(AvailableProtocols.ACME.getName())  ||
                protocol.equals(AvailableProtocols.EST.getName())   || 
                protocol.equals(AvailableProtocols.REST_CA_MANAGEMENT.getName()) || 
                protocol.equals(AvailableProtocols.REST_CERTIFICATE_MANAGEMENT.getName()) ||
                protocol.equals(AvailableProtocols.REST_CRYPTOTOKEN_MANAGEMENT.getName()))) {
            setProtocolStatus(protocol, false);
            return false;
        }
        return ret == null ? true : ret;
    }

    public void setProtocolStatus(String protocol, boolean status) {
        data.put(protocol, status);
    }

    /** @return map containing the current status of all configurable protocols. */
    public LinkedHashMap<String, Boolean> getAllProtocolsAndStatus() {
        LinkedHashMap<String, Boolean> protocolStatusMap = new LinkedHashMap<>();
        for (AvailableProtocols protocol : AvailableProtocols.values()) {
            protocolStatusMap.put(protocol.getName(), getProtocolStatus(protocol.getName()));
        }
        return protocolStatusMap;
    }

    @Override
    public String getConfigurationId() {
        return CONFIGURATION_ID;
    }

    @Override
    public void upgrade() {
        if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
            data.put(VERSION,  Float.valueOf(LATEST_VERSION));
        }
    }
}
