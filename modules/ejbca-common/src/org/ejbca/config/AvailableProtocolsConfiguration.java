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
 */
public class AvailableProtocolsConfiguration extends ConfigurationBase implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final float LATEST_VERSION = 3f;

    public static final String CONFIGURATION_ID = "AVAILABLE_PROTOCOLS";
    private static final String REST_CERTIFICATE_MANAGEMENT_PROTOCOL_EE_ONLY_PATH = "/ejbca/ejbca-rest-api/v1/ca";
    
    private static final String CUSTOM_HEADER_REST_ENABLED = "ejbca.rest.custombrowserheader.enabled";
    private static final String CUSTOM_HEADER_REST_NAME_DEFAULT = "X-Keyfactor-Requested-With";
    private static final String CUSTOM_HEADER_REST_NAME = "ejbca.rest.custombrowserheader";

    /**
     * Protocols currently supporting enable/disable configuration by EJBCA
     */
    public enum AvailableProtocols {
        // If you add a protocol > 6.11.0 it should be disabled by default by returning false from #getProtocolStatus
        ACME("ACME", "/ejbca/acme"),
        CERT_STORE("Certstore", WebConfiguration.DEFAULT_CERTSTORE_CONTEXTROOT),
        CMP("CMP", "/ejbca/publicweb/cmp"),
        CRL_STORE("CRLstore", WebConfiguration.DEFAULT_CRLSTORE_CONTEXTROOT),
        EST("EST", "/.well-known/est"),
        MSAE("MSAE", "/ejbca/msae"),
        OCSP("OCSP", "/ejbca/publicweb/status/ocsp"),
        PUBLIC_WEB("Public Web", "/ejbca"),
        SCEP("SCEP", "/ejbca/publicweb/apply/scep"),
        RA_WEB("RA Web", "/ejbca/ra"),
        REST_CA_MANAGEMENT("REST CA Management", "/ejbca/ejbca-rest-api/v1/ca_management"),
        REST_CERTIFICATE_MANAGEMENT("REST Certificate Management", "/ejbca/ejbca-rest-api/v1/certificate"),
        REST_CRYPTOTOKEN_MANAGEMENT("REST Crypto Token Management", "/ejbca/ejbca-rest-api/v1/cryptotoken"),
        REST_ENDENTITY_MANAGEMENT("REST End Entity Management", "/ejbca/ejbca-rest-api/v1/endentity"),
        REST_ENDENTITY_MANAGEMENT_V2("REST End Entity Management V2", "/ejbca/ejbca-rest-api/v2/endentity"),
        REST_CONFIGDUMP("REST Configdump", "/ejbca/ejbca-rest-api/v1/configdump"),
        REST_CERTIFICATE_MANAGEMENT_V2("REST Certificate Management V2", "/ejbca/ejbca-rest-api/v2/certificate"),
        REST_SSH_V1("REST SSH V1", "/ejbca/ejbca-rest-api/v1/ssh"),
        WEB_DIST("Webdist", "/ejbca/publicweb/webdist"),
        WS("Web Service", "/ejbca/ejbcaws"),
        ITS("ITS Certificate Management", "/ejbca/its");

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

        /**
         * Returns protocol URLs that should be shown on configuration page.
         * Method is used to hide the /ca REST endpoint from configuration page while
         * only a subset of Certificate Management APIs are rolled out to Community edition.
         * @param name Protocol name
         * @param isEnterprise true/false depending on whether EE version is running
         * @return Protocol paths
         */
        public static String getContextPathByName(String name, boolean isEnterprise) {
            if (isEnterprise && REST_CERTIFICATE_MANAGEMENT.name.equals(name)) {
                return REST_CERTIFICATE_MANAGEMENT_PROTOCOL_EE_ONLY_PATH + "<br/>" + reverseLookupMap.get(name);
            }
            return reverseLookupMap.get(name);
        }
    }

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
                protocol.equals(AvailableProtocols.MSAE.getName())   ||
                protocol.equals(AvailableProtocols.REST_CA_MANAGEMENT.getName()) ||
                protocol.equals(AvailableProtocols.REST_CONFIGDUMP.getName()) ||
                protocol.equals(AvailableProtocols.REST_CERTIFICATE_MANAGEMENT.getName()) ||
                protocol.equals(AvailableProtocols.REST_CRYPTOTOKEN_MANAGEMENT.getName()) ||
                protocol.equals(AvailableProtocols.REST_ENDENTITY_MANAGEMENT.getName()) || 
                protocol.equals(AvailableProtocols.REST_ENDENTITY_MANAGEMENT_V2.getName()) || 
                protocol.equals(AvailableProtocols.REST_CERTIFICATE_MANAGEMENT_V2.getName()) ||
                protocol.equals(AvailableProtocols.REST_SSH_V1.getName()) ||
                protocol.equals(AvailableProtocols.ITS.getName()))) {
            setProtocolStatus(protocol, false);
            return false;
        }
        return (ret == null || ret);
    }

    public void setProtocolStatus(String protocol, boolean status) {
        data.put(protocol, status);
    }

    /** @return map containing the current status of all configurable protocols. */
    public Map<String, Boolean> getAllProtocolsAndStatus() {
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
    
    public boolean isCustomHeaderForRestEnabled() {
        return Boolean.parseBoolean((String) data.getOrDefault(CUSTOM_HEADER_REST_ENABLED, String.valueOf(true)));
    }
    
    public void setCustomHeaderForRestEnabled(boolean value) {
        data.put(CUSTOM_HEADER_REST_ENABLED, String.valueOf(value));
    }
    
    public String getCustomHeaderForRest() {
        return (String) data.getOrDefault(CUSTOM_HEADER_REST_NAME, CUSTOM_HEADER_REST_NAME_DEFAULT);
    }
    
    public void setCustomHeaderForRest(String value) {
        data.put(CUSTOM_HEADER_REST_NAME, value);
    }

    @Override
    public void upgrade() {
        if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
            data.put(VERSION,  Float.valueOf(LATEST_VERSION));
        }
    }
}
