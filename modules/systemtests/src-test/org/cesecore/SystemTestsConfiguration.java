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
package org.cesecore;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;

/**
 * Helper class for running the system tests on a system where the default
 * assumptions regarding external port, IP etc does not apply.
 * 
 * @version $Id$
 */
public abstract class SystemTestsConfiguration {

    public static final String PKCS11_LIBRARY = "pkcs11.library";
    public static final String PKCS11_SLOT_PIN = "pkcs11.slotpin";
    public static final String PKCS11_SECURITY_PROVIDER = "pkcs11.provider";
    public static final String PKCS11_SLOT_TYPE = "pkcs11.slottype"; 
    public static final String PKCS11_SLOT_VALUE = "pkcs11.slottypevalue"; 

    
    private static final Logger log = Logger.getLogger(SystemTestsConfiguration.class);
    private static final String PROPERTYFILE = "/systemtests.properties";
    private static Properties properties = null;

    private static Properties getProperties() {
        if (properties==null) {
            properties = new Properties();
            try {
                final InputStream is = SystemTestsConfiguration.class.getResourceAsStream(PROPERTYFILE);
                if (is!=null) {
                    properties.load(is);
                    is.close();
                }
            } catch (IOException e) {
                log.warn(e.getMessage());
            }
            if (properties.isEmpty()) {
                log.info(PROPERTYFILE + " was not detected. Defaults will be used.");
            } else {
                log.info(PROPERTYFILE + " was detected.");
            }
        }
        return properties;
    }

    /** @return the host that the test should access for protocols (e.g. the IP of an HTTP proxy in front of EJBCA)*/
    public static String getRemoteHost(final String defaultValue) {
        return getProperties().getProperty("target.hostname", defaultValue);
    }

    /** @return the HTTP port of the host that the test should access for protocols (e.g. the HTTP port of an http proxy in front of EJBCA)*/
    public static String getRemotePortHttp(final String defaultValue) {
        return getProperties().getProperty("target.port.http", defaultValue);
    }

    /** @return the HTTPS port of the host that the test should access for protocols (e.g. the HTTPS port of an http proxy in front of EJBCA)*/
    public static String getRemotePortHttps(final String defaultValue) {
        return getProperties().getProperty("target.port.https", defaultValue);
    }
    
    public static String getPkcs11Library(String defaultValue) {
        return getProperties().getProperty(PKCS11_LIBRARY, defaultValue);
    }
    
    public static char[] getPkcs11SlotPin(String defaultValue) {
        return getProperties().getProperty(PKCS11_SLOT_PIN, defaultValue).toCharArray();
    }
    
    public static String getPkcs11SecurityProvider(String defaultValue) {
        return getProperties().getProperty(PKCS11_SECURITY_PROVIDER, defaultValue);
    }    
    
    public static Pkcs11SlotLabelType getPkcs11SlotType(String defaultValue) {
        return Pkcs11SlotLabelType.getFromKey(getProperties().getProperty(PKCS11_SLOT_TYPE, defaultValue));
    }
    
    public static String getPkcs11SlotValue(String defaultValue) {
        return getProperties().getProperty(PKCS11_SLOT_VALUE, defaultValue);
    }
}
