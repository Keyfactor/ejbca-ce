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

import java.io.File;
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

    private static final String PKCS11_LIBRARY = "pkcs11.library";
    private static final String PKCS11_SLOT_PIN = "pkcs11.slotpin";
    private static final String PKCS11_SECURITY_PROVIDER = "pkcs11.provider";
    private static final String PKCS11_SLOT_TYPE = "pkcs11.slottype"; 
    private static final String PKCS11_SLOT_VALUE = "pkcs11.slottypevalue";
    // These are public so they can be used in error messages
    public static final String TARGET_CLIENTCERT_CA = "target.clientcert.ca";
    public static final String TARGET_SERVERCERT_CA = "target.servercert.ca";
    // Used by tests that spawn servers
    public static final String TESTSERVERS_BINDADDRESS = "testservers.bindaddress";
    public static final String TESTSERVERS_HOSTNAME = "testservers.hostname";

    private static final String[] COMMON_PKCS11_PATHS = {
        "/etc/utimaco/libcs2_pkcs11.so", // Utimaco (Linux)
        "C:/Program Files/Utimaco/SafeGuard CryptoServer/Lib/cs2_pkcs11.dll", // Utimaco (Windows)
        "/usr/lunasa/lib/libCryptoki2_64.so", // LunaSA (Linux 64-bit)
        "/usr/lunasa/lib/libCryptoki2.so", // LunaSA (Linux 32-bit)
        "/opt/PTK/lib/libcryptoki.so", // ProtectServer (Linux). This symlink is set by safeNet-install.sh->"5 Set the default cryptoki and/or hsm link". Use it instead of symlinking manually.
        "/opt/ETcpsdk/lib/linux-x86_64/libcryptoki.so", // ProtectServer (Linux 64-bit)
        "/opt/ETcpsdk/lib/linux-i386/libcryptoki.so", // ProtectServer (Linux 32-bit)
        "C:/Program Files/SafeNet/ProtectToolkit C SDK/bin/sw/cryptoki.dll", // ProtectServer (Windows)
        "/usr/lib/softhsm/libsofthsm2.so", // SoftHSM 2 (Linux)
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", // SoftHSM 2 (Linux multiarch, 64-bit)
    };

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

    public static String[] getServerCertificateCaNames() {
        return getProperties().getProperty(TARGET_SERVERCERT_CA, "ManagementCA;AdminCA1").split(";");
    }

    public static String[] getClientCertificateCaNames() {
        return getProperties().getProperty(TARGET_CLIENTCERT_CA, "ManagementCA;AdminCA1").split(";");
    }

    /**
     * Address which tests that spawn servers should bind to.
     * Default is 127.0.0.1, which means that only local connections are allowed.
     * Set to 0.0.0.0 to allow external connections (perhaps from a different VM).
     */
    public static String getTestServersBindAddress() {
        return getProperties().getProperty(TESTSERVERS_BINDADDRESS, "127.0.0.1");
    }

    /** Hostname of that EJBCA should connect to, to reach servers spawned by tests. */
    public static String getTestServersHostname() {
        return getProperties().getProperty(TESTSERVERS_HOSTNAME, "localhost");
    }

    /** Use {@link #getHsmLibrary} instead, which has auto-detection. */
    private static String getPkcs11LibraryInternal(String defaultValue) {
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
    
    /**
     * Returns the PKCS#11 library to use in system tests. It looks for the one in systemtests.properties,
     * and if that is not configured, it looks in some common locations. 
     * @param defaultValue The value to return if no HSM library is available.
     * @return PKCS#11 library, or defaultValue if not available.
     */
    public static String getPkcs11Library(final String defaultValue) {
        final String hsmlib = getPkcs11LibraryInternal(guessPkcs11Library());
        if (hsmlib == null) {
            return defaultValue;
        }
        if (!(new File(hsmlib).exists())) {
            log.error("HSM library " + hsmlib + " defined, but does not exist.");
            return defaultValue;
        }

        return hsmlib;
    }

    /**
     * Returns the PKCS#11 library to use in system tests. It looks for the one in systemtests.properties,
     * and if that is not configured, it looks in some common locations.
     * <p>
     * This method used to be in CryptoTokenTestUtils, where it was called getHSMLibrary
     * @return PKCS#11 library, or null if not available.
     */
    public static String getPkcs11Library() {
        return getPkcs11Library(null);
    }

    /**
     * Searches for common PKCS#11 libraries, returning the first one found.
     * @return File system path to HSM library, or null if none was found.
     */
    private static String guessPkcs11Library() {
        for (final String path : COMMON_PKCS11_PATHS) {
            final File libraryFile = new File(path);
            if (libraryFile.exists()) {
                return libraryFile.getAbsolutePath();
            }
        }
        return null;
    }
}
