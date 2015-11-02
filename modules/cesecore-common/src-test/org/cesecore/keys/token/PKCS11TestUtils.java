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
package org.cesecore.keys.token;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;

/**
 * @version $Id$
 *
 */
public class PKCS11TestUtils {

    private static final Logger log = Logger.getLogger(PKCS11TestUtils.class);

    private static final String PROPERTYFILE = "/systemtests.properties";
    private static Properties properties = null;

    public static final String PKCS11_LIBRARY = "pkcs11.library";
    public static final String PKCS11_SLOT_PIN = "pkcs11.slotpin";
    public static final String PKCS11_SECURITY_PROVIDER = "pkcs11.provider";
    public static final String PKCS11_SLOT_TYPE = "pkcs11.slottype"; 
    public static final String PKCS11_SLOT_VALUE = "pkcs11.slottypevalue"; 

    private static final String UTIMACO_PKCS11_LINUX_LIB = "/etc/utimaco/libcs2_pkcs11.so";
    private static final String UTIMACO_PKCS11_WINDOWS_LIB = "C:/Program Files/Utimaco/SafeGuard CryptoServer/Lib/cs2_pkcs11.dll";
    private static final String LUNASA_PKCS11_LINUX_LIB = "/usr/lunasa/lib/libCryptoki2_64.so";
    private static final String LUNASA_PKCS11_LINUX32_LIB = "/usr/lunasa/lib/libCryptoki2.so";
    private static final String PROTECTSERVER_PKCS11_LINUX_LIB = "/opt/PTK/lib/libcryptoki.so"; // this symlink is set by safeNet-install.sh->"5 Set the default cryptoki and/or hsm link". Use it instead of symlinking manually.
    private static final String PROTECTSERVER_PKCS11_LINUX64_LIB = "/opt/ETcpsdk/lib/linux-x86_64/libcryptoki.so";
    private static final String PROTECTSERVER_PKCS11_LINUX32_LIB = "/opt/ETcpsdk/lib/linux-i386/libcryptoki.so";
    private static final String PROTECTSERVER_PKCS11_WINDOWS_LIB = "C:/Program Files/SafeNet/ProtectToolkit C SDK/bin/sw/cryptoki.dll";

    
    public static String getHSMProvider() {
        final File utimacoCSLinux = new File(UTIMACO_PKCS11_LINUX_LIB);
        final File utimacoCSWindows = new File(UTIMACO_PKCS11_WINDOWS_LIB);
        final File lunaSALinux64 = new File(LUNASA_PKCS11_LINUX_LIB);
        final File lunaSALinux32 = new File(LUNASA_PKCS11_LINUX32_LIB);
        final File protectServerLinux = new File(PROTECTSERVER_PKCS11_LINUX_LIB);
        final File protectServerLinux64 = new File(PROTECTSERVER_PKCS11_LINUX64_LIB);
        final File protectServerLinux32 = new File(PROTECTSERVER_PKCS11_LINUX32_LIB);
        final File protectServerWindows = new File(PROTECTSERVER_PKCS11_WINDOWS_LIB);
        String ret = null;
        if (utimacoCSLinux.exists()) {
            ret = "SunPKCS11-libcs2_pkcs11.so-slot1";
        } else if (utimacoCSWindows.exists()) {
            ret = "SunPKCS11-cs2_pkcs11.dll-slot1";
        } else if (lunaSALinux64.exists()) {
            ret = "SunPKCS11-libCryptoki2_64.so-slot1";
        } else if (lunaSALinux32.exists()) {
            ret = "SunPKCS11-libCryptoki2.so-slot1";
        } else if ( protectServerLinux32.exists() || protectServerLinux64.exists() ||  protectServerLinux.exists()) {
            ret = "SunPKCS11-libcryptoki.so-slot1";
        } else if (protectServerWindows.exists()) {
            ret = "SunPKCS11-cryptoki.dll-slot1";
        }
        // Override auto-detected properties if configuration exists
        ret = getSystemTestsProperties().getProperty(PKCS11_SECURITY_PROVIDER, ret);
        if (log.isDebugEnabled()) {
            log.debug("getHSMProvider: "+ret);
        }
        return ret;
    }
    
    public static String getHSMLibrary() {
        final File utimacoCSLinux = new File(UTIMACO_PKCS11_LINUX_LIB);
        final File utimacoCSWindows = new File(UTIMACO_PKCS11_WINDOWS_LIB);
        final File lunaSALinux64 = new File(LUNASA_PKCS11_LINUX_LIB);
        final File lunaSALinux32 = new File(LUNASA_PKCS11_LINUX32_LIB);
        final File protectServerLinux = new File(PROTECTSERVER_PKCS11_LINUX_LIB);
        final File protectServerLinux64 = new File(PROTECTSERVER_PKCS11_LINUX64_LIB);
        final File protectServerLinux32 = new File(PROTECTSERVER_PKCS11_LINUX32_LIB);
        final File protectServerWindows = new File(PROTECTSERVER_PKCS11_WINDOWS_LIB);
        String ret = null;
        if (utimacoCSLinux.exists()) {
            ret = utimacoCSLinux.getAbsolutePath();
        } else if (utimacoCSWindows.exists()) {
            ret = utimacoCSWindows.getAbsolutePath();
        } else if (lunaSALinux64.exists()) {
            ret = lunaSALinux64.getAbsolutePath();
        } else if (lunaSALinux32.exists()) {
            ret = lunaSALinux32.getAbsolutePath();
        } else if (protectServerLinux64.exists()) {
            ret = protectServerLinux64.getAbsolutePath();
        } else if (protectServerLinux32.exists()) {
            ret = protectServerLinux32.getAbsolutePath();
        } else if (protectServerLinux.exists()) {
            ret = protectServerLinux.getAbsolutePath();
        } else if (protectServerWindows.exists()) {
            ret = protectServerWindows.getAbsolutePath();
        }
        // Override auto-detected properties if configuration exists
        ret = getSystemTestsProperties().getProperty(PKCS11_LIBRARY, ret);
        if (log.isDebugEnabled()) {
            log.debug("getHSMLibrary: "+ret);
        }
        return ret;
    }

    public static String getPkcs11SlotValue(final String defaultValue) {
        final String ret = getSystemTestsProperties().getProperty(PKCS11_SLOT_VALUE, defaultValue);
        if (log.isDebugEnabled()) {
            log.debug("PKCS11_SLOT_VALUE: "+ret);
        }
        return ret;
    }

    public static Pkcs11SlotLabelType getPkcs11SlotType(final String defaultValue) {
        final Pkcs11SlotLabelType ret = Pkcs11SlotLabelType.getFromKey(getSystemTestsProperties().getProperty(PKCS11_SLOT_TYPE, defaultValue));
        if (log.isDebugEnabled()) {
            log.debug("PKCS11_SLOT_TYPE: "+ret.getKey());
        }
        return ret;
    }

    public static String getPkcs11SlotPin(String defaultValue) {
        final String ret = getSystemTestsProperties().getProperty(PKCS11_SLOT_PIN, defaultValue);
        if (log.isDebugEnabled()) {
            log.debug("PKCS11_SLOT_PIN: "+ret);
        }
        return ret;
    }

    /** @return properties defined in systemtests.properties for override of non-default environments. See also org.cesecore.SystemTestsConfiguration. */
    private static Properties getSystemTestsProperties() {
        if (properties==null) {
            properties = new Properties();
            try {
                final InputStream is = PKCS11TestUtils.class.getResourceAsStream(PROPERTYFILE);
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
}
