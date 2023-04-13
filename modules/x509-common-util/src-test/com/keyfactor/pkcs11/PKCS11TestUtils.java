/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons                                                    *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.pkcs11;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

import com.keyfactor.util.keys.token.pkcs11.Pkcs11SlotLabelType;

/**
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
    private static final String PKCS11_TOKEN_NUMBER = "pkcs11.token_number";
    private static final String PKCS11_TOKEN_INDEX = "pkcs11.token_index";
    private static final String PKCS11_TOKEN_LABEL = "pkcs11.token_label";

    private static final String UTIMACO_PKCS11_LINUX_LIB = "/etc/utimaco/libcs2_pkcs11.so";
    private static final String UTIMACO_PKCS11_WINDOWS_LIB = "C:/Program Files/Utimaco/SafeGuard CryptoServer/Lib/cs2_pkcs11.dll";
    private static final String LUNASA_PKCS11_LINUX_LIB = "/usr/lunasa/lib/libCryptoki2_64.so";
    private static final String LUNASA_PKCS11_LINUX32_LIB = "/usr/lunasa/lib/libCryptoki2.so";
    private static final String PROTECTSERVER_PKCS11_LINUX_LIB = "/opt/PTK/lib/libcryptoki.so"; // this symlink is set by safeNet-install.sh->"5 Set the default cryptoki and/or hsm link". Use it instead of symlinking manually.
    private static final String PROTECTSERVER_PKCS11_LINUX64_LIB = "/opt/ETcpsdk/lib/linux-x86_64/libcryptoki.so";
    private static final String PROTECTSERVER_PKCS11_LINUX32_LIB = "/opt/ETcpsdk/lib/linux-i386/libcryptoki.so";
    private static final String PROTECTSERVER_PKCS11_WINDOWS_LIB = "C:/Program Files/SafeNet/ProtectToolkit C SDK/bin/sw/cryptoki.dll";

    public static final String RSA_TEST_KEY_1 = "rsatest00001";
    public static final String RSA_TEST_KEY_2 = "rsatest00002";
    public static final String RSA_TEST_KEY_3 = "rsatest00003";
    public static final String ECC_TEST_KEY_1 = "ecctest00001";
    public static final String ECC_TEST_KEY_2 = "ecctest00002";
    public static final String ECC_TEST_KEY_3 = "ecctest00003";
    public static final String DSA_TEST_KEY_1 = "dsatest00001";
    public static final String DSA_TEST_KEY_2 = "dsatest00002";
    public static final String DSA_TEST_KEY_3 = "dsatest00003";
    
    public static final String NON_EXISTING_KEY = "sdkfjhsdkfjhsd777";
    
    public static final String KEY_SIZE_1024 = "1024";
    public static final String KEY_SIZE_2048 = "2048";
    
    public static final String WRONG_PIN = "gfhf56564";
    
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
        ret = StringUtils.trim(getSystemTestsProperties().getProperty(PKCS11_SECURITY_PROVIDER, ret));
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
        ret = StringUtils.trim(getSystemTestsProperties().getProperty(PKCS11_LIBRARY, ret));
        if (log.isDebugEnabled()) {
            log.debug("getHSMLibrary: "+ret);
        }
        return ret;
    }
    
    /**
     * Returns the configured PKCS#11 slot/token type as a string. The default is "1", if not configured.
     */
    public static String getPkcs11SlotValue() {
        return getPkcs11SlotValue("1");
    }

    /**
     * Returns the configured PKCS#11 slot/token type as a string, or the given default value if not configured.
     * <p>
     * <strong>Note:</strong> If the user has configured a different value in systemtests.properties, then that will be returned. Using this method can result in fragile tests.
     */
    public static String getPkcs11SlotValue(String defaultValue) {
        final String ret = getSystemTestsProperties().getProperty(PKCS11_SLOT_VALUE, defaultValue).trim();
        if (log.isDebugEnabled()) {
            log.debug("PKCS11_SLOT_VALUE: "+ret);
        }
        return ret;
    }

    /**
     * Returns the configured PKCS#11 slot/token type. The default is Pkcs11SlotLabelType.SLOT_NUMBER
     * 
     * @return A Pkcs11SlotLabelType enum value
     */
    public static Pkcs11SlotLabelType getPkcs11SlotType() {
        final String defaultValue = Pkcs11SlotLabelType.SLOT_NUMBER.getKey();
        final String propertyValue = getSystemTestsProperties().getProperty(PKCS11_SLOT_TYPE, defaultValue);
        final Pkcs11SlotLabelType ret = Pkcs11SlotLabelType.getFromKey(propertyValue.trim());
        if (log.isDebugEnabled()) {
            log.debug("PKCS11_SLOT_TYPE: "+ret.getKey());
        }
        return ret;
    }

    /** Returns the configured PKCS#11 slot/token PIN as a string. The default is "userpin1", if not configured. */
    public static String getPkcs11SlotPin() {
        final String ret = getSystemTestsProperties().getProperty(PKCS11_SLOT_PIN, "userpin1").trim();
        if (log.isDebugEnabled()) {
            log.debug("PKCS11_SLOT_PIN: "+ret);
        }
        return ret;
    }
    
    /** Returns the token number for the configured token, or null if not configured. Use in tests that require specifically a token number. */
    public static String getPkcs11TokenNumber() {
        final String ret = StringUtils.trimToNull(getSystemTestsProperties().getProperty(PKCS11_TOKEN_NUMBER, null));
        if (log.isDebugEnabled()) {
            log.debug("PKCS11_TOKEN_NUMBER: "+ret);
        }
        return ret;
    }
    
    /** Returns the token index for the configured token, or null if not configured. Use in tests that require specifically a token index. */
    public static String getPkcs11TokenIndex() {
        final String ret = StringUtils.trimToNull(getSystemTestsProperties().getProperty(PKCS11_TOKEN_INDEX, null));
        if (log.isDebugEnabled()) {
            log.debug("PKCS11_TOKEN_INDEX: "+ret);
        }
        return ret;
    }
    
    /** Returns the token label for the configured token, or null if not configured. Use in tests that require specifically a token label. */
    public static String getPkcs11TokenLabel() {
        final String ret = StringUtils.trimToNull(getSystemTestsProperties().getProperty(PKCS11_TOKEN_LABEL, null));
        if (log.isDebugEnabled()) {
            log.debug("PKCS11_TOKEN_LABEL: "+ret);
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
