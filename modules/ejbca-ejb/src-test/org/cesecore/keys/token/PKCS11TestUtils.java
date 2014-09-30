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

import org.apache.log4j.Logger;

/**
 * @version $Id$
 *
 */
public class PKCS11TestUtils {

    private static final Logger log = Logger.getLogger(PKCS11TestUtils.class);
    
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
        if (log.isDebugEnabled()) {
            log.debug("getHSMLibrary: "+ret);
        }
        return ret;
    }
}
