/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.util.keys;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;

import org.apache.log4j.Logger;

/**
 *
 */
public class X509KeyTools {

    private static final Logger log = Logger.getLogger(X509KeyTools.class);

    /**
     * Detect if "Unlimited Strength" Policy files has bean properly installed.
     * 
     * @return true if key strength is limited
     */
    public static boolean isUsingExportableCryptography() {
        boolean returnValue = true;
        try {
            final int keylen = Cipher.getMaxAllowedKeyLength("DES");
            if (log.isDebugEnabled()) {
                log.debug("MaxAllowedKeyLength for DES is: "+keylen);
            }
            if ( keylen == Integer.MAX_VALUE ) {
                returnValue = false;
            }
        } catch (NoSuchAlgorithmException e) {
            // NOPMD
        }
        return returnValue;
    }
}
