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
package org.ejbca.util.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.config.EjbcaConfiguration;

/**
 * This utility class contains static utility methods related to cryptographic functions.
 * 
 * @version $Id$
 * 
 */
public class CryptoTools {
    
    public static final String BCRYPT_PREFIX = "$2a$";
    
    private static final Logger log = Logger.getLogger(CryptoTools.class);

    /**
     * Creates the hashed password using the bcrypt algorithm, http://www.mindrot.org/projects/jBCrypt/
     */
    public static String makePasswordHash(String password) {
        if (password == null) {
            return null;
        }
        final int rounds = EjbcaConfiguration.getPasswordLogRounds();
        if (rounds > 0 && EjbcaConfiguration.getEffectiveApplicationVersion() > 311) {
            return BCrypt.hashpw(password, BCrypt.gensalt(rounds));
        } else {
            return makeOldPasswordHash(password);
        }
    }

    /**
     * Creates the hashed password using the old hashing, which is a plain SHA1 password
     */
    public static String makeOldPasswordHash(String password) {
        if (password == null) {
            return null;
        }
        String ret = null;
        try {
            final MessageDigest md = MessageDigest.getInstance("SHA1");
            final byte[] pwdhash = md.digest(password.trim().getBytes());
            ret = new String(Hex.encode(pwdhash));
        } catch (NoSuchAlgorithmException e) {
            log.error("SHA1 algorithm not supported.", e);
            throw new Error("SHA1 algorithm not supported.", e);
        }
        return ret;
    }

    /**
     * This method takes a BCrypt-generated password hash and extracts the salt element into cleartext.
     * 
     * @param passwordHash a BCrypt generated password hash.
     * @return the salt in cleartext.
     */
    public static String extractSaltFromPasswordHash(String passwordHash) {
        if(!passwordHash.startsWith(BCRYPT_PREFIX)) {
            throw new IllegalArgumentException("Provided string is not a BCrypt hash.");
        }
        //Locate the third '$', this is where the rounds declaration ends.
        int offset = passwordHash.indexOf('$', BCRYPT_PREFIX.length())+1;
        return passwordHash.substring(0, offset+22);            
    }

}
