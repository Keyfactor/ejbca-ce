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
package org.ejbca.core.ejb.authentication.cli;

import java.security.Principal;
import java.util.HashSet;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationTokenMetaData;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.user.AccessUserAspect;
import org.ejbca.core.ejb.authentication.cli.exception.UninitializedCliAuthenticationTokenException;
import org.ejbca.util.crypto.BCrypt;
import org.ejbca.util.crypto.CryptoTools;
import org.ejbca.util.crypto.SupportedPasswordHashAlgorithm;

/**
 * This authentication token is used for authentication from the CLI. Its security features are described in CliAuthenticationTokenReferenceRegistry
 * 
 * 
 */
public class CliAuthenticationToken extends AuthenticationToken {

    public static final CliAuthenticationTokenMetaData metaData = new CliAuthenticationTokenMetaData();
    
    private static final long serialVersionUID = -3942437717641924829L;

    private final long referenceNumber;
    private final String userName;
    // In case the password was hashed using BCrypt, we need to supply the hash in order to recreate it.
    private String passwordSalt;
    private final String salt;
    private String hash;

    private transient boolean isVerified = false;
    
    //This value only remains to allow for CLI users back in 5.0
    private final SupportedPasswordHashAlgorithm hashAlgorithm;

    /**
     * 
     * 
     * @param principal a UsernamePrincipal representing a user name.
     * @param passwordHash a hashed password.
     * @param referenceId the reference ID of this token.
     */
    @SuppressWarnings("deprecation")
    public CliAuthenticationToken(final UsernamePrincipal principal, final String passwordHash, final String salt, final long referenceId, final SupportedPasswordHashAlgorithm hashAlgorithm) {
        super(new HashSet<Principal>() {
            private static final long serialVersionUID = 5868667272584423392L;
            {
                add(principal);
            }
        }, null);
        this.referenceNumber = referenceId;
        this.userName = principal.getName();
        this.salt = salt;
        this.hashAlgorithm = hashAlgorithm;
        if (passwordHash != null) {
            this.hash = generateHash(passwordHash, referenceId);
            // The modern BCrypt hash uses a salt, which we have to pass with.
            switch (hashAlgorithm) {
            case SHA1_BCRYPT:
                passwordSalt = CryptoTools.extractSaltFromPasswordHash(passwordHash);
                break;
            case SHA1_OLD:
            default:
                passwordSalt = null;
                break;
            }
        } else {
            this.hash = null;
            this.passwordSalt = null;
        }


    }

    /**
     * Construct a cryptographic hash from the concatenated password hash and reference id.
     * 
     * @param passwordHash
     * @param referenceId
     * @return
     */
    private String generateHash(final String passwordHash, final Long referenceId) {
        String concactenatedInput = passwordHash.concat(referenceId.toString());
        return BCrypt.hashpw(concactenatedInput, salt);

    }

    @Override
    public boolean matches(AccessUserAspect accessUser) throws AuthenticationFailedException {
        /*
         * We just have to verify once, so that the same token can be used sequentially within EJBCA. 
         */
        if (hash == null) {
            throw new UninitializedCliAuthenticationTokenException("CliAuthenticationToken was matched without shared secret being set.");
        }
        if (isVerified) {
            return true;
        } else {
            if (matchTokenType(accessUser.getTokenType()) && userName.equals(accessUser.getMatchValue())) {
                if (!CliAuthenticationTokenReferenceRegistry.INSTANCE.verifySha1Hash(referenceNumber, hash)) {
                    //This is an authentication error
                    throw new AuthenticationFailedException("Incorrect one-time hash was passed with CLI token, most likely due to an incorrect password.");
                } else if (!CliAuthenticationTokenReferenceRegistry.INSTANCE.unregisterToken(referenceNumber)) {
                    // The reference to this token has been used, another authentication error
                    throw new AuthenticationFailedException("The same CLI authentication token was apparently used twice. This is either an implementation error or a replay attack.");
                } else {
                 // The reference to this token hasn't been used.
                    isVerified = true;
                    return true;
                }
            }
        }
        return false;
    }
    
    @Override
    public int getPreferredMatchKey() {
        return CliUserAccessMatchValue.USERNAME.getNumericValue();
    }
    
    /** Returns the username */
    @Override
    public String getPreferredMatchValue() {
        return userName;
    }
   

    /**
     * Returns the reference number, a nonce.
     * 
     * @return the referenceId
     */
    public long getReferenceNumber() {
        return referenceNumber;
    }

    /**
     * This value is a SHA1 hash consisting of the hashed password concactenated with
     * 
     * @return the sha1Hash
     */
    public String getSha1Hash() {
        return hash;
    }

    public void setHashFromHashedPassword(String hashedPassword) {
        hash = generateHash(hashedPassword, referenceNumber);
    }

    /**
     * Sets the SHA1 hash using the clear text password and the same salt supplied when this token was created (in the BCrypt version).
     * 
     * @param cleartextPassword The password in cleartext. It will be hashed within this method.
     */
    public void setHashFromCleartextPassword(String cleartextPassword) {
        String hashedPassword = BCrypt.hashpw(cleartextPassword, passwordSalt);
        setHashFromHashedPassword(hashedPassword);
    }

    /**
     * @param hash the hash to set
     */
    public void setHash(String hash) {
        this.hash = hash;
    }

    /**
     * Note that this clone method will return a CliAuthenticationToken which will *not* contain the SHA1 hash.
     */
    @Override
    public CliAuthenticationToken clone() {
        CliAuthenticationToken clone = new CliAuthenticationToken(new UsernamePrincipal(userName), null, this.salt, this.referenceNumber, this.hashAlgorithm);
        clone.setPasswordSalt(passwordSalt);
        return clone;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 1337;
        int result = 1;
        result = prime * result + (isVerified ? 1231 : 1237);
        result = prime * result + (int) (referenceNumber ^ (referenceNumber >>> 32));
        result = prime * result + ((hash == null) ? 0 : hash.hashCode());
        result = prime * result + ((userName == null) ? 0 : userName.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        CliAuthenticationToken other = (CliAuthenticationToken) obj;
        if (isVerified != other.isVerified) {
            return false;
        }
        if (referenceNumber != other.referenceNumber) {
            return false;
        }
        if (hash == null) {
            if (other.hash != null) {
                return false;
            }
        } else if (!hash.equals(other.hash)) {
            return false;
        }
        if (userName == null) {
            if (other.userName != null) {
                return false;
            }
        } else if (!userName.equals(other.userName)) {
            return false;
        }
        return true;
    }

    /**
     * @return the passwordSalt
     */
    public String getPasswordSalt() {
        return passwordSalt;
    }

    /**
     * @param passwordSalt the passwordSalt to set
     */
    public void setPasswordSalt(String passwordSalt) {
        this.passwordSalt = passwordSalt;
    }

    @Override
    protected String generateUniqueId() {
        return generateUniqueId(isVerified, userName, referenceNumber, hash, salt);
    }

    @Override
    public AuthenticationTokenMetaData getMetaData() {
        return metaData;
    }
}
