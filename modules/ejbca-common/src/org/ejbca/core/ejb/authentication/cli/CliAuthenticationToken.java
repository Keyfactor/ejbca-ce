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
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.user.AccessUserAspect;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.ejbca.core.ejb.authentication.cli.exception.UninitializedCliAuthenticationTokenException;
import org.ejbca.util.crypto.BCrypt;
import org.ejbca.util.crypto.CryptoTools;
import org.ejbca.util.crypto.SupportedPasswordHashAlgorithm;

/**
 * This authentication token is used for authentication from the CLI. Its security features are described in CliAuthenticationTokenReferenceRegistry
 * 
 * 
 * @version $Id$
 */
public class CliAuthenticationToken extends AuthenticationToken {

    public static final String TOKEN_TYPE = "CliAuthenticationToken";
    
    private static final long serialVersionUID = -3942437717641924829L;

    private final long referenceNumber;
    private final String userName;
    private final SupportedPasswordHashAlgorithm hashAlgorithm;
    // In case the password was hashed using BCrypt, we need to supply the hash in order to recreate it.
    private String passwordSalt;
    private final String sha1Salt;
    private String sha1Hash;

    private transient boolean isVerified = false;

    /**
     * 
     * 
     * @param principal a UsernamePrincipal representing a user name.
     * @param passwordHash a hashed password.
     * @param referenceId the reference ID of this token.
     * @param hashAlgorithm the hash algorithm used to produce the password hash. This will be needed in order to reproduce the sha1Hash on the client
     *            side.
     */
    public CliAuthenticationToken(final UsernamePrincipal principal, final String passwordHash, final String sha1Salt, final long referenceId,
            final SupportedPasswordHashAlgorithm hashAlgorithm) {
        super(new HashSet<Principal>() {
            private static final long serialVersionUID = 5868667272584423392L;
            {
                add(principal);
            }
        }, null);
        this.referenceNumber = referenceId;
        this.userName = principal.getName();
        this.hashAlgorithm = hashAlgorithm;
        this.sha1Salt = sha1Salt;
        if (passwordHash != null) {
            this.sha1Hash = generateSha1Hash(passwordHash, referenceId);

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
            this.sha1Hash = null;
            this.passwordSalt = null;
        }

    }

    /**
     * Construct a SHA1 hash from the concatenated password hash and reference id.
     * 
     * @param passwordHash
     * @param referenceId
     * @return
     */
    private String generateSha1Hash(final String passwordHash, final Long referenceId) {
        String concactenatedInput = passwordHash.concat(referenceId.toString());
        switch (hashAlgorithm) {
        case SHA1_BCRYPT:
            return BCrypt.hashpw(concactenatedInput, sha1Salt);
        case SHA1_OLD:
        default:
            return CryptoTools.makeOldPasswordHash(concactenatedInput);
        }
    }

    @Override
    public boolean matches(AccessUserAspect accessUser) throws AuthenticationFailedException {
        
        /*
         * We just have to verify once, so that the same token can be used sequentially within EJBCA. 
         */
        if (sha1Hash == null) {
            throw new UninitializedCliAuthenticationTokenException("CliAuthenticationToken was matched without shared secret being set.");
        }
        if (isVerified) {
            return true;
        } else {
            if (matchIdentity(accessUser)) {
                if (!CliAuthenticationTokenReferenceRegistry.INSTANCE.verifySha1Hash(referenceNumber, sha1Hash)) {
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
    public boolean matchIdentity(AccessUserAspect accessUser) {
        return matchTokenType(accessUser.getTokenType()) && userName.equals(accessUser.getMatchValue());
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
        return sha1Hash;
    }

    public void setSha1HashFromHashedPassword(String hashedPassword) {
        sha1Hash = generateSha1Hash(hashedPassword, referenceNumber);
    }

    /**
     * Sets the SHA1 hash using the clear text password and the same salt supplied when this token was created (in the BCrypt version).
     * 
     * @param cleartextPassword The password in cleartext. It will be hashed within this method.
     */
    public void setSha1HashFromCleartextPassword(String cleartextPassword) {
        String hashedPassword;
        switch (hashAlgorithm) {
        case SHA1_BCRYPT:
            hashedPassword = BCrypt.hashpw(cleartextPassword, passwordSalt);
            break;
        case SHA1_OLD:
        default:
            hashedPassword = CryptoTools.makeOldPasswordHash(cleartextPassword);
            break;
        }
        setSha1HashFromHashedPassword(hashedPassword);
    }

    /**
     * @param sha1Hash the sha1Hash to set
     */
    public void setSha1Hash(String sha1Hash) {
        this.sha1Hash = sha1Hash;
    }

    /**
     * Note that this clone method will return a CliAuthenticationToken which will *not* contain the SHA1 hash.
     */
    @Override
    public CliAuthenticationToken clone() {
        CliAuthenticationToken clone = new CliAuthenticationToken(new UsernamePrincipal(userName), null, this.sha1Salt, this.referenceNumber,
                hashAlgorithm);
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
        result = prime * result + ((sha1Hash == null) ? 0 : sha1Hash.hashCode());
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
        if (sha1Hash == null) {
            if (other.sha1Hash != null) {
                return false;
            }
        } else if (!sha1Hash.equals(other.sha1Hash)) {
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

    public SupportedPasswordHashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
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
    public boolean matchTokenType(String tokenType) {
        return tokenType.equals(TOKEN_TYPE);
    }

    @Override
    public AccessMatchValue getDefaultMatchValue() {   
        return CliUserAccessMatchValue.USERNAME;
    }

    @Override
    public AccessMatchValue getMatchValueFromDatabaseValue(Integer databaseValue) {     
        if (databaseValue.intValue() != CliUserAccessMatchValue.USERNAME.getNumericValue()) {
            return null;
        } else {
            return CliUserAccessMatchValue.USERNAME;
        }
    }

}
