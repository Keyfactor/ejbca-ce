/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.validation;

import java.util.Map;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * Interface for public key blacklist operations.
 *
 * @version $Id: PublicKeyBlacklistSession.java 21703 2017-04-01 12:00:00Z anjakobs $
 */
public interface PublicKeyBlacklistSession {

    /**
     * Adds a public key blacklist entry to the database.
     * 
     * @param admin AuthenticationToken of administrator
     * @param entry the public key blacklist entry to add
     * @return the public key blacklist ID as added
     * 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_publickeyblacklist
     * @throws PublicKeyBlacklistExistsException if public key blacklist already exists.
     */
    int addPublicKeyBlacklistEntry(AuthenticationToken admin, PublicKeyBlacklistEntry entry)
            throws AuthorizationDeniedException, PublicKeyBlacklistExistsException;
    
    /** Removes the public key blacklist entry.
     * 
     * @param admin AuthenticationToken of administrator.
     * @param fingerprint the fingerprint of the public key blacklist entry to remove.
     * 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_publickeyblacklist
     * @throws PublicKeyBlacklistDoesntExistsException if the public key blacklist does not exist.
     * @throws CouldNotRemovePublicKeyBlacklistException if the public key blacklist could not be removed from datastore.
     */
    void removePublicKeyBlacklistEntry(AuthenticationToken admin, String fingerprint)
            throws AuthorizationDeniedException, PublicKeyBlacklistDoesntExistsException, CouldNotRemovePublicKeyBlacklistException;

    /**
     * Retrieves a Map of all public key blacklist entry ids and fingerprints. 
     * @return the map. 
     */
    Map<Integer, String> getPublicKeyBlacklistEntryIdToFingerprintMap();
    
    /**
     * Gets a public key blacklist entry by cache or database.
     * @param a public key fingerprint, CertTools.createPublicKeyFingerprint
     * @return a PublicKeyBlacklistEntry or null if a public key blacklist entry with the given fingerprint does not exist. Uses cache to get the object as quickly as possible.
     */
    PublicKeyBlacklistEntry getPublicKeyBlacklistEntry(String fingerprint);
}
