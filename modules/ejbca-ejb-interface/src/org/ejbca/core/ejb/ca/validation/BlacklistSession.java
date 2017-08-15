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

package org.ejbca.core.ejb.ca.validation;

import java.util.Map;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.validation.BlacklistEntry;

/**
 * Interface for public key blacklist operations.
 *
 * @version $Id$
 */
public interface BlacklistSession {

    /**
     * Adds a public key blacklist entry to the database.
     * 
     * @param admin AuthenticationToken of administrator
     * @param entry the public key blacklist entry to add
     * @return the public key blacklist ID as added
     * 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_blacklist
     * @throws BlacklistExistsException if public key blacklist already exists.
     */
    int addBlacklistEntry(AuthenticationToken admin, BlacklistEntry entry)
            throws AuthorizationDeniedException, BlacklistExistsException;
    
    /** Removes the public key blacklist entry.
     * 
     * @param admin AuthenticationToken of administrator.
     * @param type the type of blacklist entry to remove.
     * @param value the fingerprint of the blacklist entry to remove.
     * 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_blacklist
     * @throws BlacklistDoesntExistsException if the public key blacklist does not exist.
     */
    void removeBlacklistEntry(AuthenticationToken admin, String type, String value)
            throws AuthorizationDeniedException, BlacklistDoesntExistsException;

    /** 
     * Updates the public key blacklist entry with the given fingerprint.
     *  
     * @param admin AuthenticationToken of administrator.
     * @param entry the public key blacklist to be changed.
     * 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_publickeyblacklist
     * @throws BlacklistDoesntExistsException if there's no public key blacklist with the given fingerprint.
     * 
     * */
    void changeBlacklistEntry(AuthenticationToken admin, BlacklistEntry entry)
            throws AuthorizationDeniedException, BlacklistDoesntExistsException;


    /**
     * Retrieves a Map of all public key blacklist entry ids and fingerprints. 
     * @return the map. 
     */
    Map<Integer, String> getBlacklistEntryIdToValueMap();
    
    /**
     * Gets a public key blacklist entry by cache or database.
     * @param a fingerprint of the public key blacklist entry, BlacklistEntry.createFingerprint 
     * @return a BlacklistEntry or null if a public key blacklist entry with the given fingerprint does not exist. Uses cache to get the object as quickly as possible.
     */
    BlacklistEntry getBlacklistEntry(String type, String value);
}
