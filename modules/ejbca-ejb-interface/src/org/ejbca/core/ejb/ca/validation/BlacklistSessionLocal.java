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

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.validation.BlacklistEntry;

/**
 * Local interface for public key blacklist operations.
 * 
 * @version $Id$
 */
@Local
public interface BlacklistSessionLocal extends BlacklistSession {

    /**
     * Gets a public key blacklist entry by cache or database.
     * @return a Blacklist or null if a public key blacklist with the given id does not exist. Uses cache to get the object as quickly as possible.
     *         
     */
    BlacklistEntry getBlacklistEntry(int id);

    /**
     * Returns the id of the public key blacklist entry with the given fingerprint.
     * @return the id or 0 if the public key blacklist cannot be found.
     * 
     * @throws BlacklistDoesntExistsException if a custom public key blacklist does not exist.
     */
    int getBlacklistEntryId(String type, String value);

    /**
     * Gets the fingerprint of the public key blacklist entry with the given id.
     * 
     * @return the fingerprint of the public key blacklist with the given id or null if none was found.
     */
    String getBlacklistEntryFingerprint(int id);

    /**
     * Adds a public key blacklist entry to the database. Used for importing and exporting
     * entries from xml-files.
     *
     * @param admin AuthenticationToken of administrator.
     * @param id the public key blacklist is.
     * @param entry the public key blacklist to add.
     *
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_publickeyblacklist
     * @throws BlacklistExistsException if public key blacklist already exists.
     */
    void addBlacklistEntry(AuthenticationToken admin, int id, BlacklistEntry entry)
            throws AuthorizationDeniedException, BlacklistExistsException;

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
     * Flushes the public key blacklist entry cache to ensure that next time they are read from database.
     */
    void flushBlacklistEntryCache();
}
