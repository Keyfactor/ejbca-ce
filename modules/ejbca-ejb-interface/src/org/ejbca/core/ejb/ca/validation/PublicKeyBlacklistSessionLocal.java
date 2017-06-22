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
import org.ejbca.core.model.ca.validation.PublicKeyBlacklistEntry;

/**
 * Local interface for public key blacklist operations.
 * 
 * @version $Id: PublicKeyBlacklistSessionLocal.java 22019 2017-04-01 12:12:00Z anjakobs $
 */
@Local
public interface PublicKeyBlacklistSessionLocal extends PublicKeyBlacklistSession {

    /**
     * Gets a public key blacklist entry by cache or database.
     * @return a PublicKeyBlacklist or null if a public key blacklist with the given id does not exist. Uses cache to get the object as quickly as possible.
     *         
     */
    PublicKeyBlacklistEntry getPublicKeyBlacklistEntry(int id);

    /**
     * Returns the id of the public key blacklist entry with the given fingerprint.
     * @return the id or 0 if the public key blacklist cannot be found.
     * 
     * @throws PublicKeyBlacklistDoesntExistsException if a custom public key blacklist does not exist.
     */
    int getPublicKeyBlacklistEntryId(String fingerprint);

    /**
     * Gets the fingerprint of the public key blacklist entry with the given id.
     * 
     * @return the fingerprint of the public key blacklist with the given id or null if none was found.
     */
    String getPublicKeyBlacklistEntryFingerprint(int id);

    /**
     * Adds a public key blacklist entry to the database. Used for importing and exporting
     * entries from xml-files.
     *
     * @param admin AuthenticationToken of administrator.
     * @param id the public key blacklist is.
     * @param entry the public key blacklist to add.
     *
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_publickeyblacklist
     * @throws PublicKeyBlacklistExistsException if public key blacklist already exists.
     */
    void addPublicKeyBlacklistEntry(AuthenticationToken admin, int id, PublicKeyBlacklistEntry entry)
            throws AuthorizationDeniedException, PublicKeyBlacklistExistsException;

    /** 
     * Updates the public key blacklist entry with the given fingerprint.
     *  
     * @param admin AuthenticationToken of administrator.
     * @param fingerprint the fingerprint of the public key blacklist entry to change.
     * @param entry the public key blacklist to be added.
     * 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_publickeyblacklist
     * @throws PublicKeyBlacklistDoesntExistsException if there's no public key blacklist with the given fingerprint.
     * 
     * */
    void changePublicKeyBlacklistEntry(AuthenticationToken admin, String fingerprint, PublicKeyBlacklistEntry entry)
            throws AuthorizationDeniedException, PublicKeyBlacklistDoesntExistsException;

    /**
     * Flushes the public key blacklist entry cache to ensure that next time they are read from database.
     */
    void flushPublicKeyBlacklistEntryCache();
}
