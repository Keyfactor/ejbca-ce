/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.authentication.oauth;

import java.util.List;


/**
 * This class is responsible for managing a list of OAuth Keys.
 *
 * @version $Id$
 */
public class OAuthKeyManager {
    private final List<OAuthKeyInfo> oauthKeys;

    /**
     * Create a new OAuth Key manager responsible for a list of keys specified.
     * @param oauthKeys the keys managed by this OAuth Key manager
     */
    public OAuthKeyManager(final List<OAuthKeyInfo> oauthKeys) {
        this.oauthKeys = oauthKeys;
    }

    /**
     * Returns a list of all keys managed by this OAuth Key manager.
     * @return a list of all OAuth Keys
     */
    public List<OAuthKeyInfo> getAllOauthKeys() {
        return oauthKeys;
    }

    /**
     * Add a new OAuth Key to this OAuth Key manager. This method will prevent duplicate keys from being added.
     * @param oauthKey the OAuth Key to add
     * @throws DuplicateOAuthKeyException if the OAuth Key to add is a duplicate according to {@link #canAdd(OAuthKeyInfo)}
     */
    public void addOauthKey(final OAuthKeyInfo oauthKey) {
        if (!canAdd(oauthKey)) {
            throw new DuplicateOAuthKeyException("The OAuth Key " + oauthKey.toString() + " already exists.");
        }
        oauthKeys.add(oauthKey);
    }

    /**
     * Removes an existing OAuth Key from this key manager.
     * @param oauthKey the OAuth Key to remove
     * @throws IllegalArgumentException if the OAuth Key is not managed by this OAuth Key manager
     */
    public void removeOauthKey(final OAuthKeyInfo oauthKey) {
        if (!oauthKeys.contains(oauthKey)) {
            throw new IllegalArgumentException("The OAuth Key " + oauthKey.toString() + " is not managed by this OAuth Key manager.");
        }
        oauthKeys.remove(oauthKey);
    }

    /**
     * Determine whether the OAuth Key given as input can be added to this OAuth Key manager. A OAuth Key cannot be added
     * if any of the following conditions hold for another OAuth Key:
     * <ul>
     *   <li>The other key has an ID identical to the new OAuth Key</li>
     * </ul>
     * @param oauthKey the new OAuth Key to check
     * @return true if the OAuth Key given as input can be added, false otherwise
     */
    public boolean canAdd(final OAuthKeyInfo oauthKey) {
        for (OAuthKeyInfo existing : oauthKeys) {
            final boolean hasSameId = existing.getInternalId() == oauthKey.getInternalId();
            if (hasSameId) {
                return false;
            }
        }
        return true;
    }

    /**
     * Returns the string representation of this object containing
     * the OAuth Keys currently managed by this OAuth Key manager.
     */
    @Override
    public String toString() {
        return "OAuth Keys: " + getAllOauthKeys().toString();
    }
}
