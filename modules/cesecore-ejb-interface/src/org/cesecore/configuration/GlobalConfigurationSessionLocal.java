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
package org.cesecore.configuration;

import java.util.Map;
import java.util.Set;

import jakarta.ejb.Local;

import jakarta.persistence.LockModeType;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * Local interface for GlobalConfigurationSession.
 */
@Local
public interface GlobalConfigurationSessionLocal extends GlobalConfigurationSession {

    /** @return the found entity instance or null if the entity does not exist */
    GlobalConfigurationData findByConfigurationId(String configurationId);

    /** @return the found entity instance or null if the entity does not exist,
     * Allows specifying the lock type to prevent concurrent modifications to a same config  */
    GlobalConfigurationData findByConfigurationId(String configurationId, LockModeType lockModeType, Map<String, Object> dbHints);


    /** @return all registered configuration IDs. */
    Set<String> getIds();
    
    /**
     * Removes a configuration from the database
     *  
     * @param authenticationToken an authentication token
     * @param configurationId the ID of the configuration, i.e. its primary key
     * @throws AuthorizationDeniedException if the administrator was not authorized to the configuration in question
     */
    void removeConfiguration(final AuthenticationToken authenticationToken, final String configurationId) throws AuthorizationDeniedException;
}
