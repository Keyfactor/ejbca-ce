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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import java.util.Properties;

/** 
 * Session bean to handle global configuration and such.
 */
public interface GlobalConfigurationSession {

    /**
     * Retrieves a copy of the {@link ConfigurationBase} object from the cache with the specified configuration ID. If
     * there is no such object in the cache, or if the object in the cache has expired, it is fetched from
     * the database and the cache is updated.
     *
     * <p>If no such object with the specified configuration ID could be found, <code>null</code> is returned.
     *
     * <p>To make sure the object is loaded from the database, you may invoke {@link #flushConfigurationCache(String)}
     * before calling this method.
     * @param configID the configuration ID of the object to return,
     *                        e.g. {@link org.ejbca.config.GlobalConfiguration#GLOBAL_CONFIGURATION_ID}.
     * @return a copy from the cache, or a copy from the database, if the copy in the cache was stale or missing.
     */
    ConfigurationBase getCachedConfiguration(String configID);

    /** Clear and load global configuration cache. */
    void flushConfigurationCache(String configID);
    
    /** @return all currently used properties (configured in conf/*.properties.
     * Required admin access to '/' to dump these properties. 
     */
    Properties getAllProperties(AuthenticationToken admin, String configID) throws AuthorizationDeniedException;
    
    /** Saves the GlobalConfiguration. 
    *
    * @param authenticationToken an authentication token
    * @param globconf the new Configuration
    * 
    * @throws AuthorizationDeniedException if user was not authorized to edit the specific configuration
    * @see GlobalConfigurationSessionBean#checkAuthorization
    */
    void saveConfiguration(AuthenticationToken authenticationToken, ConfigurationBase conf) throws AuthorizationDeniedException;

    /** Saves the GlobalConfiguration and checks whether root access is enabled for the user. 
    *
    * @param authenticationToken an authentication token
    * @param globconf the new Configuration
    * 
    * @throws AuthorizationDeniedException if user was not authorized to edit the specific configuration
    * @see GlobalConfigurationSessionBean#checkAuthorization
    */
    void saveConfigurationWithRootAccessCheck(AuthenticationToken authenticationToken, ConfigurationBase conf) throws AuthorizationDeniedException;
}
