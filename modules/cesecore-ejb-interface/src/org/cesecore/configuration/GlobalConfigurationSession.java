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

import java.util.Properties;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.configuration.ConfigurationBase;

/** 
 * Session bean to handle global configuration and such.
 * 
 * @version $Id$
 */
public interface GlobalConfigurationSession {
    
    /**
     * Retrieves the cached GlobalConfiguration. This cache is updated from
     * persistence either by the time specified by
     * {@link #MIN_TIME_BETWEEN_GLOBCONF_UPDATES} or when {@link #flushCache()}
     * is executed. This method should be used in all cases where a quick
     * response isn't necessary, otherwise use {@link #flushCache()}.
     * 
     * @return the cached GlobalConfiguration value.
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
