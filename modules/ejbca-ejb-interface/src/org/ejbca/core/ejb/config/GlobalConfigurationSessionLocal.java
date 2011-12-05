/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.config;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.config.GlobalConfiguration;

/**
 * Local interface for RaAdminSession.
 * @version $Id$
 */
@Local
public interface GlobalConfigurationSessionLocal extends GlobalConfigurationSession {

    /** Saves the GlobalConfiguration. 
     *
     * @param admin an authentication token
     * @param globconf the new Global Configuration
     * 
     * @throws AuthorizationDeniedException if admin was not authorized to /super_administrator 
     */
    void saveGlobalConfiguration(AuthenticationToken admin, GlobalConfiguration globconf) throws AuthorizationDeniedException;
    
}
