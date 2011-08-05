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

import javax.ejb.Remote;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.config.GlobalConfiguration;

/**
 * Remote interface for RaAdminSession.
 * @version $Id$
 */
@Remote
public interface GlobalConfigurationSessionRemote extends GlobalConfigurationSession {

    /** 
     * Saves the GlobalConfiguration but not when in production mode. 
     */
    void saveGlobalConfigurationRemote(AuthenticationToken admin, GlobalConfiguration globconf);

    /**
     * Sets the value for the setting IssueHardwareTokens. This is used by the 
     * CLI command initializehardtokenissuing and therefor needs remote 
     * access.
     * @param admin The administrator.
     * @param value The value to set.
     */
    void setSettingIssueHardwareTokens(AuthenticationToken admin, boolean value);
	
}
