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

import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.log.Admin;

/**
 * Local interface for RaAdminSession.
 */
@Local
public interface GlobalConfigurationSessionLocal extends GlobalConfigurationSession {

    /** Saves the GlobalConfiguration. */
    void saveGlobalConfiguration(Admin admin, GlobalConfiguration globconf);
    
}
