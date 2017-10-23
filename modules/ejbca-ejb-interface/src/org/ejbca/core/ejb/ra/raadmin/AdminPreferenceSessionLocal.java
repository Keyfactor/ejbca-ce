/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.ra.raadmin;

import java.util.List;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.config.RaStyleInfo;

/**
 * Local interface for RaAdminSession.
 */
@Local
public interface AdminPreferenceSessionLocal extends AdminPreferenceSession {
    
    /**
     * Returns custom RA Styles associated with the role of the requesting administrator. If the administrator has requested
     * styles very recently, the same content will be returned to prevent requests via Peers for for every resource request
     * e.g. in a page load in the RA web.
     * @param authenticationToken of the requesting administrator
     * @return List of custom RA styles available for the requesting administrator
     */
    List<RaStyleInfo> getAvailableRaStyleInfos(AuthenticationToken admin);

}
