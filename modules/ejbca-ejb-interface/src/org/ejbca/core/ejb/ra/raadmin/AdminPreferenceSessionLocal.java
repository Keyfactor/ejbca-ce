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
import java.util.Locale;

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
   
    /**
     * Returns the currently set RA style id for the requested administrator.
     * @param admin AuthenticationToken the administrators holding the preferences.
     * @return RA style id currently set in the RA GUI for the administrator @admin. Null if @admin has no preferences set.
     */
    Integer getCurrentRaStyleId(AuthenticationToken admin);
    
    /**
     * Sets the current RA Style id the requesting administrator.
     * @param current style id for the admin.
     * @param admin is the admin who is saving its preferences in database.
     */
    void setCurrentRaStyleId(int currentStyleId, AuthenticationToken admin);
    
    /**
     * Returns the currently set locale for the requesting administrator.
     * @param admin Administrator saving its data to the database.
     * @return Currently set Locale in the RA GUI for the administrator @admin.
     */
    Locale getCurrentRaLocale(AuthenticationToken admin);
    
    /**
     * Sets the current locale for the requesting administrator.
     * @param current locale for this admin.
     * @param admin is the admin who is saving its preferences in database.
     */
    void setCurrentRaLocale(Locale locale, AuthenticationToken admin);
    
    /**
     * Returns the RaStyleInfo which will be used by the requesting administrator. If there are multiple
     * styles available and no preferences has been set by the administrator, the first one available will be
     * returned.
     * @param admin Authentication token of the requesting administrator
     * @return Preferred RaStyleInfo for the requested administrator. Null if 'Default' (Id 0) is selected or 
     * if no styles are available
     */
    RaStyleInfo getPreferedRaStyleInfo(AuthenticationToken admin);

}
