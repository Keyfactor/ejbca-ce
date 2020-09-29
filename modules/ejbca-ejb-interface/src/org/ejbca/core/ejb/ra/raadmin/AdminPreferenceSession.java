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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ra.raadmin.AdminPreference;

/**
 * Session bean to handle admin preference administration.
 *
 * Saving administrator preferences requires an authentication token that uniquely identifies
 * the administrator (so it will not work with a public access authentication token).
 *
 * Currently the {@link X509CertificateAuthenticationToken} and
 * {@link org.cesecore.authentication.tokens#OAuth2AuthenticationToken OAuth2AuthenticationToken}
 * authentication tokens are supported.
 */
public interface AdminPreferenceSession {
    
    /**
     * Finds the admin preference belonging to the given administrator.
     *
     * @param admin Authentication token of the administrator
     *
     * @return null if the admin does not exist, or is a public access admin.
     */
    AdminPreference getAdminPreference(AuthenticationToken admin);

    /**
     * Adds a admin preference to the database.
     *
     * @param admin An {@link X509CertificateAuthenticationToken} or {@link org.cesecore.authentication.tokens#OAuth2AuthenticationToken OAuth2AuthenticationToken}
     *              representing the admin the preference should cover.
     * @param adminpreference the admin preference to add. 
     *
     * @return  false if admin already exists.
     */
    boolean addAdminPreference(AuthenticationToken admin, AdminPreference adminpreference);

    /**
     * Changes the admin preference in the database.
     *
     * @param admin An {@link X509CertificateAuthenticationToken} or {@link org.cesecore.authentication.tokens#OAuth2AuthenticationToken OAuth2AuthenticationToken}
     *              representing the admin the preference should cover.
     * @param adminpreference the admin preference to add. 
     *
     * @return false if admin does not exist.
     */
    boolean changeAdminPreference(AuthenticationToken admin, AdminPreference adminpreference);

    /**
     * Changes the admin preference in the database without logging. 
     *
     * @param admin An {@link X509CertificateAuthenticationToken} or {@link org.cesecore.authentication.tokens#OAuth2AuthenticationToken OAuth2AuthenticationToken}
     *              representing the admin the preference should cover.
     * @param adminpreference the admin preference to add. 
     *
     * @return false if admin does not exist.
     */
    boolean changeAdminPreferenceNoLog(AuthenticationToken admin, AdminPreference adminpreference);

    /** 
     * Checks if an admin preference exists in the database.
     * Returns false if the authentication token is of an unsupported type
     * (such as a public access token).
     *
     * @param admin Authentication token of the administrator
     *
     * @return true if it exists
     */
    boolean existsAdminPreference(AuthenticationToken admin);

    /**
     * Function that returns the default admin preference.
     *
     * @return the default admin preference. 
     */
    AdminPreference getDefaultAdminPreference();

    /**
     * Function that saves the default admin preference.
     * @param admin An {@link AuthenticationToken} for authorization.
     * @param adminpreference The {@link AdminPreference} to save as default.
     * @throws AuthorizationDeniedException if the local {@link AuthenticationToken} wasn't authorized to /system_functionality/edit_systemconfiguration
     */
    void saveDefaultAdminPreference(AuthenticationToken admin, AdminPreference defaultadminpreference) throws AuthorizationDeniedException;

}
