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

/** Session bean to handle admin preference administration
 * 
 * @version $Id$
 */
public interface AdminPreferenceSession {
    
    /**
     * Finds the admin preference belonging to a certificate serial number.
     * 
     * @param certificatefingerprint The certificate finger print of the certificate the admin uses as a credential.
     * 
     * @return null if the admin does not exist.
     */
    AdminPreference getAdminPreference(String certificatefingerprint);

    /**
     * Adds a admin preference to the database.
     * 
     * @param admin An {@link X509CertificateAuthenticationToken} representing the admin the preference should 
     *              cover.
     * @param adminpreference the admin preference to add. 
     * 
     *  @return  false if admin already exists.
     */
    boolean addAdminPreference(X509CertificateAuthenticationToken admin, AdminPreference adminpreference);

    /**
     * Changes the admin preference in the database.
     * 
     * @param admin An {@link X509CertificateAuthenticationToken} representing the admin the preference should 
     *              cover.
     * @param adminpreference the admin preference to add. 
     * 
     * @return false if admin does not exist.
     */
    boolean changeAdminPreference(X509CertificateAuthenticationToken admin, AdminPreference adminpreference);

    /**
     * Changes the admin preference in the database without logging. 
     * @param admin An {@link X509CertificateAuthenticationToken} representing the admin the preference should 
     *              cover.
     * @param adminpreference the admin preference to add. 
     * 
     * @return false if admin does not exist.
     */
    boolean changeAdminPreferenceNoLog(X509CertificateAuthenticationToken admin, AdminPreference adminpreference);

    /** 
     * Checks if a admin preference exists in the database. 
     * 
     * @param certificatefingerprint The certificate finger print of the certificate the admin uses as a credential.
     * 
     * @return true if it exists
     */
    boolean existsAdminPreference(String certificatefingerprint);

    /** Function that returns the default admin preference. 
     * 
     * @return the default admin preference. 
     */
    AdminPreference getDefaultAdminPreference();

    /** Function that saves the default admin preference. 
     * @param admin An {@link AuthenticationToken} for authorization.
     * @param adminpreference The {@link AdminPreference} to save as default.
     * @throws AuthorizationDeniedException if the local {@link AuthenticationToken} wasn't authorized to /system_functionality/edit_systemconfiguration
     */
    void saveDefaultAdminPreference(AuthenticationToken admin, AdminPreference defaultadminpreference) throws AuthorizationDeniedException;

}
