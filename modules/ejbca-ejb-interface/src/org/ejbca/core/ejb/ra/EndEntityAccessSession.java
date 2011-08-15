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
package org.ejbca.core.ejb.ra;

import java.util.List;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Provides find methods for EndEntityInformation objects. 
 * 
 * @version $Id$
 *
 */
public interface EndEntityAccessSession {

    /**
     * Finds a user by username.
     * 
     * @param admin the administrator performing the action
     * @return EndEntityInformation or null if the user is not found.
     */
    public EndEntityInformation findUser(AuthenticationToken admin, String username) throws AuthorizationDeniedException;

    /**
     * Finds a user by its subject and issuer DN.
     * @return EndEntityInformation or null if the user is not found.
     */
    public EndEntityInformation findUserBySubjectAndIssuerDN(AuthenticationToken admin, String subjectdn, String issuerdn) throws AuthorizationDeniedException;

    /**
     * Finds a user by its subject DN.
     * @return EndEntityInformation or null if the user is not found.
     */
    public EndEntityInformation findUserBySubjectDN(AuthenticationToken admin, String subjectdn) throws AuthorizationDeniedException;

    /**
     * Finds a users by subject email.
     * @return List of all matching EndEntityInformation, never null
     */
    public List<EndEntityInformation> findUserByEmail(AuthenticationToken admin, String email) throws AuthorizationDeniedException;
    
}
