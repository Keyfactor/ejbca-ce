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
package org.ejbca.core.ejb.ra.raadmin;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/**
 * @version $Id$
 */
@Local
public interface EndEntityProfileSessionLocal extends EndEntityProfileSession {

    /** Helper method that checks if an administrator is authorized to all CAs present in the profiles "available CAs"
     * 
     * @param admin administrator to check
     * @param profile the profile to check
     * @throws AuthorizationDeniedException if admin is not authorized to one of the available CAs in the profile
     */
    void authorizedToProfileCas(AuthenticationToken admin, EndEntityProfile profile) throws AuthorizationDeniedException;
}
