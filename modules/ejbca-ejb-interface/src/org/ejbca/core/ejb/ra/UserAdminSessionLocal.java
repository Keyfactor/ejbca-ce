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

import java.util.Collection;

import javax.ejb.FinderException;
import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Local interface for UserAdminSession.
 */
@Local
public interface UserAdminSessionLocal extends UserAdminSession {

    /**
     * Finds all users and returns the first MAXIMUM_QUERY_ROWCOUNT.
     * 
     * @return Collection of EndEntityInformation
     */
    public Collection<EndEntityInformation> findAllUsersWithLimit(AuthenticationToken admin) throws FinderException;
    

}
