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

import javax.ejb.Local;

/**
 * Local interface for UserAdminSession.
 */
@Local
public interface UserAdminSessionLocal extends UserAdminSession {
    /**
     * Finds all users and returns the first MAXIMUM_QUERY_ROWCOUNT.
     * 
     * @return Collection of UserDataVO
     */
    public java.util.Collection findAllUsersWithLimit(org.ejbca.core.model.log.Admin admin) throws javax.ejb.FinderException;

}
