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
package org.ejbca.core.ejb.ca.caadmin;

import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.CAExistsException;
import org.ejbca.core.model.log.Admin;

/**
 * CRUD bean for creating, removing and retrieving CAs.
 * 
 * @version $Id$
 * 
 */
public interface CaSession {

 

    /**
     * Makes sure that no CAs are cached to ensure that we read from database
     * next time we try to access it.
     */
    public void flushCACache();

    /**
     * Get the CA object. Does not perform any authorization check. Checks if
     * the CA has expired or the certificate isn't valid yet and in that case
     * sets the correct CA status.
     * 
     * @param admin
     *            is used for logging
     * @param caid
     *            identifies the CA
     * @return the CA object
     * @throws CADoesntExistsException
     *             if no CA was found
     */
    public CA getCA(Admin admin, int caid) throws CADoesntExistsException;
  
    /**
     * Get the CA object performing the regular authorization check. Checks if
     * the CA has expired or the certificate isn't valid yet and in that case
     * sets the correct CA status.
     * 
     * @param admin
     *            the admin retrieving the CA
     * @param name
     *            name of the CA that we're searching for
     * @return CA value object, never null
     * @throws CADoesntExistsException
     *             if CA with caid does not exist or admin is not authorized to
     *             CA
     */
    public CA getCA(Admin admin, String name) throws CADoesntExistsException;
    
    /**
     * Method used to remove a CA from the system. You should first check that
     * the CA isn't used by any EndEntity, Profile or AccessRule before it is
     * removed. CADataHandler for example makes this check. Should be used with
     * care. If any certificate has been created with the CA use revokeCA
     * instead and don't remove it.
     */
    public void removeCA(Admin admin, int caid) throws AuthorizationDeniedException;

    /**
     * Renames the name of CA used in administrators web interface. This name
     * doesn't have to be the same as SubjectDN and is only used for reference.
     */
    public void renameCA(Admin admin, String oldname, String newname) throws CAExistsException, AuthorizationDeniedException;
}
