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

import java.util.Collection;

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
     * Method returning id's of all CA's available to the system. i.e. not
     * having status "external" or "waiting for certificate response"
     * 
     * @return a Collection (Integer) of available CA id's
     */
    public Collection<Integer> getAvailableCAs();

    /**
     * Method returning id's of all CA's available to the system that the
     * administrator is authorized to i.e. not having status "external" or
     * "waiting for certificate response"
     * 
     * @param admin The administrator
     * @return a Collection<Integer> of available CA id's
     */
    public Collection<Integer> getAvailableCAs(Admin admin);
    
    /**
     * Get the CA object performing the regular authorization check. Checks if
     * the CA has expired or the certificate isn't valid yet and in that case
     * sets the correct CA status.
     * 
     * @param admin the admin retrieving the CA
     * @param caid numerical id of CA (subjectDN.hashCode()) that we search for
     * @return CA value object, never null
     * @throws CADoesntExistsException
     *             if CA with caid does not exist or admin is not authorized to
     *             CA
     */
    public CA getCA(Admin admin, int caid) throws CADoesntExistsException;
  
    /**
     * Get the CA object performing the regular authorization check. Checks if
     * the CA has expired or the certificate isn't valid yet and in that case
     * sets the correct CA status.
     * 
     * @param admin the admin retrieving the CA
     * @param name name of the CA that we're searching for
     * @return CA value object, never null
     * @throws CADoesntExistsException
     *             if CA with caid does not exist or admin is not authorized to
     *             CA
     */
    public CA getCA(Admin admin, String name) throws CADoesntExistsException;
    
    /**
     * Method used to remove a CA from the system.
     * 
     * You should first check that the CA isn't used by any EndEntity, Profile
     * or AccessRule before it is removed. CADataHandler for example makes this
     * check.
     * 
     * Should be used with care. If any certificate has been created with the CA
     * use revokeCA instead and don't remove it.
     */
    public void removeCA(Admin admin, int caid) throws AuthorizationDeniedException;

    /**
     * Renames the name of CA used in administrators web interface. This name
     * doesn't have to be the same as SubjectDN and is only used for reference.
     */
    public void renameCA(Admin admin, String oldname, String newname) throws CAExistsException, AuthorizationDeniedException;
}
