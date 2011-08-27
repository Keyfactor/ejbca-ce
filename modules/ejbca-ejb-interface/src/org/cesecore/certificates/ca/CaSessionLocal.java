/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ca;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;

/**
 * Local interface for CaSession
 * 
 * Based on EJCBA version: CaSessionLocal.java 10428 2010-11-11 16:45:12Z anatom
 * 
 * @version $Id: CaSessionLocal.java 406 2011-03-02 11:38:30Z tomas $
 */
@Local
public interface CaSessionLocal extends CaSession {

    /**
     * Makes sure that no CAs are cached to ensure that we read from database
     * next time we try to access it.
     */
    public void flushCACache();

    /**
     * Get the CA object. Does not perform any authorization check. Checks if
     * the CA has expired or the certificate isn't valid yet and in that case
     * sets the correct CA status.
     * NOTE: This method will return a shared CA object from a cache. Not suitable for reading a CA object that you 
     * plan to edit. Use this when you need to use the CA, since it's faster. User getCAForEdit if you want to edit the 
     * CA object and does not want your changes to be overwritten by another thread.
     *
     * @see #getCAForEdit(AuthenticationToken, String)
     * 
     * @param admin AuthenticationToken of admin
     * @param caid identifies the CA
     * @return the CA object
     * @throws CADoesntExistsException if no CA was found
     * @throws AuthorizationDeniedException if not authorized to get CA
     */
    public CA getCA(AuthenticationToken admin, int caid) throws CADoesntExistsException, AuthorizationDeniedException;
  
    /**
     * Get the CA object performing the regular authorization check. Checks if
     * the CA has expired or the certificate isn't valid yet and in that case
     * sets the correct CA status.
     * NOTE: This method will return a shared CA object from a cache. Not suitable for reading a CA object that you 
     * plan to edit. Use this when you need to use the CA, since it's faster. User getCAForEdit if you want to edit the 
     * CA object and does not want your changes to be overwritten by another thread.
     * 
     * @see #getCAForEdit(AuthenticationToken, String)
     * 
     * @param admin AuthenticationToken of admin
     * @param name name of the CA that we are searching for
     * @return CA value object, never null
     * @throws CADoesntExistsException if CA with name does not exist
     * @throws AuthorizationDeniedException if not authorized to get CA
     */
    public CA getCA(AuthenticationToken admin, String name) throws CADoesntExistsException, AuthorizationDeniedException;
    
    /**
     * Get the CA object performing the regular authorization check. Checks if
     * the CA has expired or the certificate isn't valid yet and in that case
     * sets the correct CA status.
     * NOTE: This method will return a new CA object from the database. Not suitable for reading a CA object that you 
     * plan to simply use. Use this when you need to edit the CA object, since it's slower. User getCA if you want to simply use the 
     * CA object and does not need to make edits.
     * 
     * @see #getCA(AuthenticationToken, String)
     * 
     * @param admin AuthenticationToken of admin
     * @param caid identifies the CA
     * @return CA value object, never null
     * @throws CADoesntExistsException if CA with caid does not exist
     * @throws AuthorizationDeniedException if not authorized to get CA
     */
	public CA getCAForEdit(AuthenticationToken admin, int caid) throws CADoesntExistsException, AuthorizationDeniedException;

    /**
     * Get the CA object performing the regular authorization check. Checks if
     * the CA has expired or the certificate isn't valid yet and in that case
     * sets the correct CA status.
     * NOTE: This method will return a new CA object from the database. Not suitable for reading a CA object that you 
     * plan to simply use. Use this when you need to edit the CA object, since it's slower. User getCA if you want to simply use the 
     * CA object and does not need to make edits.
     * 
     * @see #getCA(AuthenticationToken, String)
     * 
     * @param admin AuthenticationToken of admin
     * @param name name of the CA that we are searching for
     * @return CA value object, never null
     * @throws CADoesntExistsException if CA with name does not exist
     * @throws AuthorizationDeniedException if not authorized to get CA
     */
	public CA getCAForEdit(AuthenticationToken admin, String name) throws CADoesntExistsException, AuthorizationDeniedException;

    /** Changes a CA in the database. Can change mostly everything except caid, caname and subject DN. When editing a CA the CA token will usually be taken off line.
     * So you need to activate the CA token after editing, if auto-activation of the CA token is not enabled. 
     * 
     * @param admin AuthenticationToken of admin
     * @param ca the CA to edit
     * @param auditlog if audit logging of the edit should be done or not, not needed if called from other internal methods that already does audit logging.
     * @throws CADoesntExistsException
     * @throws AuthorizationDeniedException
     * @throws CryptoTokenOfflineException if the CA token is to be activated but is off line
     * @throws CryptoTokenAuthenticationFailedException if the CA token is to be activated but the authentication code is wrong
     */
    public void editCA(final AuthenticationToken admin, final CA ca, boolean auditlog) throws CADoesntExistsException, AuthorizationDeniedException, IllegalCryptoTokenException;

}
