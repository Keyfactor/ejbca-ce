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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * Local interface for CaSession
 * 
 * @version $Id$
 */
@Local
public interface CaSessionLocal extends CaSession {

    /**
     * Returns true if authorized to a CA without performing any logging operations.
     * 
     * @param admin the token to check against.
     * @param caid the ID of the CA in question
     * @return true if the token was authorized.
     */
    boolean authorizedToCANoLogging(final AuthenticationToken admin, final int caid);
    
    /**
     * Returns true if authorized to a CA
     * 
     * @param admin the token to check against.
     * @param caid the ID of the CA in question
     * @return true if the token was authorized.
     */
    boolean authorizedToCA(final AuthenticationToken admin, final int caid);
    
    /**
     * 
     * @return a list of all CAData objects, or an empty list if none were found.
     */
    List<CAData> findAll();
    
    /** @return the found entity instance or null if the entity does not exist */
    CAData findById(final Integer cAId);
    /**
     * @throws CADoesntExistsException if the entity does not exist
     * @return the found entity instance
     */
    CAData findByIdOrThrow(final Integer cAId) throws CADoesntExistsException;
    
    /**
     * @throws javax.persistence.NonUniqueResultException if more than one entity with the name exists
     * @return the found entity instance or null if the entity does not exist
     */
    CAData findByName(final String name);

    /**
     * @throws CADoesntExistsException if the entity does not exist
     * @throws javax.persistence.NonUniqueResultException if more than one entity with the name exists
     * @return the found entity instance
     */
    CAData findByNameOrThrow(final String name) throws CADoesntExistsException;
    
    /**
     * Makes sure that no CAs are cached to ensure that we read from database
     * next time we try to access it.
     */
    void flushCACache();

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
     * @param caid identifies the CA
     * @return the CA object
     * @throws CADoesntExistsException if no CA was found
     * @throws AuthorizationDeniedException if not authorized to get CA
     */
    CA getCA(AuthenticationToken admin, int caid) throws CADoesntExistsException, AuthorizationDeniedException;
  
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
    CA getCA(AuthenticationToken admin, String name) throws CADoesntExistsException, AuthorizationDeniedException;
    
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
    CA getCAForEdit(AuthenticationToken admin, int caid) throws CADoesntExistsException, AuthorizationDeniedException;

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
    CA getCAForEdit(AuthenticationToken admin, String name) throws CADoesntExistsException, AuthorizationDeniedException;

    /** Changes a CA in the database. Can change mostly everything except caid, caname and subject DN. When editing a CA the CA token will usually be taken off line.
     * So you need to activate the CA token after editing, if auto-activation of the CA token is not enabled. 
     * 
     * @param admin AuthenticationToken of admin
     * @param ca the CA to edit
     * @param auditlog if audit logging of the edit should be done or not, not needed if called from other internal methods that already does audit logging.
     * @throws CADoesntExistsException
     * @throws AuthorizationDeniedException
     */
    void editCA(final AuthenticationToken admin, final CA ca, boolean auditlog) throws CADoesntExistsException, AuthorizationDeniedException;

    /**
     * Verify that a CA exists.
     * 
     * @param caid is the id of the CA
     * @throws CADoesntExistsException if the CA is not found
     */
    void verifyExistenceOfCA(int caid) throws CADoesntExistsException;

    /**
     * Returns a HashMap containing mappings of caid (Integer) to CA name
     * (String) of all CAs in the system.
     * 
     * @return HashMap with Integer->String mappings
     */
    HashMap<Integer,String> getCAIdToNameMap();
    
    /**
     * Returns a HashMap containing mappings of caid (Integer) to CA name
     * (String) of all active and uninitialized CAs in the system that the admin is authorized to.
     * 
     * @return HashMap with Integer->String mappings
     */
    Map<Integer, String> getActiveCAIdToNameMap(final AuthenticationToken authenticationToken);

    /**
     * Internal (local only) method for getting CAInfo, to avoid access control logging for
     * internal operations. Tries to find the CA even if the CAId is wrong due to CA certificate
     * DN not being the same as CA DN.
     * 
     * Note! No authorization checks performed in this internal method
     * 
     * @param caid
     *            numerical id of CA (subjectDN.hashCode()) that we search for, or -1 if a name is to be used instead
     * @param name
     *            human readable name of CA, used instead of caid if caid == -1, can be null if caid != -1
     * @param fromCache if we should use the CA cache or return a new, decoupled, instance from the database, to be used when you need
     *             a completely distinct object, for edit, and not a shared cached instance.
     * @return CA value object, never null
     * @throws CADoesntExistsException
     *             if no CA was found
     */
    CAInfo getCAInfoInternal(final int caid, final String name, boolean fromCache) throws CADoesntExistsException;

    /**
     * Internal (local only) method for getting CAInfo, to avoid access control logging for internal operations.
     * 
     * Note! No authorization checks performed in this internal method
     * 
     * @param caid
     *            numerical id of CA (subjectDN.hashCode()) that we search for
     * @return CA value object, never null
     * @throws CADoesntExistsException
     *             if no CA was found
     */
    CAInfo getCAInfoInternal(final int caid) throws CADoesntExistsException;

    /**
     * Internal (local only) method to get the CA object without logging the authorization check.
     * (the auth check is performed though)
     * 
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
    CA getCANoLog(AuthenticationToken admin, int caid) throws CADoesntExistsException, AuthorizationDeniedException;

    /**
     * Local access CRUD method for persisting the CA object to the database and removes any old
     * object with this CA id from the cache.
     * 
     * @return the CA Id
     */
    int mergeCa(CA ca);
    
    /**
     * Checks if at least one CA references a key validator.
     * @param keyValidatorId
     * @return true if there are no references.
     * 
     * @throws AuthorizationDeniedException if not authorized.
     */
    boolean existsKeyValidatorInCAs(int keyValidatorId) throws AuthorizationDeniedException;
}
