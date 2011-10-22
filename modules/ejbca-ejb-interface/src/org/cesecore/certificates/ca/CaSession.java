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

import java.util.Collection;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.IllegalCryptoTokenException;

/*! \mainpage The CESeCore project
*
* \section section1 Heading towards Common Criteria certification
*
* In order to make the CESeCore security core publicly available for
* integration in numerous security based applications, the CESeCore
* project aims to realize a CESeCore Common Criteria EAL4+
* certification.
*
* \section section2 Reusable Java library
*
* Taking on the form of a common security function Java library, the
* CESeCore security core will provide a reusable base for implementing
* third-party trustworthy systems. The ready-made CESeCore library
* simplifies development of secure software, and allows for Common
* Criteria certification to be easily extended to any related product
* or service.
*
* \section section3 Integrator friendly
*
* CESeCore integrators will be able to correct, improve and extend their
* applications at any time - without the need to perform frequent system
* re-evaluations, nor perform continous checks of the security functions
* implemented by the security core (including features like digital
signature
* creation/validation, digital certificate and CRLs creation, key management
* and maintenance of a secure audit log).
*/

/**
 * CRUD bean for creating, removing and retrieving CAs.
 * 
 * Based on EJBCA version: CaSession.java 10428 2010-11-11 16:45:12Z anatom
 * 
 * @version $Id$
 */
public interface CaSession {

    /** Adds a CA to the database 
     * 
     * @param admin AuthenticationToken of admin
     * @param ca the CA to add
     * @throws CAExistsException if CA already exists
     * @throws AuthorizationDeniedException if not authorized to add CA
     */
    public void addCA(AuthenticationToken admin, CA ca) throws CAExistsException, AuthorizationDeniedException, IllegalCryptoTokenException;
    
    /** Changes a CA in the database. Can change mostly everything except caid, caname and subject DN. When editing a CA the CA token will usually be taken off line.
     * So you need to activate the CA token after editing, if auto-activation of the CA token is not enabled. 
     * 
     * @param admin AuthenticationToken of admin
     * @param cainfo the CAInfo to change values of the CA
     * @throws CADoesntExistsException
     * @throws AuthorizationDeniedException
     * @throws IllegalCryptoTokenException if the CA token is not proper
     */
    public void editCA(final AuthenticationToken admin, final CAInfo cainfo) throws CADoesntExistsException, AuthorizationDeniedException, IllegalCryptoTokenException;

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
     * @param admin AuthenticationToken of admin
     * @return a Collection<Integer> of available CA id's
     */
    public Collection<Integer> getAvailableCAs(AuthenticationToken admin);
    
    /**
     * Method returning names of all CA's available to the system that the
     * administrator is authorized to i.e. not having status "external" or
     * "waiting for certificate response"
     * 
     * @param admin AuthenticationToken of admin
     * @return a Collection<String> of available CA names
     */
    public Collection<String> getAvailableCANames(final AuthenticationToken admin);

    /**
     * Returns a value object containing non-sensitive information about a CA
     * give it's name.
     * 
     * @param admin administrator calling the method
     * @param name human readable name of CA
     * @return CAInfo value object, never null
     * @throws CADoesntExistsException if CA with caid does not exist
     * @throws AuthorizationDeniedException if admin not authorized to CA 
     */
    public CAInfo getCAInfo(AuthenticationToken admin, String name) throws CADoesntExistsException, AuthorizationDeniedException;

    /**
     * Returns a value object containing non-sensitive information about a CA
     * give it's name.
     * 
     * @param admin administrator calling the method
     * @param caid numerical unique id of CA
     * @return CAInfo value object, never null
     * @throws CADoesntExistsException if CA with caid does not exist
     * @throws AuthorizationDeniedException if admin not authorized to CA 
     */
    public CAInfo getCAInfo(AuthenticationToken admin, int caid) throws CADoesntExistsException, AuthorizationDeniedException;

    /**
     * Returns a value object containing non-sensitive information about a CA
     * give it's name. This method has the option of doing a signature test with the CAs token before returning the CAInfo object,
     * the CAInfo token status is updated with the result of the signature test. This makes sure we don't read any cached value, or that the CA token went off-line 
     * since we last used it.
     * 
     * @param admin administrator calling the method
     * @param caid numerical unique id of CA
     * @param doSignTest true if a signature operation with the CA token should be performed when getting the CA info
     * @return CAInfo value object, never null
     * @throws CADoesntExistsException if CA with caid does not exist
     * @throws AuthorizationDeniedException if admin not authorized to CA 
     */
    public CAInfo getCAInfo(AuthenticationToken admin, int caid, boolean doSignTest) throws CADoesntExistsException, AuthorizationDeniedException;

    /**
     * Method used to remove a CA from the system. You should first check that
     * the CA isn't used by any EndEntity, Profile or AccessRule before it is
     * removed. CADataHandler for example makes this check. 
     * Should be used with care. If any certificate has been created with the CA use revokeCA
     * instead and don't remove it.
     * 
     * @param admin AuthenticationToken of admin
     * @param caid numerical unique id of CA
     * 
     * If the CA does not exist, nothing happens the method return silently.
     * @throws AuthorizationDeniedException if not authorized to remove CA
     */
    public void removeCA(AuthenticationToken admin, int caid) throws AuthorizationDeniedException;

    /**
     * Renames the short name of CA (used in administrators interfaces). 
     * This name does not have to be the same as SubjectDN and is only used for reference.
     * 
     * @param admin AuthenticationToken of admin
     * @param oldname the name of the CA to rename
     * @param newname the new name of the CA
     * 
     * @throws CAExistsException if the CA with newname already exists
     * @throws CADoesntExistsException if the CA with oldname does not exist
     * @throws AuthorizationDeniedException if not authorized to rename CA
     */
    public void renameCA(AuthenticationToken admin, String oldname, String newname) throws CAExistsException, CADoesntExistsException, AuthorizationDeniedException;
}
