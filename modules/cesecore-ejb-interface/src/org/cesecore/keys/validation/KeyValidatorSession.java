/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.validation;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * Interface for key validator operations.
 *
 * @version $Id$
 */
public interface KeyValidatorSession {
    
    /**
     * Gets a key validator by cache or database.
     * 
     * @param id the identifier of a validator
     * 
     * @return a BaseKeyValidator or null if a key validator with the given id does not exist. Uses cache to get the object as quickly as possible.
     *         
     */
    Validator getValidator(int id);

    /**
     * Gets the name of the key validator with the given id.
     * 
     * @return the name of the key validator with the given id or null if none was found.
     */
    String getKeyValidatorName(int id);

    /**
     * Adds a key validator to the database.
     * 
     * @param admin AuthenticationToken of admin
     * @param validator the key validator to add
     * @return the key validator ID as added
     * 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_keyvalidator
     * @throws KeyValidatorExistsException if key validator already exists.
     */
    int addKeyValidator(AuthenticationToken admin, Validator validator) throws AuthorizationDeniedException, KeyValidatorExistsException;

    /** 
     * Updates the key validator with the given name.
     *  
     * @param admin AuthenticationToken of administrator.
     * @param validator the key validator to be modified.
     * 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_keyvalidator
     * @throws KeyValidatorDoesntExistsException if there's no key validator with the given name.
     * 
     * */
    void changeKeyValidator(AuthenticationToken admin, Validator validator)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException;

    /** Removes the key validator data if it is not referenced by a CA.
     * If the validatorId does not exist, the method returns without doing anything.
     * 
     * @param admin AuthenticationToken of admin.
     * @param validatorId the ID of the validator to remove
     * 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_keyvalidators
     * @throws CouldNotRemoveKeyValidatorException if the key validator is referenced by other objects.
     */
    void removeKeyValidator(final AuthenticationToken admin, final int validatorId)
            throws AuthorizationDeniedException, CouldNotRemoveKeyValidatorException;

    /** Removes the key validator data equal if it is not referenced by a CA.
     * If the validatorId does not exist, the method returns without doing anything.
     * 
     * @param admin AuthenticationToken of admin.
     * @param validatorName the name of the validator to remove
     * 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_keyvalidators
     * @throws CouldNotRemoveKeyValidatorException if the key validator is referenced by other objects.
     */
    void removeKeyValidator(AuthenticationToken admin, String validatorName) 
            throws AuthorizationDeniedException, CouldNotRemoveKeyValidatorException;

    /**
     * Flushes the key validators cache to ensure that next time they are read from database.
     */
    void flushKeyValidatorCache();
}
