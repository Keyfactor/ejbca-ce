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

import java.security.PublicKey;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.zip.ZipException;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Local interface for key validator operations.
 * 
 * @version $Id$
 */
@Local
public interface KeyValidatorSessionLocal extends KeyValidatorSession {

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
     * Retrieves a Map of all key validators.
     * 
     * @return Map of BaseKeyValidator mapped by ID.
     */
    Map<Integer, Validator> getAllKeyValidators();

    /**
     * Retrieves a Map of key validators.
     * @param ids the list of ids.
     * 
     * @return Map of BaseKeyValidator mapped by ID.
     */
    Map<Integer, Validator> getKeyValidatorsById(Collection<Integer> ids);

    /**
     * Retrieves a Map of key validator names. 
     * @return mapping of key validators ids and names. 
     */
    Map<Integer, String> getKeyValidatorIdToNameMap();

    /**
     * Adds a key validator to the database. Used for importing and exporting
     * profiles from xml-files.
     *
     * @param admin AuthenticationToken of administrator.
     * @param validator the key validator to add.
     *
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_keyvalidator
     * @throws KeyValidatorExistsException if key validator already exists.
     */
    void importValidator(AuthenticationToken admin, Validator validator) throws AuthorizationDeniedException, KeyValidatorExistsException;

    /**
     * Imports a list of key validators, stored in separate XML files in the ZIP container.
     * @param authenticationToken an authentication token
     * @param filebuffer a byte array containing a zip file
     * 
     * @return a container object containing lists of the imported and ignored key validator names
     * 
     * @throws AuthorizationDeniedException if not authorized
     * @throws ZipException if the byte array did not contain a zip file
     */
    ValidatorImportResult importKeyValidatorsFromZip(final AuthenticationToken authenticationToken, final byte[] filebuffer)
            throws AuthorizationDeniedException, ZipException;
   
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

    /**
     * Adds a key validator with the same content as the original.
     * 
     * @param admin an authentication token
     * @param the ID of a validator
     * @param newName the name of the clone
     * 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_keyvalidator
     * @throws KeyValidatorDoesntExistsException if key validator does not exist
     * @throws KeyValidatorExistsException if key validator already exists.
     */
    void cloneKeyValidator(final AuthenticationToken admin, final int validatorId, final String newName)
            throws  AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException;
    
    /**
     * Adds a key validator with the same content as the original.
     * 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_keyvalidator
     * @throws KeyValidatorDoesntExistsException if key validator does not exist
     * @throws KeyValidatorExistsException if key validator already exists.
     */
    void cloneKeyValidator(final AuthenticationToken admin, final Validator validator, final String newName)
            throws  AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException;

    /**
     * Renames a key validator or throws an exception.
     * 
     * @param admin an authentication token
     * @param validatorId the ID of the validator to modify
     * @param newName the new name of the validator
     * 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_keyvalidator
     * @throws KeyValidatorDoesntExistsException if key validator does not exist
     * @throws KeyValidatorExistsException if key validator already exists.
     */
    void renameKeyValidator(AuthenticationToken admin, final int validatorId, String newName)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException;
    
    /**
     * Renames a key validator or throws an exception.
     * 
     * @param admin an authentication token
     * @param validator the validator to modify
     * @param newName the new name of the validator
     * 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_keyvalidator
     * @throws KeyValidatorDoesntExistsException if key validator does not exist
     * @throws KeyValidatorExistsException if key validator already exists.
     */
    void renameKeyValidator(final AuthenticationToken admin, final Validator validator, String newName)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException;

    /** Removes the key validator data equal if its referenced by a CA or not.
     * 
     * @param admin AuthenticationToken of admin.
     * @param validatorId the ID of the validator to remove
     * 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_keyvalidators
     * @throws KeyValidatorDoesntExistsException if the key validator does not exist.
     * @throws CouldNotRemoveKeyValidatorException if the key validator is referenced by other objects.
     */
    void removeKeyValidator(final AuthenticationToken admin, final int validatorId)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException, CouldNotRemoveKeyValidatorException;

    /** Retrieves a Collection of id:s (Integer) to authorized key validators. 
     * @param admin the administrator for whom to get the profile ids he/she has access to
     * @param keyValidatorAccessRule an access rule which is required on the key validator in order for it to be returned, for example AccessRulesConstants.CREATE_KEYVALIDATOR to only return profiles for which the admin have create rights
     * @return Collection of end key validator id:s (Integer)
     */
    Collection<Integer> getAuthorizedKeyValidatorIds(final AuthenticationToken admin, String keyValidatorAccessRule);

    /**
     * Validates a key against the key validators which match the filter criteria defined in it and the CA reference to it. 
     * The method is invoked while certificate issuance for user certificates and CA certificates.
     * 
     * @param ca the issuing CA, or CA to be issued in case of a root or sub-ca.
     * @param endEntityInformation the end entity information
     * @param certificateProfile the certificate profile
     * @param notBefore the certificates notBefore validity
     * @param notAfter the certificates notAfter validity
     * @param publicKey the public key of the certificate
     * @return true if all matching key validators could validate the public key successfully. If false #getMessage().size() is greater than 0.
     * @throws KeyValidationException if the key validation failed. If the key validators failed action is set to abort certificate issuance {@link KeyValidationFailedActions#ABORT_CERTIFICATE_ISSUANCE} and validation fails, or the wrong algorithm type is chosen, message is NOT null. Exception of any technical errors are stored in the cause, and message is null.
     * @throws IllegalValidityException if the certificate validity could not be determined.
     */
    boolean validatePublicKey(final CA ca, EndEntityInformation endEntityInformation, CertificateProfile certificateProfile, Date notBefore,
            Date notAfter, PublicKey publicKey) throws KeyValidationException, IllegalValidityException;

    //  /**
    //     * Checks authorization to key validators. Only key validators that refer to CA's that the authentication token is 
    //     * authorized to will be OK. Also checks the passed in extra resources. 
    //     * Does this in a single call to authorizationSession to keep it efficient
    //     * 
    //     * @param admin Administrator performing the operation
    //     * @param profile Certificate Profile that we want to check authorization for
    //     * @param logging if we should log access or not
    //     * @param resources, additional resources to check, for example StandardRules.CERTIFICATEPROFILEEDIT.resource()
    //     * @return true if authorized to the profile and the resources
    //     */
    //    boolean authorizedToProfileWithResource(AuthenticationToken admin, CertificateProfile profile, boolean logging, String... resources);
}
