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

import javax.ejb.Remote;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * @version $Id$
 *
 */
@Remote
public interface KeyValidatorProxySessionRemote {

    /**
     * Gets a key validator by cache or database.
     * @return a BaseKeyValidator or null if a key validator with the given id does not exist. Uses cache to get the object as quickly as possible.
     *         
     */
    Validator getKeyValidator(int id);

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
     * Retrieves a Map of key validator ids. 
     * @return mapping of key validators names and ids. 
     */
    Map<String, Integer> getKeyValidatorNameToIdMap();

    /**
     * Adds a key validator to the database. Used for importing and exporting
     * profiles from xml-files.
     *
     * @param admin AuthenticationToken of administrator.
     * @param id the key validator is.
     * @param name the name of the key validator to add.
     * @param validator the key validator to add.
     *
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_validator
     * @throws KeyValidatorExistsException if key validator already exists.
     */
    void addKeyValidator(AuthenticationToken admin, int id, String name, Validator validator)
            throws AuthorizationDeniedException, KeyValidatorExistsException;

    /**
     * Adds a key validator to the database.
     * 
     * @param admin AuthenticationToken of admin
     * @param validator the key validator to add
     * @return the key validator ID as added
     * 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_validator
     * @throws KeyValidatorExistsException if key validator already exists.
     */
    int addKeyValidator(AuthenticationToken admin, Validator validator)
            throws AuthorizationDeniedException, KeyValidatorExistsException;

    /** 
     * Updates the key validator with the given name.
     *  
     * @param admin AuthenticationToken of administrator.
     * @param validator the key validator to be modified.
     * 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_validator
     * @throws KeyValidatorDoesntExistsException if there's no key validator with the given name.
     * 
     * */
    void changeKeyValidator(AuthenticationToken admin, Validator validator)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException;

    /**
     * Adds a key validator with the same content as the original.
     * 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_validator
     * @throws KeyValidatorDoesntExistsException if key validator does not exist
     * @throws KeyValidatorExistsException if key validator already exists.
     */
    void cloneKeyValidator(AuthenticationToken admin, Validator validator, String newname)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException;

    /**
     * Renames a key validator or throws an exception.
     * 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_validator
     * @throws KeyValidatorDoesntExistsException if key validator does not exist
     * @throws KeyValidatorExistsException if key validator already exists.
     */
    void renameKeyValidator(AuthenticationToken admin, Validator validator, String newname)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException;

    /** Removes the key validator data if it is not referenced by a CA. Does not throw any errors if the validator does not exist
     * 
     * @param admin AuthenticationToken of admin.
     * @param validatorId the ID of the key validator to remove.
     * 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_validators
     * @throws CouldNotRemoveKeyValidatorException if the key validator is referenced by other objects.
     */
    void removeKeyValidator(AuthenticationToken admin, final int validatorId)
            throws AuthorizationDeniedException, CouldNotRemoveKeyValidatorException;

    /** Retrieves a Collection of id:s (Integer) to authorized key validators. 
     * @param admin the administrator for whom to get the profile ids he/she has access to
     * @param keyValidatorAccessRule an access rule which is required on the key validator in order for it to be returned, for example AccessRulesConstants.CREATE_VALIDATOR to only return profiles for which the admin have create rights
     * @return Collection of end key validator id:s (Integer)
     */
    Collection<Integer> getAuthorizedKeyValidatorIds(AuthenticationToken admin, String keyValidatorAccessRule);
    
    /**
     * Flushes the key validators cache to ensure that next time they are read from database.
     */
    void flushKeyValidatorCache();

    /**
     * Validates a key against the key validators which match the filter criteria defined in it and the CA reference to it. 
     * The method is invoked while certificate issuance for user certificates and CA certificates.
     * 
     * @param admin the AuthenticationToken of the admin who requested the operation resulting in validation, used for audit logging, for example the admin requesting cert issuance 
     * @param ca the issuing CA, or CA to be issued in case of a root or sub-ca.
     * @param endEntityInformation the end entity information
     * @param certificateProfile the certificate profile
     * @param notBefore the certificates notBefore validity
     * @param notAfter the certificates notAfter validity
     * @param publicKey the public key of the certificate
     * @return true if all matching key validators could validate the public key successfully. If false #getMessage().size() is greater than 0.
     * @throws KeyValidationException if the validation failed and failed action type is set to abort certificate issuance {@link KeyValidationFailedActions#ABORT_CERTIFICATE_ISSUANCE}.
     * @throws IllegalValidityException if the certificate validity could not be determined.
     */
    boolean validatePublicKey(AuthenticationToken admin, final CA ca, EndEntityInformation endEntityInformation, CertificateProfile certificateProfile, Date notBefore,
            Date notAfter, PublicKey publicKey) throws KeyValidationException, IllegalValidityException;
    
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
    
    /** Change a Validator without affecting the cache */
    void internalChangeValidatorNoFlushCache(Validator validator)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException;

}
