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
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Local interface for key validator operations.
 *
 * @version $Id$
 */
@Local
public interface KeyValidatorSessionLocal extends KeyValidatorSession, CertificateValidationDomainService {

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
     * Retrieves a Map of key validator ids, sorted on profile name.
     * @return sorted mapping of key validator names and ids.
     */
    Map<String, Integer> getKeyValidatorNameToIdMap();

    /**
     * <p>Returns the ids for validators conflicting with a given key validator which is to be added.</p>
     * <p>A new validator is conflicting either if it has the same id or if has the same name and type as an
     * existing validator. A validator can be added to this session iff this method returns an empty list.</p>
     * @param validator the validator to be added to this session
     * @return a list of ids for conflicting validators, or an empty list if there are no conflicts
     */
    List<Integer> getConflictingKeyValidatorIds(final Validator validator);

    /**
     * Adds a key validator to the database. Used for importing and exporting
     * profiles from xml-files.
     *
     * @param admin AuthenticationToken of administrator.
     * @param validator the key validator to add.
     *
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_validator
     * @throws KeyValidatorExistsException if key validator already exists.
     */
    void importValidator(AuthenticationToken admin, Validator validator) throws AuthorizationDeniedException, KeyValidatorExistsException;

    /**
     * Adds a key validator with the same content as the original.
     *
     * @param admin an authentication token
     * @param the ID of a validator
     * @param newName the name of the clone
     *
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_validator
     * @throws KeyValidatorDoesntExistsException if key validator does not exist
     * @throws KeyValidatorExistsException if key validator already exists.
     */
    void cloneKeyValidator(final AuthenticationToken admin, final int validatorId, final String newName)
            throws  AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException;

    /**
     * Adds a key validator with the same content as the original.
     *
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_validator
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
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_validator
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
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_validator
     * @throws KeyValidatorDoesntExistsException if key validator does not exist
     * @throws KeyValidatorExistsException if key validator already exists.
     */
    void renameKeyValidator(final AuthenticationToken admin, final Validator validator, String newName)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException;

    /** Retrieves a Collection of id:s (Integer) to authorized key validators.
     * @param admin the administrator for whom to get the profile ids he/she has access to
     * @param keyValidatorAccessRule an additional access rule which is required in order for it to be returned, for example REGULAR_EDITVALIDATOR to only return profiles only if the admin have validator create rights
     * @return Collection of end key validator id:s (Integer)
     */
    Collection<Integer> getAuthorizedKeyValidatorIds(final AuthenticationToken admin, String keyValidatorAccessRule);

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
     * @throws ValidationException if the key validation failed. If the key validators failed action is set to abort certificate issuance {@link KeyValidationFailedActions#ABORT_CERTIFICATE_ISSUANCE} and validation fails, or the wrong algorithm type is chosen, message is NOT null. Exception of any technical errors are stored in the cause, and message is null.
     * @throws IllegalValidityException if the certificate validity could not be determined.
     */
    boolean validatePublicKey(AuthenticationToken admin, final CA ca, EndEntityInformation endEntityInformation, CertificateProfile certificateProfile, Date notBefore,
            Date notAfter, PublicKey publicKey) throws ValidationException, IllegalValidityException;

    /**
     * Validates dnsName fields defined in the SubjectAltName field of the end entity against CAA rules.
     *
     * @param authenticationToken the authentication token of the administrator performing the action
     * @param ca the issuing CA
     * @param endEntityInformation the end entity object
     * @param the incoming request message
     *
     * @throws ValidationException if validation failed
     */
    void validateDnsNames(final AuthenticationToken authenticationToken, final CA ca, final EndEntityInformation endEntityInformation,
            final RequestMessage requestMessage) throws ValidationException;

    /**
     * Validates a generated certificate during issuance.
     * 
     * @param authenticationToken the authentication token of the administrator performing the action.
     * @param ca the issuing CA
     * @param endEntityInformation the end entity object
     * @param certificate the certificate to validate
     * @throws ValidationException if the validation failed. If the validation failed action is set to abort certificate issuance {@link KeyValidationFailedActions#ABORT_CERTIFICATE_ISSUANCE} and validation fails, message is NOT null. Exception of any technical errors are stored in the cause, and message is null.
     */
    void validateCertificate(final AuthenticationToken authenticationToken, final CA ca, final EndEntityInformation endEntityInformation, final X509Certificate certificate)  throws ValidationException, IllegalValidityException;

    /** Removes the key validator data if it is not referenced by a CA.
     * If the validatorId does not exist, the method returns without doing anything.
     *
     * @param admin AuthenticationToken of admin.
     * @param validatorId the ID of the validator to remove
     *
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_validators
     * @throws CouldNotRemoveKeyValidatorException if the key validator is in use
     */
    void removeKeyValidator(AuthenticationToken admin, int validatorId)
            throws AuthorizationDeniedException, CouldNotRemoveKeyValidatorException;

    /**
     * Replaces the settings of a key validator without changing its name or profile ID.
     * @param authenticationToken used for authentication
     * @param validator the new settings of the validator
     * @param the id of the validator to update
     */
    void replaceKeyValidator(AuthenticationToken authenticationToken, LinkedHashMap<Object, Object> data, int id) throws AuthorizationDeniedException;
}
