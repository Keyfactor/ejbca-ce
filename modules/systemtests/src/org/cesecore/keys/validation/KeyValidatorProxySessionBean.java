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

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.profiles.ProfileData;
import org.cesecore.profiles.ProfileSessionLocal;

/**
 * @version $Id$
 *
 */

@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "KeyValidatorProxySessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class KeyValidatorProxySessionBean implements KeyValidatorProxySessionRemote {

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private KeyValidatorSessionLocal keyValidatorSession;

    @EJB
    private ProfileSessionLocal profileSession;

    @Override
    public Validator getValidator(int id) {
        return keyValidatorSession.getValidator(id);
    }

    @Override
    public String getKeyValidatorName(int id) {
        return keyValidatorSession.getKeyValidatorName(id);
    }

    @Override
    public Map<Integer, Validator> getAllKeyValidators() {
        return keyValidatorSession.getAllKeyValidators();
    }

    @Override
    public Map<Integer, Validator> getKeyValidatorsById(Collection<Integer> ids) {
        return keyValidatorSession.getKeyValidatorsById(ids);
    }

    @Override
    public Map<Integer, String> getKeyValidatorIdToNameMap() {
        return keyValidatorSession.getKeyValidatorIdToNameMap();
    }

    @Override
    public int addKeyValidator(AuthenticationToken admin, Validator validator)
            throws AuthorizationDeniedException, KeyValidatorExistsException {
        return keyValidatorSession.addKeyValidator(admin, validator);
    }

    @Override
    public void changeKeyValidator(AuthenticationToken admin, Validator validator)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException {
        keyValidatorSession.changeKeyValidator(admin, validator);
    }
    
    @Override
    public List<Integer> getConflictingKeyValidatorIds(Validator validator) {
        return keyValidatorSession.getConflictingKeyValidatorIds(validator);
    }

    @Override
    public void importValidator(AuthenticationToken admin, Validator validator) throws AuthorizationDeniedException, KeyValidatorExistsException {
        keyValidatorSession.importValidator(admin, validator);
    }

    @Override
    public void cloneKeyValidator(AuthenticationToken admin, Validator validator, String newname)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException {
        keyValidatorSession.cloneKeyValidator(admin, validator, newname);
    }

    @Override
    public void cloneKeyValidator(AuthenticationToken admin, int validatorId, String newName)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException {
        keyValidatorSession.cloneKeyValidator(admin, validatorId, newName);
    }
    
    @Override
    public void renameKeyValidator(AuthenticationToken admin, int validatorId, String newName)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException {
        keyValidatorSession.renameKeyValidator(admin, validatorId, newName);
    }

    @Override
    public void renameKeyValidator(AuthenticationToken admin, Validator validator, String newname)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException {
        keyValidatorSession.renameKeyValidator(admin, validator, newname);
    }

    @Override
    public void removeKeyValidator(AuthenticationToken admin, final int validatorId)
            throws AuthorizationDeniedException, CouldNotRemoveKeyValidatorException {
        keyValidatorSession.removeKeyValidator(admin, validatorId);
    }
    
    @Override
    public void removeKeyValidator(AuthenticationToken admin, String validatorName)
            throws AuthorizationDeniedException, CouldNotRemoveKeyValidatorException {
        keyValidatorSession.removeKeyValidator(admin, validatorName);
    }

    @Override
    public Collection<Integer> getAuthorizedKeyValidatorIds(AuthenticationToken admin, String keyValidatorAccessRule) {
        return keyValidatorSession.getAuthorizedKeyValidatorIds(admin, keyValidatorAccessRule);
    }

    @Override
    public void flushKeyValidatorCache() {
        keyValidatorSession.flushKeyValidatorCache();
    }

    @Override
    public boolean validatePublicKey(AuthenticationToken admin, CA ca, EndEntityInformation endEntityInformation, CertificateProfile certificateProfile, Date notBefore,
            Date notAfter, PublicKey publicKey) throws ValidationException, IllegalValidityException {
        return keyValidatorSession.validatePublicKey(admin, ca, endEntityInformation, certificateProfile, notBefore, notAfter, publicKey);
    }

    @Override
    public void internalChangeValidatorNoFlushCache(Validator validator)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException {
        ProfileData data = profileSession.findById(validator.getProfileId());
        if (data != null) {
            profileSession.changeProfile(validator);
        }
    }

    @Override
    public void validateCertificate(AuthenticationToken authenticationToken, IssuancePhase phase, CA ca, EndEntityInformation endEntityInformation,
            X509Certificate certificate) throws ValidationException {
        keyValidatorSession.validateCertificate(authenticationToken, phase, ca, endEntityInformation, certificate);
    }

    @Override
    public List<ValidationResult> validateDnsNames(AuthenticationToken authenticationToken, IssuancePhase issuancePhase, CA ca, EndEntityInformation endEntityInformation,
            RequestMessage requestMessage) throws ValidationException {
        return keyValidatorSession.validateDnsNames(authenticationToken, issuancePhase, ca, endEntityInformation, requestMessage);
    }

    @Override
    public Map<Integer, String> getKeyValidatorIdToNameMap(int applicableCas) {
        return keyValidatorSession.getKeyValidatorIdToNameMap(applicableCas);
    }
    
    @Override
    public void replaceKeyValidator(AuthenticationToken authenticationToken, LinkedHashMap<Object, Object> data, int id)
            throws AuthorizationDeniedException {
        keyValidatorSession.replaceKeyValidator(authenticationToken, data, id);
    }
}
