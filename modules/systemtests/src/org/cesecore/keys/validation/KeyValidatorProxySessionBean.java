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
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.jndi.JndiConstants;

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

    @Override
    public BaseKeyValidator getKeyValidator(int id) {
        return keyValidatorSession.getKeyValidator(id);
    }

    @Override
    public BaseKeyValidator getKeyValidator(String name) {
        return keyValidatorSession.getKeyValidator(name);
    }

    @Override
    public int getKeyValidatorId(String name) {
        return keyValidatorSession.getKeyValidatorId(name);
    }

    @Override
    public String getKeyValidatorName(int id) {
        return keyValidatorSession.getKeyValidatorName(id);
    }

    @Override
    public Map<Integer, BaseKeyValidator> getAllKeyValidators() {
        return keyValidatorSession.getAllKeyValidators();
    }

    @Override
    public Map<Integer, BaseKeyValidator> getKeyValidatorsById(Collection<Integer> ids) {
        return keyValidatorSession.getKeyValidatorsById(ids);
    }

    @Override
    public Map<Integer, String> getKeyValidatorIdToNameMap() {
        return keyValidatorSession.getKeyValidatorIdToNameMap();
    }

    @Override
    public Map<?, ?> getKeyValidatorData(int id) throws KeyValidatorDoesntExistsException {
        return keyValidatorSession.getKeyValidatorData(id);
    }

    @Override
    public void addKeyValidator(AuthenticationToken admin, int id, String name, BaseKeyValidator validator)
            throws AuthorizationDeniedException, KeyValidatorExistsException {
        keyValidatorSession.addKeyValidator(admin, id, name, validator);
    }

    @Override
    public int addKeyValidator(AuthenticationToken admin, String name, BaseKeyValidator validator)
            throws AuthorizationDeniedException, KeyValidatorExistsException {
        return keyValidatorSession.addKeyValidator(admin, name, validator);
    }

    @Override
    public void changeKeyValidator(AuthenticationToken admin, String name, BaseKeyValidator validator)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException {
        keyValidatorSession.changeKeyValidator(admin, name, validator);
    }

    @Override
    public void cloneKeyValidator(AuthenticationToken admin, String oldname, String newname)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException {
        keyValidatorSession.cloneKeyValidator(admin, oldname, newname);
    }

    @Override
    public void renameKeyValidator(AuthenticationToken admin, String oldname, String newname)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException {
        keyValidatorSession.renameKeyValidator(admin, oldname, newname);
    }

    @Override
    public void removeKeyValidator(AuthenticationToken admin, String name)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException, CouldNotRemoveKeyValidatorException {
        keyValidatorSession.removeKeyValidator(admin, name);
    }

    @Override
    public Collection<Integer> getAuthorizedKeyValidatorIds(AuthenticationToken admin, String keyValidatorAccessRule) {
        return keyValidatorSession.getAuthorizedKeyValidatorIds(admin, keyValidatorAccessRule);
    }

    @Override
    public List<String> getCustomKeyValidatorImplementationClasses() {
        return keyValidatorSession.getCustomKeyValidatorImplementationClasses();
    }

    @Override
    public IKeyValidator createKeyValidatorInstanceByData(Map<?, ?> data) {
        return keyValidatorSession.createKeyValidatorInstanceByData(data);
    }

    @Override
    public void flushKeyValidatorCache() {
        keyValidatorSession.flushKeyValidatorCache();
    }

    @Override
    public boolean validatePublicKey(CA ca, EndEntityInformation endEntityInformation, CertificateProfile certificateProfile, Date notBefore,
            Date notAfter, PublicKey publicKey) throws KeyValidationException, IllegalValidityException {
        return keyValidatorSession.validatePublicKey(ca, endEntityInformation, certificateProfile, notBefore, notAfter, publicKey);
    }
}
