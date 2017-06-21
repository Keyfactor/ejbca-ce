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

import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.ServiceLoader;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.CertTools;
import org.cesecore.util.ProfileID;

/**
 * Handles management of key validators.
 * 
 * @version $Id: KeyValidatorSessionBean.java 24997 2017-03-01 12:12:00Z anjakobs $
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "KeyValidatorSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class KeyValidatorSessionBean implements KeyValidatorSessionLocal, KeyValidatorSessionRemote {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(KeyValidatorSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private PublicKeyBlacklistSessionLocal blacklistSession;

    @Override
    public BaseKeyValidator getKeyValidator(int id) {
        return getKeyValidatorInternal(id, null, true);
    }

    @Override
    public BaseKeyValidator getKeyValidator(String name) {
        return getKeyValidatorInternal(-1, name, true);
    }

    @Override
    public String getKeyValidatorName(int id) {
        if (log.isTraceEnabled()) {
            log.trace(">getKeyValidatorName(id: " + id + ")");
        }
        final BaseKeyValidator entity = getKeyValidatorInternal(id, null, true);
        String result = null;
        if (null != entity) {
            result = entity.getName();
        }
        if (log.isTraceEnabled()) {
            log.trace("<getKeyValidatorName(): " + result);
        }
        return result;
    }

    @Override
    public Map<?, ?> getKeyValidatorData(int id) throws KeyValidatorDoesntExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">getKeyValidatorData(id: " + id + ")");
        }
        final BaseKeyValidator entity = getKeyValidatorInternal(id, null, true);
        if (entity == null) {
            throw new KeyValidatorDoesntExistsException("Key validator with id " + id + " doesn't exist.");
        }
        return (Map<?, ?>) entity.saveData();
    }

    @Override
    public void addKeyValidator(AuthenticationToken admin, int id, String name, BaseKeyValidator validator)
            throws AuthorizationDeniedException, KeyValidatorExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">addKeyValidator(name: " + name + ", id: " + id + ")");
        }
        addKeyValidatorInternal(admin, id, name, validator);
        final String message = intres.getLocalizedMessage("keyvalidator.addedkeyvalidator", name);
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", message);
        auditSession.log(EventTypes.KEYVALIDATOR_CREATION, EventStatus.SUCCESS, ModuleTypes.KEY_VALIDATOR, ServiceTypes.CORE, admin.toString(), null,
                null, null, details);
        if (log.isTraceEnabled()) {
            log.trace("<addKeyValidator()");
        }
    }

    @Override
    public void changeKeyValidator(AuthenticationToken admin, String name, BaseKeyValidator validator)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">changeKeyValidator(name: " + name + ")");
        }
        assertIsAuthorizedToEditKeyValidators(admin);
        KeyValidatorData data = KeyValidatorData.findByName(entityManager, name);
        final String message;
        if (data != null) {
            final Map<Object, Object> diff = getKeyValidator(data).diff(validator);
            data.setKeyValidator(validator);
            // Since loading a KeyValidator is quite complex, we simple purge the cache here.
            KeyValidatorCache.INSTANCE.removeEntry(data.getId());
            message = intres.getLocalizedMessage("keyvalidator.changedkeyvalidator", name);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", message);
            for (Map.Entry<Object, Object> entry : diff.entrySet()) {
                details.put(entry.getKey().toString(), entry.getValue().toString());
            }
            auditSession.log(EventTypes.KEYVALIDATOR_CHANGE, EventStatus.SUCCESS, ModuleTypes.KEY_VALIDATOR, ServiceTypes.CORE, admin.toString(),
                    null, null, null, details);
        } else {
            message = intres.getLocalizedMessage("keyvalidator.errorchangekeyvalidator", name);
            log.info(message);
        }
        if (log.isTraceEnabled()) {
            log.trace("<changeKeyValidator()");
        }
    }

    @Override
    public void removeKeyValidator(AuthenticationToken admin, String name)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException, CouldNotRemoveKeyValidatorException {
        if (log.isTraceEnabled()) {
            log.trace(">removeKeyValidator(name: " + name + ")");
        }
        assertIsAuthorizedToEditKeyValidators(admin);
        String message;
        try {
            KeyValidatorData data = KeyValidatorData.findByName(entityManager, name);
            if (data == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Trying to remove a key validator that does not exist: " + name);
                }
                throw new KeyValidatorDoesntExistsException();
            } else {
                if (caSession.existsKeyValidatorInCAs(data.getId())) {
                    throw new CouldNotRemoveKeyValidatorException();
                }
                entityManager.remove(data);
                // Purge the cache here.
                KeyValidatorCache.INSTANCE.removeEntry(data.getId());
                message = intres.getLocalizedMessage("keyvalidator.removedkeyvalidator", name);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", message);
                auditSession.log(EventTypes.KEYVALIDATOR_REMOVAL, EventStatus.SUCCESS, ModuleTypes.KEY_VALIDATOR, ServiceTypes.CORE, admin.toString(),
                        null, null, null, details);
            }
        } catch (Exception e) {
            log.info(intres.getLocalizedMessage("keyvalidator.errorremovekeyvalidator", name));
            throw e;
        }
        if (log.isTraceEnabled()) {
            log.trace("<removeKeyValidator()");
        }
    }

    @Override
    public void flushKeyValidatorCache() {
        KeyValidatorCache.INSTANCE.flush();
        if (log.isDebugEnabled()) {
            log.debug("Flushed KeyValidator cache.");
        }
    }

    @Override
    public int addKeyValidator(AuthenticationToken admin, String name, BaseKeyValidator keyValidator)
            throws AuthorizationDeniedException, KeyValidatorExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">addKeyValidator(name: " + name + ")");
        }
        final int id = findFreeKeyValidatorId();
        addKeyValidator(admin, id, name, keyValidator);
        if (log.isTraceEnabled()) {
            log.trace("<addKeyValidator()");
        }
        return id;
    }

    @Override
    public void cloneKeyValidator(AuthenticationToken admin, String oldname, String newname)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">cloneKeyValidator(name: " + oldname + ")");
        }
        BaseKeyValidator keyValildator = null;
        KeyValidatorData data = KeyValidatorData.findByName(entityManager, oldname);
        if (data == null) {
            throw new KeyValidatorDoesntExistsException("Could not find key validator " + oldname);
        }
        try {
            keyValildator = (BaseKeyValidator) getKeyValidator(data).clone();
            addKeyValidatorInternal(admin, findFreeKeyValidatorId(), newname, keyValildator);
            final String message = intres.getLocalizedMessage("keyvalidator.clonedkeyvalidator", newname, oldname);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", message);
            auditSession.log(EventTypes.KEYVALIDATOR_CREATION, EventStatus.SUCCESS, ModuleTypes.KEY_VALIDATOR, ServiceTypes.CORE, admin.toString(),
                    null, null, null, details);
        } catch (KeyValidatorExistsException e) {
            final String message = intres.getLocalizedMessage("keyvalidator.errorclonekeyvalidator", newname, oldname);
            log.info(message);
            throw e;
        } catch (CloneNotSupportedException e) {
            // Severe error, should never happen
            throw new EJBException(e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<cloneKeyValidator()");
        }
    }

    @Override
    public void renameKeyValidator(AuthenticationToken admin, String name, String newName)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">renameKeyValidator(from " + name + " to " + newName + ")");
        }
        assertIsAuthorizedToEditKeyValidators(admin);
        boolean success = false;
        if (KeyValidatorData.findByName(entityManager, newName) == null) {
            KeyValidatorData data = KeyValidatorData.findByName(entityManager, name);
            if (data != null) {
                data.setName(newName);
                success = true;
                // Since loading a key validator is quite complex, we simple purge the cache here.
                KeyValidatorCache.INSTANCE.removeEntry(data.getId());
            }
        }
        if (success) {
            final String message = intres.getLocalizedMessage("keyvalidator.renamedkeyvalidator", name, newName);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", message);
            auditSession.log(EventTypes.KEYVALIDATOR_RENAME, EventStatus.SUCCESS, ModuleTypes.KEY_VALIDATOR, ServiceTypes.CORE, admin.toString(),
                    null, null, null, details);
        } else {
            final String message = intres.getLocalizedMessage("keyvalidator.errorrenamekeyvalidator", name, newName);
            log.info(message);
            throw new KeyValidatorExistsException();
        }
        if (log.isTraceEnabled()) {
            log.trace("<renameKeyValidator()");
        }
    }

    @Override
    public Map<Integer, BaseKeyValidator> getAllKeyValidators() {
        final List<KeyValidatorData> keyValidators = KeyValidatorData.findAll(entityManager);
        final Map<Integer, BaseKeyValidator> result = new HashMap<Integer, BaseKeyValidator>();
        BaseKeyValidator keyValidator;
        for (KeyValidatorData data : keyValidators) {
            keyValidator = getKeyValidator(data);
            if (keyValidator != null) {
                result.put(data.getId(), keyValidator);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Key validator with name " + data.getName() + " could not be created.");
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Key validators found in datastore: " + result);
        }
        return result;
    }

    @Override
    public Map<Integer, BaseKeyValidator> getKeyValidatorsById(Collection<Integer> ids) {
        final List<KeyValidatorData> keyValidators = KeyValidatorData.findAllById(entityManager, ids);
        final Map<Integer, BaseKeyValidator> result = new HashMap<Integer, BaseKeyValidator>();
        BaseKeyValidator keyValidator;
        for (KeyValidatorData data : keyValidators) {
            keyValidator = getKeyValidator(data);
            if (keyValidator != null) {
                result.put(data.getId(), keyValidator);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Key validator with name " + data.getName() + " could not be created.");
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Key validators found in datastore: " + result);
        }
        return result;
    }

    @Override
    public Map<Integer, String> getKeyValidatorIdToNameMap() {
        final HashMap<Integer, String> result = new HashMap<Integer, String>();
        for (KeyValidatorData data : KeyValidatorData.findAll(entityManager)) {
            if (log.isDebugEnabled()) {
                log.debug("Find key validator " + data.getName() + " with id " + data.getId());
            }
            result.put(data.getId(), data.getName());
        }
        return result;
    }

    @Override
    public int getKeyValidatorId(String name) {
        // Get key validator to ensure it is in the cache, or read.
        final BaseKeyValidator keyValidator = getKeyValidatorInternal(-1, name, true);
        int result = 0;
        if (null != keyValidator) {
            result = keyValidator.getKeyValidatorId();
        }
        return result;
    }

    @Override
    public boolean validatePublicKey(final CA ca, EndEntityInformation endEntityInformation, CertificateProfile certificateProfile, Date notBefore,
            Date notAfter, PublicKey publicKey) throws KeyValidationException, IllegalValidityException {
        boolean result = true;
        // ECA-4219 Workaround: While CA creation, select key validators in AdminGUI -> Edit CAs -> Create CA -> Key Validators.
        // ca != null brcause of import or update of external certificates.
        if (ca != null && !CollectionUtils.isEmpty(ca.getKeyValidators())) { // || certificateProfile.isTypeRootCA() || certificateProfile.isTypeSubCA()
            final CertificateValidity certificateValidity = new CertificateValidity(endEntityInformation, certificateProfile, notBefore, notAfter,
                    ca.getCACertificate(), false);
            if (log.isDebugEnabled()) {
                log.debug("Validate " + publicKey.getAlgorithm() + " public key with " + publicKey.getFormat() + " format.");
                log.debug("Certificate 'notBefore' " + certificateValidity.getNotBefore());
                log.debug("Certificate 'notAfter' " + certificateValidity.getNotAfter());
            }
            final Map<Integer, BaseKeyValidator> map = getKeyValidatorsById(ca.getKeyValidators());
            if (!map.isEmpty()) {
                // A bit hackish, make a call to blacklist session to ensure that blacklist cache has this entry loaded
                // this call is made here, even if the Validator does not use blacklists, but Validator can not call an EJB so easily.
                // and we don't want to do instanceof, so we take the hit
                // TODO: if the key is not in the cache (which it hopefully is not) this is a database lookup for each key. Huuge performance hit
                // should better be implemented as a full in memory cache with a state so we know if it's loaded or not, with background updates
                // TODO: the BlacklistKeyValidator can make a local EJB helper lookup instead, this combined with a background loaded cache should be higly efficient
                blacklistSession.getPublicKeyBlacklistEntryId(CertTools.createPublicKeyFingerprint(publicKey, PublicKeyBlacklistKeyValidator.DIGEST_ALGORITHM));
                // carry on after filling the blacklist cache...
            }
            final List<Integer> ids = new ArrayList<Integer>(map.keySet());
            BaseKeyValidator keyValidator;
            String name = null;
            for (Integer id : ids) {
                keyValidator = map.get(id);
                keyValidator.setCertificateProfile(certificateProfile);
                name = keyValidator.getName();
                if (log.isTraceEnabled()) {
                    log.trace("Try to apply key validator: " + keyValidator.toDisplayString());
                }
                try {
                    // Filter for base key validator critieria.
                    final List<Integer> certificateProfileIds = keyValidator.getCertificateProfileIds();
                    if (null != certificateProfileIds && !certificateProfileIds.contains(endEntityInformation.getCertificateProfileId())) {
                        if (log.isDebugEnabled()) {
                            log.debug(intres.getLocalizedMessage("keyvalidator.filterconditiondoesnotmatch", name, "applicableCertificateProfiles"));
                        }
                        continue;
                    }
                    if (!KeyValidatorDateConditions.evaluate(keyValidator.getNotBefore(), certificateValidity.getNotBefore(),
                            keyValidator.getNotBeforeCondition())) {
                        if (log.isDebugEnabled()) {
                            log.debug(intres.getLocalizedMessage("keyvalidator.filterconditiondoesnotmatch", name, "notBefore"));
                        }
                        continue;
                    }
                    if (!KeyValidatorDateConditions.evaluate(keyValidator.getNotAfter(), certificateValidity.getNotAfter(),
                            keyValidator.getNotAfterCondition())) {
                        if (log.isDebugEnabled()) {
                            log.debug(intres.getLocalizedMessage("keyvalidator.filterconditiondoesnotmatch", name, "notAfter"));
                        }
                        continue;
                    }
                    log.info(intres.getLocalizedMessage("keyvalidator.isbeingprocessed", name, endEntityInformation.getUsername()));
                    keyValidator.before();
                    if (!(result = keyValidator.validate(publicKey))) {
                        postProcessKeyValidation(keyValidator, result);
                    }
                } catch (KeyValidationException e) {
                    throw e;
                } catch (Exception e) {
                    final String message = intres.getLocalizedMessage("keyvalidator.couldnotbeprocessed", name, e.getMessage());
                    log.warn(message, e);
                    throw new KeyValidationException(message, e);
                } finally {
                    keyValidator.after();
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("No key validator configured for CA " + ca.getName() + " (id=" + ca.getCAId() + ").");
            }
        }
        return result;
    }

    @Override
    public IKeyValidator createKeyValidatorInstanceByData(Map<?, ?> data) {
        final Integer type = (Integer) data.get(BaseKeyValidator.TYPE);
        final String classpath = (String) data.get(BaseKeyValidator.CLASSPATH);
        BaseKeyValidator result = null;
        if (StringUtils.isNotBlank(classpath)) { // Must be a custom key validator.
            final List<ICustomKeyValidator> keyValidators = getCustomKeyValidatorImplementations();
            for (IKeyValidator keyValidator : keyValidators) {
                if (keyValidator.getClass().getName().equals(classpath)) {
                    result = (BaseKeyValidator) keyValidator;
                }
            }
        } else {
            final List<IKeyValidator> keyValidators = getKeyValidatorImplementations();
            for (IKeyValidator keyValidator : keyValidators) {
                if (keyValidator.getKeyValidatorType() == type) {
                    result = (BaseKeyValidator) keyValidator;
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Created key validator " + result + " with type " + type + " and custom classpath " + classpath);
        }
        if (result != null) {
            result.loadData(data);
            result.init();
        }
        return result;
    }

    /**
     * Post processes a key validator by the result of its validation and the failedAction stored in the BaseKeyValidator.
     * @param keyValidator the key validator.
     * @param result the evaulation result.
     */
    private void postProcessKeyValidation(IKeyValidator keyValidator, boolean result) throws KeyValidationException {
        final String name = keyValidator.getName();
        if (!result) { // Evaluation has failed.
            final int index = keyValidator.getFailedAction();
            final String message = intres.getLocalizedMessage("keyvalidator.validationfailed", name, keyValidator.getMessages());
            if (KeyValidationFailedActions.LOG_INFO.getIndex() == index) {
                log.info(message);
            } else if (KeyValidationFailedActions.LOG_WARN.getIndex() == index) {
                log.warn(message);
            } else if (KeyValidationFailedActions.LOG_ERROR.getIndex() == index) {
                log.error(message);
            } else if (KeyValidationFailedActions.ABORT_CERTIFICATE_ISSUANCE.getIndex() == index) {
                throw new KeyValidationException(message);
            } else {
                // NOOP
            }
        } else {
            final String message = intres.getLocalizedMessage("keyvalidator.validationsuccessful", name, keyValidator.getPublicKey().getEncoded());
            log.info(message);
        }
    }

    public boolean authorizedToKeyValidatorWithResource(AuthenticationToken admin, CertificateProfile profile, boolean logging, String... resources) {
        // We need to check that admin also have rights to the passed in resources
        final List<String> rules = new ArrayList<>(Arrays.asList(resources));
        // Check that admin is authorized to all CAids
        for (final Integer caid : profile.getAvailableCAs()) {
            rules.add(StandardRules.CAACCESS.resource() + caid);
        }
        // Perform authorization check
        boolean ret = false;
        if (logging) {
            ret = authorizationSession.isAuthorized(admin, rules.toArray(new String[rules.size()]));
        } else {
            ret = authorizationSession.isAuthorizedNoLogging(admin, rules.toArray(new String[rules.size()]));
        }
        return ret;
    }

    @Override
    public Collection<Integer> getAuthorizedKeyValidatorIds(AuthenticationToken admin, String keyValidatorAccessRule) {
        final ArrayList<Integer> result = new ArrayList<Integer>();
        final Map<Integer, String> map = getKeyValidatorIdToNameMap();
        String accessRule;
        boolean authorized;
        if (authorizationSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource())) {
            for (final Entry<Integer, String> entry : map.entrySet()) {
                // ECA-4219 Fix. Authorization does not seem to be effective. If so, it would NOT be put into list for AdminGUI -> Amdin. Privileges -> Access Rules -> Base Mode -> Key Validators. But it would still appear in the Advanced Mode!
                // accessRule = "/keyvalidator/" + entry.getValue() + keyValidatorAccessRule; // AccessRulesConstants.KEYVALIDATORPREFIX not available here.
                accessRule = "/keyvalidatorrules/" + entry.getValue().toString() + keyValidatorAccessRule;
                authorized = authorizationSession.isAuthorizedNoLogging(admin, accessRule);
                if (log.isDebugEnabled()) {
                    log.debug("Access rule " + accessRule + " authorized " + authorized);
                }
                if (authorized) {
                    result.add(entry.getKey());
                }
            }
        }
        return result;
    }

    @Override
    public List<IKeyValidator> getKeyValidatorImplementations() {
        final List<IKeyValidator> result = new ArrayList<IKeyValidator>();
        try {
            final ServiceLoader<? extends IKeyValidator> serviceLoader = ServiceLoader.load(IKeyValidator.class);
            for (IKeyValidator keyValidator : serviceLoader) {
                result.add(keyValidator);
            }
            if (log.isDebugEnabled()) {
                log.debug("Available KeyValidator plug-ins found: " + result);
            }
        } catch (Exception | Error e) {
            if (log.isDebugEnabled()) {
                log.debug("Error loading key validator implementations: " + e.getMessage(), e);
            }
        }
        return result;
    }

    @Override
    public List<String> getKeyValidatorImplementationClasses() {
        final List<IKeyValidator> keyValidators = getKeyValidatorImplementations();
        final List<String> result = new ArrayList<String>();
        for (IKeyValidator keyValidator : keyValidators) {
            result.add(keyValidator.getClass().getName());
        }
        return result;
    }

    @Override
    public List<Integer> getKeyValidatorTypes() {
        final List<Integer> result = new ArrayList<Integer>();
        final List<IKeyValidator> keyValidators = getKeyValidatorImplementations();
        for (IKeyValidator keyValidator : keyValidators) {
            result.add(keyValidator.getKeyValidatorType());
        }
        result.add(new Integer(0)); // Custom key validator type.
        return result;
    }

    @Override
    public List<ICustomKeyValidator> getCustomKeyValidatorImplementations() {
        final List<ICustomKeyValidator> result = new ArrayList<ICustomKeyValidator>();
        try {
            final ServiceLoader<? extends ICustomKeyValidator> serviceLoader = ServiceLoader.load(ICustomKeyValidator.class);
            for (ICustomKeyValidator keyValidator : serviceLoader) {
                if (!keyValidator.isReadOnly()) {
                    result.add(keyValidator);
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("Available CustomKeyValidator plug-ins found: " + result);
            }
        } catch (Exception | Error e) {
            if (log.isDebugEnabled()) {
                log.debug("Error loading custom key validator implementations: " + e.getMessage(), e);
            }
        }
        return result;
    }

    @Override
    public List<String> getCustomKeyValidatorImplementationClasses() {
        final List<ICustomKeyValidator> keyValidators = getCustomKeyValidatorImplementations();
        final List<String> result = new ArrayList<String>();
        for (ICustomKeyValidator keyValidator : keyValidators) {
            result.add(keyValidator.getClasspath());
        }
        return result;
    }

    /** Adds a key validator or throws an exception. */
    private void addKeyValidatorInternal(AuthenticationToken admin, int id, String name, BaseKeyValidator keyValidator)
            throws AuthorizationDeniedException, KeyValidatorExistsException {
        assertIsAuthorizedToEditKeyValidators(admin);
        if (KeyValidatorData.findByName(entityManager, name) == null && KeyValidatorData.findById(entityManager, Integer.valueOf(id)) == null) {
            entityManager.persist(new KeyValidatorData(Integer.valueOf(id), name, keyValidator));
        } else {
            final String message = intres.getLocalizedMessage("keyvalidator.erroraddkeyvalidator", name);
            log.info(message);
            throw new KeyValidatorExistsException();
        }
    }

    /** Gets a key validator by cache or database, can return null. Puts it into the cache, if not already present. */
    private BaseKeyValidator getKeyValidatorInternal(int id, final String name, boolean fromCache) {
        if (log.isTraceEnabled()) {
            log.trace(">getKeyValidatorInternal: " + id + ", " + name);
        }
        Integer idValue = Integer.valueOf(id);
        if (id == -1) {
            idValue = KeyValidatorCache.INSTANCE.getNameToIdMap().get(name);
        }
        BaseKeyValidator result = null;
        // If we should read from cache, and we have an id to use in the cache, and the cache does not need to be updated
        if (fromCache && idValue != null && !KeyValidatorCache.INSTANCE.shouldCheckForUpdates(idValue)) {
            // Get from cache (or null)
            result = KeyValidatorCache.INSTANCE.getEntry(idValue);
        }

        // if we selected to not read from cache, or if the cache did not contain this entry
        if (result == null) {
            if (log.isDebugEnabled()) {
                log.debug("KeyValidator with ID " + idValue + " and/or name '" + name + "' will be checked for updates.");
            }
            // We need to read from database because we specified to not get from cache or we don't have anything in the cache
            final KeyValidatorData data;
            if (name != null) {
                data = KeyValidatorData.findByName(entityManager, name);
            } else {
                data = KeyValidatorData.findById(entityManager, idValue);
            }
            if (data != null) {
                result = getKeyValidator(data);
                final int digest = data.getProtectString(0).hashCode();
                // The cache compares the database data with what is in the cache
                // If database is different from cache, replace it in the cache
                KeyValidatorCache.INSTANCE.updateWith(data.getId(), digest, data.getName(), result);
            } else {
                // Ensure that it is removed from cache if it exists
                if (idValue != null) {
                    KeyValidatorCache.INSTANCE.removeEntry(idValue);
                }
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<getKeyValidatorInternal: " + id + ", " + name + ": " + (result == null ? "null" : "not null"));
        }
        return result;
    }

    /** Gets the concrete key validator by the base objects data, and updates it if necessary. */
    private BaseKeyValidator getKeyValidator(KeyValidatorData keyValidatorData) {
        BaseKeyValidator result = keyValidatorData.getCachedKeyValidator();
        if (result == null) {
            XMLDecoder decoder;
            try {
                decoder = new XMLDecoder(new ByteArrayInputStream(keyValidatorData.getData().getBytes("UTF8")));
            } catch (UnsupportedEncodingException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Could not decode key validator with name " + keyValidatorData.getName() + " because " + e.getMessage());
                }
                throw new EJBException(e);
            }
            final HashMap<?, ?> map = (HashMap<?, ?>) decoder.readObject();
            decoder.close();
            // Handle Base64 encoded string values.
            final HashMap<?, ?> base64Map = new Base64GetHashMap(map);
            result = (BaseKeyValidator) createKeyValidatorInstanceByData(base64Map);
            if (result != null) {
                result.setKeyValidtorId(keyValidatorData.getId());
                result.setName(keyValidatorData.getName());
                result.loadData(base64Map);
            }
        }
        return result;
    }

    /** Gets a free ID for the new key validator instance. */
    private int findFreeKeyValidatorId() {
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(int i) {
                return KeyValidatorData.findById(KeyValidatorSessionBean.this.entityManager, i) == null;
            }
        };
        return ProfileID.getNotUsedID(db);
    }

    /** Assert the administrator is authorized to edit key validators. */
    private void assertIsAuthorizedToEditKeyValidators(AuthenticationToken admin) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(admin, StandardRules.KEYVALIDATOREDIT.resource())) {
            final String message = intres.getLocalizedMessage("store.editkeyvalidatornotauthorized", admin.toString());
            throw new AuthorizationDeniedException(message);
        }
    }
}
