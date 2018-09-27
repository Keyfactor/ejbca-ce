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

import java.io.Serializable;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.commons.collections.CollectionUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.util.encoders.Base64;
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
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.config.ExternalScriptsConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.profiles.ProfileData;
import org.cesecore.profiles.ProfileSessionLocal;
import org.cesecore.util.CertTools;

/**
 * Handles management of key validators.
 *
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "KeyValidatorSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class KeyValidatorSessionBean implements KeyValidatorSessionLocal, KeyValidatorSessionRemote {

	// NOTE: Should be replaced by a ManagedExecutorService when we drop support for JEE 6
    private static final ExecutorService executorService = Executors.newFixedThreadPool(64);

    /** Class logger. */
    private static final Logger log = Logger.getLogger(KeyValidatorSessionBean.class);

    /** Internal localization of logs and errors. */
    private static final InternalResources intres = InternalResources.getInstance();

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private ProfileSessionLocal profileSession;
    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;

    @Override
    public Validator getValidator(int id) {
        return getValidatorInternal(id, true);
    }

    @Override
    public String getKeyValidatorName(int id) {
        if (log.isTraceEnabled()) {
            log.trace(">getKeyValidatorName(id: " + id + ")");
        }
        final Validator entity = getValidatorInternal(id, true);
        String result = null;
        if (null != entity) {
            result = entity.getProfileName();
        }
        if (log.isTraceEnabled()) {
            log.trace("<getKeyValidatorName(): " + result);
        }
        return result;
    }

    @Override
    public void importValidator(AuthenticationToken admin, Validator validator) throws AuthorizationDeniedException, KeyValidatorExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">addKeyValidator(name: " + validator.getProfileName() + ", id: " + validator.getProfileId() + ")");
        }
        addValidatorInternal(admin, validator);
        final String message = intres.getLocalizedMessage("validator.added_validator", validator.getProfileName());
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", message);
        auditSession.log(EventTypes.VALIDATOR_CREATION, EventStatus.SUCCESS, ModuleTypes.VALIDATOR, ServiceTypes.CORE, admin.toString(), null, null,
                null, details);
        if (log.isTraceEnabled()) {
            log.trace("<addKeyValidator()");
        }
    }

    @Override
    public void changeKeyValidator(AuthenticationToken admin, Validator validator)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException {
        assertIsAuthorizedToEditValidators(admin);
        ProfileData data = profileSession.findById(validator.getProfileId());
        final String message;
        final String name = validator.getProfileName();
        if (data != null) {
            profileSession.changeProfile(validator);
            // Since loading a KeyValidator is quite complex, we simple purge the cache here.
            ValidatorCache.INSTANCE.removeEntry(data.getId());
            message = intres.getLocalizedMessage("validator.changed_validator", name);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", message);
            //TODO: Include a diff in the changelog (profileData.getProfile().diff(profile);), but make sure to resolve all steps so that we don't
            //      output a ton of serialized garbage (see ECA-5276)
            auditSession.log(EventTypes.VALIDATOR_CHANGE, EventStatus.SUCCESS, ModuleTypes.VALIDATOR, ServiceTypes.CORE, admin.toString(), null, null,
                    null, details);
        } else {
            message = intres.getLocalizedMessage("validator.error.change_validator", name);
            log.info(message);
            throw new KeyValidatorDoesntExistsException("Validator by ID " + validator.getProfileId() + " does not exist in database.");
        }
    }

    @Override
    public void removeKeyValidator(final AuthenticationToken admin, final int validatorId)
            throws AuthorizationDeniedException, CouldNotRemoveKeyValidatorException {
        if (log.isTraceEnabled()) {
            log.trace(">removeKeyValidator(id: " + validatorId + ")");
        }
        assertIsAuthorizedToEditValidators(admin);
        String message;

        ProfileData data = profileSession.findById(validatorId);
        if (data == null) {
            if (log.isDebugEnabled()) {
                log.debug("Trying to remove a key validator that does not exist with ID: " + validatorId);
            }
            return;
        }

        if (caSession.existsKeyValidatorInCAs(data.getId())) {
            throw new CouldNotRemoveKeyValidatorException();
        }

        profileSession.removeProfile(data);
        // Purge the cache here.
        ValidatorCache.INSTANCE.removeEntry(data.getId());
        message = intres.getLocalizedMessage("validator.removed_validator", data.getProfileName());
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", message);
        auditSession.log(EventTypes.VALIDATOR_REMOVAL, EventStatus.SUCCESS, ModuleTypes.VALIDATOR, ServiceTypes.CORE, admin.toString(), null, null,
                null, details);
        if (log.isTraceEnabled()) {
            log.trace("<removeKeyValidator()");
        }
    }

    @Override
    public void removeKeyValidator(AuthenticationToken admin, final String validatorName)
            throws AuthorizationDeniedException, CouldNotRemoveKeyValidatorException {
        if (log.isTraceEnabled()) {
            log.trace(">removeKeyValidator(id: " + validatorName + ")");
        }
        assertIsAuthorizedToEditValidators(admin);
        String message;

        List<ProfileData> datas = profileSession.findByNameAndType(validatorName, Validator.TYPE_NAME);
        if (datas == null) {
            if (log.isDebugEnabled()) {
                log.debug("Trying to remove a key validator that does not exist with name: " + validatorName);
            }
            return;
        } else {
            for (ProfileData data : datas) {
                if (caSession.existsKeyValidatorInCAs(data.getId())) {
                    throw new CouldNotRemoveKeyValidatorException();
                }
                profileSession.removeProfile(data);
                // Purge the cache here.
                ValidatorCache.INSTANCE.removeEntry(data.getId());
                message = intres.getLocalizedMessage("validator.removed_validator", data.getProfileName());
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", message);
                auditSession.log(EventTypes.VALIDATOR_REMOVAL, EventStatus.SUCCESS, ModuleTypes.VALIDATOR, ServiceTypes.CORE, admin.toString(), null,
                        null, null, details);
            }
        }

        if (log.isTraceEnabled()) {
            log.trace("<removeKeyValidator()");
        }
    }

    @Override
    public void flushKeyValidatorCache() {
        ValidatorCache.INSTANCE.flush();
        if (log.isDebugEnabled()) {
            log.debug("Flushed KeyValidator cache.");
        }
    }

    @Override
    public int addKeyValidator(AuthenticationToken admin, Validator validator) throws AuthorizationDeniedException, KeyValidatorExistsException {
        final int id = addValidatorInternal(admin, validator);
        final String message = intres.getLocalizedMessage("validator.added_validator", validator.getProfileName());
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", message);
        auditSession.log(EventTypes.VALIDATOR_CREATION, EventStatus.SUCCESS, ModuleTypes.VALIDATOR, ServiceTypes.CORE, admin.toString(), null, null,
                null, details);
        return id;
    }

    @Override
    public void cloneKeyValidator(final AuthenticationToken admin, final int validatorId, final String newName)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException {
        cloneKeyValidator(admin, getValidatorInternal(validatorId, true), newName);
    }

    @Override
    public void cloneKeyValidator(final AuthenticationToken admin, final Validator validator, final String newName)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException {
        Validator validatorClone = null;
        final Integer origProfileId = validator.getProfileId();
        if (origProfileId == null) {
            throw new KeyValidatorDoesntExistsException("Could not find key validator " + validator.getProfileName());
        }
        validatorClone = getValidator(origProfileId).clone();
        validatorClone.setProfileName(newName);
        try {
            addValidatorInternal(admin, validatorClone);
            final String message = intres.getLocalizedMessage("validator.cloned_validator", newName, validator.getProfileName());
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", message);
            auditSession.log(EventTypes.VALIDATOR_CREATION, EventStatus.SUCCESS, ModuleTypes.VALIDATOR, ServiceTypes.CORE, admin.toString(), null,
                    null, null, details);
        } catch (KeyValidatorExistsException e) {
            final String message = intres.getLocalizedMessage("validator.error.clone_validator", newName, validator.getProfileName());
            log.info(message);
            throw e;
        }
    }

    @Override
    public void renameKeyValidator(AuthenticationToken admin, final int validatorId, String newName)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException {
        renameKeyValidator(admin, getValidatorInternal(validatorId, true), newName);
    }

    @Override
    public void renameKeyValidator(AuthenticationToken admin, final Validator validator, String newName)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">renameKeyValidator(from " + validator.getProfileName() + " to " + newName + ")");
        }
        assertIsAuthorizedToEditValidators(admin);
        boolean success = false;
        if (profileSession.findByNameAndType(newName, Validator.TYPE_NAME).isEmpty()) {
            ProfileData data = profileSession.findById(validator.getProfileId());
            if (data != null) {
                data.setProfileName(newName);
                success = true;
                // Since loading a key validator is quite complex, we simple purge the cache here.
                ValidatorCache.INSTANCE.removeEntry(data.getId());
            }
        }
        if (success) {
            final String message = intres.getLocalizedMessage("validator.renamed_validator", validator.getProfileName(), newName);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", message);
            auditSession.log(EventTypes.VALIDATOR_RENAME, EventStatus.SUCCESS, ModuleTypes.VALIDATOR, ServiceTypes.CORE, admin.toString(), null, null,
                    null, details);
        } else {
            final String message = intres.getLocalizedMessage("validator.errorrenamekeyvalidator", validator.getProfileName(), newName);
            log.info(message);
            throw new KeyValidatorExistsException();
        }
        if (log.isTraceEnabled()) {
            log.trace("<renameKeyValidator()");
        }
    }

    @Override
    public Map<Integer, Validator> getAllKeyValidators() {
        final List<ProfileData> keyValidators = findAllProfiles(Validator.TYPE_NAME);
        final Map<Integer, Validator> result = new HashMap<>();
        final boolean enabled = ((ExternalScriptsConfiguration) globalConfigurationSession
                .getCachedConfiguration("0")).getEnableExternalScripts();
        for (ProfileData data : keyValidators) {
            if (!enabled && data.getProfile() instanceof ExternalCommandCertificateValidator) {
                if (log.isTraceEnabled()) {
                    log.trace("Skip " + data.getProfileType() + " with name " + data.getProfileName() + " because calls for external command certificate validators are disabled.");
                }
                continue;
            }
            //Cast is safe since we know we retrieved the correct implementation
            try {
                result.put(data.getId(), (Validator) data.getProfile());
            } catch (IllegalStateException e) {
                // NOPMD: Implementation not available in this version if EJBCA
            }
        }
        if (log.isDebugEnabled()) {
            for (Integer id : result.keySet()) {
                log.debug("Key validators found in datastore: " + id + ":" + result.get(id).getProfileName());
            }
        }
        return result;
    }

    // Not used.
    @Override
    public Map<Integer, Validator> getKeyValidatorsById(Collection<Integer> ids) {
        final List<ProfileData> keyValidators = findAllProfiles(Validator.TYPE_NAME);
        final Map<Integer, Validator> result = new HashMap<>();
        for (ProfileData data : keyValidators) {
            result.put(data.getId(), (Validator) data.getProfile());
        }
        if (log.isDebugEnabled()) {
            for (Integer id : result.keySet()) {
                log.debug("Key validators found in datastore: " + id + ":" + result.get(id).getProfileName());
            }
        }
        return result;
    }

    @Override
    public Map<Integer, String> getKeyValidatorIdToNameMap() {
        final HashMap<Integer, String> result = new HashMap<>();
        for (ProfileData data : findAllProfiles(Validator.TYPE_NAME)) {
            result.put(data.getId(), data.getProfileName());
        }
        return result;
    }

    @Override
    public Map<Integer, String> getKeyValidatorIdToNameMap(int applicableCa) {
        final HashMap<Integer, String> result = new HashMap<>();
        for (Entry<Integer,Validator> data : getAllKeyValidators().entrySet()) {
            if (data.getValue().getApplicableCaTypes().contains(applicableCa)) {
                result.put(data.getKey(), data.getValue().getProfileName());
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Found validators for applicable CAs " + applicableCa + ": " + result);
        }
        return result;
    }

    @Override
    public void validateDnsNames(final AuthenticationToken authenticationToken, final CA ca, final EndEntityInformation endEntityInformation,
            final RequestMessage requestMessage) throws ValidationException {
        if (!CollectionUtils.isEmpty(ca.getValidators())) {
            Validator baseValidator;
            DnsNameValidator validator;
            for (Integer id : ca.getValidators()) {
                baseValidator = getValidatorInternal(id, true);
                if (baseValidator != null && baseValidator.getValidatorSubType().equals(DnsNameValidator.class)) {
                    validator = (DnsNameValidator) baseValidator;
                    // Filter for validator criteria.
                    if (baseValidator instanceof CertificateProfileAwareValidator
                            && !filterCertificateProfileAwareValidator(validator, endEntityInformation.getCertificateProfileId())) {
                        continue;
                    }
                    CertificateProfile certificateProfile = certificateProfileSession
                            .getCertificateProfile(endEntityInformation.getCertificateProfileId());
                    final String subjectAltName = endEntityInformation.getSubjectAltName();
                    final List<String> dnsNames = new ArrayList<>();
                    for (String split : subjectAltName.split(",")) {
                        if (split.trim().toLowerCase().startsWith(CertTools.DNS.toLowerCase())) {
                            dnsNames.add(split.trim().substring(CertTools.DNS.length() + 1));
                        }
                    }
                    //If the certificate profile allows extension override, there may be SANs mixed in among the extensions in the request message
                    if (certificateProfile.getAllowExtensionOverride() && requestMessage != null) {
                        Extensions extensions = requestMessage.getRequestExtensions();
                        if (extensions != null) {
                            Extension extension = extensions.getExtension(Extension.subjectAlternativeName);
                            if (extension != null) {
                                String extendedSubjectAltName = CertTools.getAltNameStringFromExtension(extension);
                                for (String split : extendedSubjectAltName.split(",")) {
                                    if (split.trim().toLowerCase().startsWith(CertTools.DNS.toLowerCase())) {
                                        dnsNames.add(split.trim().substring(CertTools.DNS.length() + 1));
                                    }
                                }
                            }
                        }
                    }

                    Entry<Boolean, List<String>> result = validator.validate(executorService, dnsNames.toArray(new String[dnsNames.size()]));

                    final String validatorName = validator.getProfileName();
                    final List<String> messages = result.getValue();
                    if (!result.getKey()) {
                        // Validation has failed. Not security event as such, since it will break issuance and not cause anything important to happen.
                        // We want thorough logging in order to trouble shoot though
                        final String message = intres.getLocalizedMessage("validator.caa.validation_failed", validatorName,
                                validator.getIssuer(), messages);
                        log.info(EventTypes.VALIDATOR_VALIDATION_FAILED + ";" + EventStatus.FAILURE + ";" + ModuleTypes.VALIDATOR + ";" + ServiceTypes.CORE + ";msg=" + message);
                        final int index = validator.getFailedAction();
                        performValidationFailedActions(index, message, message);
                    } else {
                        // Validation succeeded, this can be considered a security audit event because CAs may be asked to present this as evidence to an auditor
                        final String message = intres.getLocalizedMessage("validator.caa.validation_successful", validatorName,
                                validator.getIssuer(),
                                messages);
                        final Map<String, Object> details = new LinkedHashMap<String, Object>();
                        details.put("msg", message);
                        auditSession.log(EventTypes.VALIDATOR_VALIDATION_SUCCESS, EventStatus.SUCCESS, ModuleTypes.VALIDATOR, ServiceTypes.CORE,
                                authenticationToken.toString(), String.valueOf(ca.getCAId()), null, endEntityInformation.getUsername(), details);
                    }

                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("No validators configured for CA " + ca.getName() + " (ID=" + ca.getCAId() + ").");
            }
        }
    }

    @Override
    public boolean validatePublicKey(final AuthenticationToken admin, final CA ca, EndEntityInformation endEntityInformation,
            CertificateProfile certificateProfile, Date notBefore, Date notAfter, PublicKey publicKey)
            throws ValidationException, IllegalValidityException {
        boolean result = true;
        if (ca != null && !CollectionUtils.isEmpty(ca.getValidators())) { // || certificateProfile.isTypeRootCA() || certificateProfile.isTypeSubCA()
            final CertificateValidity certificateValidity = new CertificateValidity(endEntityInformation, certificateProfile, notBefore, notAfter,
                    ca.getCACertificate(), false, false);
            if (log.isDebugEnabled()) {
                log.debug("Validate " + publicKey.getAlgorithm() + " public key with " + publicKey.getFormat() + " format.");
                log.debug("Certificate 'notBefore' " + certificateValidity.getNotBefore());
                log.debug("Certificate 'notAfter' " + certificateValidity.getNotAfter());
            }
            Validator baseValidator;
            KeyValidator validator;
            String name;
            for (Integer id : ca.getValidators()) {
                baseValidator = getValidatorInternal(id, true);
                if (baseValidator != null && baseValidator.getValidatorSubType().equals(KeyValidator.class)) {
                    validator = (KeyValidator) baseValidator;
                    name = validator.getProfileName();
                    if (log.isTraceEnabled()) {
                        log.trace("Try to apply key validator: " + validator.toDisplayString());
                    }
                    try {
                        // Filter for validator criteria.
                        if (validator instanceof CertificateProfileAwareValidator
                                && !filterCertificateProfileAwareValidator(validator, endEntityInformation.getCertificateProfileId())) {
                            continue;
                        }
                        if (validator instanceof ValidityAwareValidator
                                && !filterValidityAwareValidator(validator, certificateValidity.getNotBefore(), certificateValidity.getNotAfter())) {
                            continue;
                        }
                        final String fingerprint = CertTools.createPublicKeyFingerprint(publicKey, "SHA-256");
                        log.info(intres.getLocalizedMessage("validator.key.isbeingprocessed", name, endEntityInformation.getUsername(), fingerprint));
                        List<String> messages = validator.validate(publicKey, certificateProfile);
                        if (messages.size() > 0) { // Validation has failed.
                            result = false;
                            final int index = validator.getFailedAction();
                            final String message = intres.getLocalizedMessage("validator.key.validation_failed", name, messages);
                            final Map<String, Object> details = new LinkedHashMap<String, Object>();
                            details.put("msg", message);
                            auditSession.log(EventTypes.VALIDATOR_VALIDATION_FAILED, EventStatus.FAILURE, ModuleTypes.VALIDATOR, ServiceTypes.CORE,
                                    admin.toString(), String.valueOf(ca.getCAId()), fingerprint, endEntityInformation.getUsername(), details);
                            performValidationFailedActions(index, message);
                        } else {
                            final byte[] keyBytes = publicKey.getEncoded();
                            final String publicKeyEncoded = (keyBytes != null ? new String(Base64.encode(keyBytes)) : "null");
                            final String message = intres.getLocalizedMessage("validator.key.validation_successful", name, publicKeyEncoded);
                            log.info(message);
                            final Map<String, Object> details = new LinkedHashMap<String, Object>();
                            details.put("msg", message);
                            auditSession.log(EventTypes.VALIDATOR_VALIDATION_SUCCESS, EventStatus.SUCCESS, ModuleTypes.VALIDATOR, ServiceTypes.CORE,
                                    admin.toString(), String.valueOf(ca.getCAId()), null, endEntityInformation.getUsername(), details);
                        }
                    } catch (ValidatorNotApplicableException e) {
                        // This methods either throws a KeyValidationException, or just logs a message and validation should be considered successful
                        // use method performValidationFailedActions because it's the same actions
                        performValidationFailedActions(validator.getNotApplicableAction(), e.getMessage());
                    } catch (ValidationException e) {
                        throw e;
                    }
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("No key validator configured for CA " + ca.getName() + " (ID=" + ca.getCAId() + ").");
            }
        }
        return result;
    }

    @Override
    public void validateCertificate(final AuthenticationToken authenticationToken, final IssuancePhase phase, final CA ca,
            final EndEntityInformation endEntityInformation, final X509Certificate certificate) throws ValidationException {
        if (log.isDebugEnabled()) {
            log.debug("Validate certificate for phase " + phase);
        }
        if (ca != null && !CollectionUtils.isEmpty(ca.getValidators())) {
            Validator baseValidator;
            CertificateValidator validator;
            String name;
            for (Integer id : ca.getValidators()) {
                baseValidator = getValidatorInternal(id, true);
                if (baseValidator != null && baseValidator.getValidatorSubType().equals(CertificateValidator.class)) {
                    validator = (CertificateValidator) baseValidator;
                    name = validator.getProfileName();
                    if (phase.getIndex() != validator.getPhase()) {
                        continue;
                    }
                    if (validator instanceof CertificateProfileAwareValidator
                            && !filterCertificateProfileAwareValidator(validator, endEntityInformation.getCertificateProfileId())) {
                        continue;
                    }
                    if (validator instanceof ValidityAwareValidator
                            && !filterValidityAwareValidator(validator, certificate.getNotBefore(), certificate.getNotAfter())) {
                        continue;
                    }
                    try {
                        final String fingerprint = CertTools.createPublicKeyFingerprint(certificate.getPublicKey(), "SHA-256");
                        log.info(intres.getLocalizedMessage("validator.certificate.isbeingprocessed", name, phase, endEntityInformation.getUsername(),
                                fingerprint));
                        final ExternalScriptsConfiguration externalScriptsConfiguration = (ExternalScriptsConfiguration) globalConfigurationSession
                                .getCachedConfiguration("0");
                        final ExternalScriptsWhitelist externalScriptsWhitelist = ExternalScriptsWhitelist.fromText(
                                externalScriptsConfiguration.getExternalScriptsWhitelist(),
                                externalScriptsConfiguration.getIsExternalScriptsWhitelistEnabled());
                        final List<String> messages = validator.validate(ca, certificate, externalScriptsWhitelist);
                        if (messages.size() > 0) { // Evaluation has failed.
                            final String message = intres.getLocalizedMessage("validator.certificate.validation_failed", name, messages);
                            final Map<String, Object> details = new LinkedHashMap<String, Object>();
                            details.put("msg", message);
                            auditSession.log(EventTypes.VALIDATOR_VALIDATION_FAILED, EventStatus.FAILURE, ModuleTypes.VALIDATOR, ServiceTypes.CORE,
                                    authenticationToken.toString(), String.valueOf(ca.getCAId()), fingerprint, endEntityInformation.getUsername(),
                                    details);
                            performValidationFailedActions(validator.getFailedAction(), message);
                        } else {
                            final String message = intres.getLocalizedMessage("validator.certificate.validation_successful", name, fingerprint);
                            log.info(message);
                            final Map<String, Object> details = new LinkedHashMap<String, Object>();
                            details.put("msg", message);
                            auditSession.log(EventTypes.VALIDATOR_VALIDATION_SUCCESS, EventStatus.SUCCESS, ModuleTypes.VALIDATOR, ServiceTypes.CORE,
                                    authenticationToken.toString(), String.valueOf(ca.getCAId()), null, endEntityInformation.getUsername(), details);
                        }
                    } catch (ValidatorNotApplicableException e) {
                        // This methods either throws a KeyValidationException, or just logs a message and validation should be considered successful
                        // use method performValidationFailedActions because it's the same actions
                        performValidationFailedActions(validator.getNotApplicableAction(), e.getMessage());
                    } catch (CertificateException e) {
                        throw new ValidationException("Certificate to validate could not be parsed or decoded: " + e.getMessage(), e);
                    }
                }
            }
        }
    }

    // Method is never called.
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
        if (authorizationSession.isAuthorizedNoLogging(admin, keyValidatorAccessRule)) {
            final boolean rootAccess = authorizationSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource());
            final List<Integer> authorizedCPIDs = certificateProfileSession.getAuthorizedCertificateProfileIds(admin, 0);
            for (final Entry<Integer, String> entry : map.entrySet()) {
                // Check that administrator have access to all certificate profiles referenced by the validator
                Validator val = getValidator(entry.getKey());
                boolean allexists = true;
                for (final Integer nextcpid : val.getCertificateProfileIds()) {
                    if (log.isTraceEnabled()) {
                        log.trace("Validator '" + val.getProfileName() + "' has " + val.getCertificateProfileIds().size() + " no of CPs selected");
                    }
                    // If any CP is selected, it's access to all (only authorized will be displayed)
                    if (nextcpid.intValue() == -1) {
                        if (log.isDebugEnabled()) {
                            log.debug("Validator is applicable to all certificate profiles, not limiting access based on CPs");
                        }
                        allexists = true;
                        break;
                    }
                    // superadmin should be able to access profiles with missing CA Ids
                    if (!authorizedCPIDs.contains(nextcpid) && (!rootAccess)) {
                        if (log.isDebugEnabled()) {
                            log.debug("Validator have certificate profile " + nextcpid + " selected which admin is not authorized to:" + admin.toString());
                        }
                        allexists = false;
                        break;
                    }
                }
                if (allexists) {
                    result.add(entry.getKey());
                }
            }
        }
        return result;
    }

    @Override
    public List<Integer> getConflictingKeyValidatorIds(final Validator validator) {
        final List<ProfileData> conflicts = profileSession.findByNameAndType(validator.getProfileName(), Validator.TYPE_NAME);
        final List<Integer> conflictingValidatorIds = new ArrayList<>();
        for (final ProfileData conflict : conflicts) {
            conflictingValidatorIds.add(conflict.getId());
        }
        return conflictingValidatorIds;
    }

    @Override
    public void replaceKeyValidator(final AuthenticationToken authenticationToken, final LinkedHashMap<Object, Object> data, final int id)
            throws AuthorizationDeniedException {
        assertIsAuthorizedToEditValidators(authenticationToken);

        final Validator validatorToUpdate = getValidator(id);
        if (validatorToUpdate == null) {
            return;
        }
        validatorToUpdate.setDataMap(data);
        ValidatorCache.INSTANCE.flush();

        final String auditMessage = intres.getLocalizedMessage("validator.changed_validator", validatorToUpdate.getProfileName());
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", auditMessage);
        auditSession.log(EventTypes.VALIDATOR_CHANGE, EventStatus.SUCCESS, ModuleTypes.VALIDATOR, ServiceTypes.CORE, authenticationToken.toString(),
                null, null, null, details);
    }

    /**
     * Gets a validator by cache or database, can return null. Puts it into the cache, if not already present.
     *
     * @param id the validators id.
     * @param fromCache true if the validator can be taken from cache.
     * @return a cloned validator that can be used at will without affecting the cache contents, edits have to be saved with replaceKeyValidator
     * */
    private Validator getValidatorInternal(int id, boolean fromCache) {
        Validator result = null;
        // If we should read from cache, and we have an id to use in the cache, and the cache does not need to be updated
        if (fromCache && !ValidatorCache.INSTANCE.shouldCheckForUpdates(id)) {
            // Get from cache (or null)
            result = ValidatorCache.INSTANCE.getEntry(id);
        }

        // if we selected to not read from cache, or if the cache did not contain this entry
        if (result == null) {

            // We need to read from database because we specified to not get from cache or we don't have anything in the cache
            final ProfileData data = profileSession.findById(id);
            if (data != null) {
                result = (Validator) data.getProfile();
                if (log.isDebugEnabled()) {
                    log.debug("Load validator: " + result.getDataMap());
                }
                final int digest = data.getProtectString(0).hashCode();
                // The cache compares the database data with what is in the cache
                // If database is different from cache, replace it in the cache
                ValidatorCache.INSTANCE.updateWith(data.getId(), digest, data.getProfileName(), result);
            } else {
                // Ensure that it is removed from cache if it exists
                ValidatorCache.INSTANCE.removeEntry(id);
            }
        }
        if (result == null) {
            log.warn("Validator with id " + id + " didn't return any validator");
        }
        // We need to clone the validator, otherwise the cache contents will be modifiable from the outside
        if (result != null) {
            return result.clone();
        }
        return null;
    }

    /**
     * Adds a key validator or throws an exception.
     *
     * @param admin AuthenticationToken of administrator.
     * @param keyValidator the validator to add.
     * @return the profile ID
     */
    private int addValidatorInternal(AuthenticationToken admin, Validator keyValidator)
            throws AuthorizationDeniedException, KeyValidatorExistsException {
        assertIsAuthorizedToEditValidators(admin);
        if (profileSession.findByNameAndType(keyValidator.getProfileName(), Validator.TYPE_NAME).isEmpty()) {
            return profileSession.addProfile(keyValidator);
        } else {
            final String message = intres.getLocalizedMessage("validator.error.add_validator", keyValidator.getProfileName());
            log.info(message);
            throw new KeyValidatorExistsException();
        }
    }

    /**
     * Assert the administrator is authorized to edit key validators.
     *
     * @param admin AuthenticationToken of administrator.
     * @throws AuthorizationDeniedException if the administrator is not authorized to.
     * */
    private void assertIsAuthorizedToEditValidators(AuthenticationToken admin) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(admin, StandardRules.VALIDATOREDIT.resource())) {
            final String message = intres.getLocalizedMessage("store.editkeyvalidatornotauthorized", admin.toString());
            throw new AuthorizationDeniedException(message);
        }
    }

    /**
     * Applies validity conditions (see {@link KeyValidatorDateConditions}) to the validator.
     *
     * @param validator the validator.
     * @param certificateNotBefore the certificates not before validity.
     * @param certificateNotAfter the certificates not after validity.
     * @return false, if the conditions does not match.
     */
    private boolean filterValidityAwareValidator(final ValidityAwareValidator validator, final Date certificateNotBefore,
            final Date certificateNotAfter) {
        if (log.isTraceEnabled()) {
            log.trace("Try to apply validity aware validator: " + validator);
        }
        final String name = validator.getProfileName();
        boolean result = true;
        if (!KeyValidatorDateConditions.evaluate(validator.getNotBefore(), certificateNotBefore, validator.getNotBeforeCondition())) {
            if (log.isDebugEnabled()) {
                log.debug(intres.getLocalizedMessage("validator.filterconditiondoesnotmatch", name, "notBefore"));
            }
            result = false;
        }
        if (!KeyValidatorDateConditions.evaluate(validator.getNotAfter(), certificateNotAfter, validator.getNotAfterCondition())) {
            if (log.isDebugEnabled()) {
                log.debug(intres.getLocalizedMessage("validator.filterconditiondoesnotmatch", name, "notAfter"));
            }
            result = false;
        }
        return result;
    }

    /**
     * Applies certificate profile conditions to the validator.
     *
     * @param validator the validator.
     * @param certificateProfileId the certificate profile id.
     * @return false, if the conditions does not match.
     */
    private boolean filterCertificateProfileAwareValidator(final CertificateProfileAwareValidator validator,
            final int certificateProfileId) {
        if (log.isTraceEnabled()) {
            log.trace("Try to apply certificate profile aware validator: " + validator);
        }
        boolean result = true;
        final List<Integer> ids = validator.getCertificateProfileIds();
        final boolean isAll = validator.isAllCertificateProfileIds();
        if (!isAll && null != ids && !ids.contains(certificateProfileId)) {
            if (log.isDebugEnabled()) {
                log.debug(intres.getLocalizedMessage("validator.filterconditiondoesnotmatch", validator.getProfileName(), "applicableCertificateProfiles"));
            }
            result = false;
        }
        return result;
    }

    /**
     * Calling overloaded method performValidationFailedActions when parameter shortMessage should be the same as the message.
     *
     * @param failedAction
     * @param message
     * @throws ValidationException
     */
    private void performValidationFailedActions(final int failedAction, final String message) throws ValidationException {
        performValidationFailedActions(failedAction, message, message);
    }

    /**
     * Post processes every validation depending on its failed action.
     *
     * @param failedAction the failed action index (see {@link KeyValidationFailedActions}).
     * @param message the message to log.
     * @param shortMessage the error message to EJBCA Certificate Enrollment Error page
     * @throws ValidationException if a failed validation has to be abort the certificate issuance.
     * */
    private void performValidationFailedActions(final int failedAction, final String message, final String shortMessage) throws ValidationException {
        if (log.isDebugEnabled()) {
            log.debug("Perform post action " + failedAction + " - " + message);
        }
        if (KeyValidationFailedActions.LOG_INFO.getIndex() == failedAction) {
            log.info(message);
        } else if (KeyValidationFailedActions.LOG_WARN.getIndex() == failedAction) {
            log.warn(message);
        } else if (KeyValidationFailedActions.LOG_ERROR.getIndex() == failedAction) {
            log.error(message);
        } else if (KeyValidationFailedActions.ABORT_CERTIFICATE_ISSUANCE.getIndex() == failedAction) {
            throw new ValidationException(shortMessage);
        } else {
            // NOOP
            log.debug(message);
        }
    }

    /**
     * Gets all profiles by type.
     *
     * @param profileType the profile type.
     * @return all profiles that match that type. {@link ExternalCommandCertificateValidator} is only included if calls to external scripts are enabled.
     */
    @SuppressWarnings("unchecked")
    // profileType does not change here!
    private final List<ProfileData> findAllProfiles(final String profileType) {
        final List<ProfileData> profiles = profileSession.findAllProfiles(profileType);
        final boolean enabled = ((ExternalScriptsConfiguration) globalConfigurationSession
                .getCachedConfiguration("0")).getEnableExternalScripts();
        if (enabled) {
            return profiles;
        } else {
            final List<ProfileData> result = new ArrayList<ProfileData>();
            Class<? extends Serializable> profileClass;
            for (ProfileData profile: profiles) {
                if ((profileClass = (Class<? extends Serializable>) profile.getProfile().getDataMap().get("profile.type")) == null || !ExternalCommandCertificateValidator.class.getName().equals(profileClass.getName())) {
                    result.add(profile);
                }
            }
            return result;
        }
    }
}
