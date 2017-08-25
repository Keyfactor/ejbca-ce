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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.commons.collections.CollectionUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
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
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.profiles.ProfileBase;
import org.cesecore.profiles.ProfileData;
import org.cesecore.profiles.ProfileSessionLocal;
import org.cesecore.util.CertTools;
import org.cesecore.util.SecureXMLDecoder;

/**
 * Handles management of key validators.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "KeyValidatorSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class KeyValidatorSessionBean implements KeyValidatorSessionLocal, KeyValidatorSessionRemote {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(KeyValidatorSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @EJB
    private AuthorizationSessionLocal authorizationSession;
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
        return getKeyValidatorInternal(id, true);
    }

    @Override
    public String getKeyValidatorName(int id) {
        if (log.isTraceEnabled()) {
            log.trace(">getKeyValidatorName(id: " + id + ")");
        }
        final Validator entity = getKeyValidatorInternal(id, true);
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
    public void importValidator(AuthenticationToken admin, Validator validator)
            throws AuthorizationDeniedException, KeyValidatorExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">addKeyValidator(name: " + validator.getProfileName() + ", id: " + validator.getProfileId() + ")");
        }
        addKeyValidatorInternal(admin, validator);
        final String message = intres.getLocalizedMessage("validator.added_validator", validator.getProfileName());
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", message);
        auditSession.log(EventTypes.VALIDATOR_CREATION, EventStatus.SUCCESS, ModuleTypes.VALIDATOR, ServiceTypes.CORE, admin.toString(), null,
                null, null, details);
        if (log.isTraceEnabled()) {
            log.trace("<addKeyValidator()");
        }
    }
    

    @Override
    public ValidatorImportResult importKeyValidatorsFromZip(final AuthenticationToken authenticationToken, final byte[] filebuffer)
            throws AuthorizationDeniedException, ZipException {
        List<Validator> importedValidators = new ArrayList<>();
        List<String> ignoredValidators = new ArrayList<>();
        if (filebuffer.length == 0) {
            throw new IllegalArgumentException("No input file");
        }
        final ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(filebuffer));
        try {
            ZipEntry ze = zis.getNextEntry();
            if (ze == null) {
                throw new ZipException("Was expecting a zip file.");
            }

            do {
                String filename = ze.getName();
                if (log.isDebugEnabled()) {
                    log.debug("Importing file: " + filename);
                }
                if (ignoreFile(filename)) {
                    ignoredValidators.add(filename);
                    continue;
                }
                try {
                    filename = URLDecoder.decode(filename, "UTF-8");
                } catch (UnsupportedEncodingException e) {
                    throw new IllegalStateException("UTF-8 was not a known character encoding", e);
                }
                int index1 = filename.indexOf("_");
                int index2 = filename.lastIndexOf("-");
                int index3 = filename.lastIndexOf(".xml");
                String nameToImport = filename.substring(index1 + 1, index2);
                int idToImport = 0;
                try {
                    idToImport = Integer.parseInt(filename.substring(index2 + 1, index3));
                } catch (NumberFormatException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("NumberFormatException parsing key validator id: " + e.getMessage());
                    }
                    ignoredValidators.add(filename);
                    continue;
                }
                if (log.isDebugEnabled()) {
                    log.debug("Extracted key validator name '" + nameToImport + "' and ID '" + idToImport + "'");
                }
                if (ignoreKeyValidator(filename, idToImport)) {
                    ignoredValidators.add(filename);
                    continue;
                }
                if (getValidator(idToImport) != null) {
                    log.warn("Key valildator id '" + idToImport + "' already exist in database. Adding with a new key validator id instead.");
                    idToImport = -1; // means we should create a new id when adding the key validator.
                }
                final byte[] filebytes = new byte[102400];
                int i = 0;
                while ((zis.available() == 1) && (i < filebytes.length)) {
                    filebytes[i++] = (byte) zis.read();
                }
                final Validator validator = getKeyValidatorFromByteArray(nameToImport, filebytes);
                if (validator == null) {
                    ignoredValidators.add(filename);
                    log.info("Ignoring validator " + filename);
                    continue;
                }
                try {
                    if (idToImport == -1) {
                        int validatorId =  addKeyValidator(authenticationToken, validator);
                        validator.setProfileId(validatorId);
                    } else {
                        if (getValidator(idToImport) == null) {
                            importValidator(authenticationToken, validator);
                        } else {
                            log.info("Ignoring validator " + validator.getProfileName() + " as it already exists.");
                            ignoredValidators.add(validator.getProfileName());
                        }
                    }
                } catch (KeyValidatorExistsException e) {
                    throw new IllegalStateException("Key validator already exists in spite of the fact that we've just checked that it doesn't.", e);
                }
                importedValidators.add(validator);
                log.info("Added key validator: " + nameToImport);
            } while ((ze = zis.getNextEntry()) != null);
            zis.closeEntry();
            zis.close();
        } catch (ZipException e) {
            throw e;
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected IOException caught.", e);
        }
        return new ValidatorImportResult(importedValidators, ignoredValidators);

    }

    /**
     * Gets a key validator by the XML file stored in the byte[].    
     * @param name the name of the key validator
     * @param bytes the XML file as bytes
     * @return the concrete key validator implementation.
     * @throws AuthorizationDeniedException if not authorized
     */
    @SuppressWarnings("unchecked")
    private Validator getKeyValidatorFromByteArray(final String name, final byte[] bytes) throws AuthorizationDeniedException {
        final ByteArrayInputStream is = new ByteArrayInputStream(bytes);
        Validator validator = null;
        try {
            final SecureXMLDecoder decoder = new SecureXMLDecoder(is);
            LinkedHashMap<Object, Object> data = null;
            try {
                data = (LinkedHashMap<Object, Object>) decoder.readObject();
                validator = ((Class<? extends Validator>) data.get(ProfileBase.PROFILE_TYPE)).newInstance();
                validator.setDataMap(data);
            } catch (IOException|InstantiationException | IllegalAccessException e) {
                log.info("Error parsing keyvalidator data: " + e.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("Full stack trace: ", e);
                }
                return null;
            } finally {
                decoder.close();
            }

            // Make sure certificate profiles exists.
            final List<Integer> certificateProfileIds = validator.getCertificateProfileIds();
            final ArrayList<Integer> certificateProfilesToRemove = new ArrayList<Integer>();
            for (Integer certificateProfileId : certificateProfileIds) {
                if (null == certificateProfileSession.getCertificateProfile(certificateProfileId)) {
                    certificateProfilesToRemove.add(certificateProfileId);
                }
            }
            for (Integer toRemove : certificateProfilesToRemove) {
                log.info("Warning: certificate profile with id " + toRemove + " was not found and will not be used in key validator '" + name + "'.");
                certificateProfileIds.remove(toRemove);
            }
            if (certificateProfileIds.size() == 0) {
                log.info("Warning: No certificate profiles left in key validator '" + name + "'.");
                certificateProfileIds.add(Integer.valueOf(CertificateProfile.ANYCA));
            }
            validator.setCertificateProfileIds(certificateProfileIds);
        } finally {
            try {
                is.close();
            } catch (IOException e) {
                throw new IllegalStateException("Unknown IOException was caught when closing stream", e);
            }
        }
        return validator;
    }

    /** 
     * Check ignore file.
     * @return true if the file shall be ignored from a key validator import, false if it should be imported. 
     */
    private boolean ignoreFile(final String filename) {
        if (!filename.endsWith(".xml")) {
            log.info(filename + " is not an XML file. IGNORED");
            return true;
        }

        if (filename.indexOf("_") < 0 || filename.lastIndexOf("-") < 0 || (filename.indexOf("keyvalidator_") < 0)) {
            log.info(filename + " is not in the expected format. " + "The file name should look like: keyvalidator_<name>-<id>.xml. IGNORED");
            return true;
        }
        return false;
    }

    /** 
     * Check ignore key validator.
     * @return true if the key validator should be ignored from a import because it already exists, false if it should be imported. 
     */
    private boolean ignoreKeyValidator(final String filename, final int id) {
        if (getValidator(id) != null) {
            log.info("Key validator with ID'" + id + "' already exist in database. IGNORED");
            return true;
        }
        return false;
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
            auditSession.log(EventTypes.VALIDATOR_CHANGE, EventStatus.SUCCESS, ModuleTypes.VALIDATOR, ServiceTypes.CORE, admin.toString(),
                    null, null, null, details);
        } else {
            message = intres.getLocalizedMessage("validator.error.change_validator", name);
            log.info(message);
            throw new KeyValidatorDoesntExistsException("Validator by ID " + validator.getProfileId() + " does not exist in database.");
        }
    }

    @Override
    public void removeKeyValidator(AuthenticationToken admin, final int validatorId)
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
            } else {
                if (caSession.existsKeyValidatorInCAs(data.getId())) {
                    throw new CouldNotRemoveKeyValidatorException();
                }
                profileSession.removeProfile(data);
                // Purge the cache here.
                ValidatorCache.INSTANCE.removeEntry(data.getId());
                message = intres.getLocalizedMessage("validator.removed_validator", data.getProfileName());
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", message);
                auditSession.log(EventTypes.VALIDATOR_REMOVAL, EventStatus.SUCCESS, ModuleTypes.VALIDATOR, ServiceTypes.CORE, admin.toString(),
                        null, null, null, details);
            }
   
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
                auditSession.log(EventTypes.VALIDATOR_REMOVAL, EventStatus.SUCCESS, ModuleTypes.VALIDATOR, ServiceTypes.CORE, admin.toString(),
                        null, null, null, details);                    
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
    public int addKeyValidator(AuthenticationToken admin, Validator validator)
            throws AuthorizationDeniedException, KeyValidatorExistsException {
        final int id = addKeyValidatorInternal(admin, validator);
        final String message = intres.getLocalizedMessage("validator.added_validator", validator.getProfileName());
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", message);
        auditSession.log(EventTypes.VALIDATOR_CREATION, EventStatus.SUCCESS, ModuleTypes.VALIDATOR, ServiceTypes.CORE, admin.toString(), null,
                null, null, details);
        return id;
    }

    @Override
    public void cloneKeyValidator(final AuthenticationToken admin, final int validatorId, final String newName)
            throws  AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException {
        cloneKeyValidator(admin, getKeyValidatorInternal(validatorId, true), newName);
    }
    
    @Override
    public void cloneKeyValidator(final AuthenticationToken admin, final Validator validator, final String newName)
            throws  AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException {
        Validator validatorClone = null;
        final Integer origProfileId = validator.getProfileId();
        if (origProfileId == null) {
            throw new KeyValidatorDoesntExistsException("Could not find key validator " + validator.getProfileName());
        }
        validatorClone = getValidator(origProfileId).clone();
        validatorClone.setProfileName(newName);
        try {
            addKeyValidatorInternal(admin, validatorClone);
            final String message = intres.getLocalizedMessage("validator.cloned_validator", newName, validator.getProfileName());
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", message);
            auditSession.log(EventTypes.VALIDATOR_CREATION, EventStatus.SUCCESS, ModuleTypes.VALIDATOR, ServiceTypes.CORE, admin.toString(),
                    null, null, null, details);
        } catch (KeyValidatorExistsException e) {
            final String message = intres.getLocalizedMessage("validator.error.clone_validator", newName, validator.getProfileName());
            log.info(message);
            throw e;
        }   
    }
    
    @Override
    public void renameKeyValidator(AuthenticationToken admin, final int validatorId, String newName)
            throws AuthorizationDeniedException, KeyValidatorDoesntExistsException, KeyValidatorExistsException {
        renameKeyValidator(admin, getKeyValidatorInternal(validatorId, true), newName);
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
            auditSession.log(EventTypes.VALIDATOR_RENAME, EventStatus.SUCCESS, ModuleTypes.VALIDATOR, ServiceTypes.CORE, admin.toString(),
                    null, null, null, details);
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
        final List<ProfileData> keyValidators = profileSession.findAllProfiles(Validator.TYPE_NAME);
        final Map<Integer, Validator> result = new HashMap<>();
        for (ProfileData data : keyValidators) {
            //Cast is safe since we know we retrieved the correct implementation
            result.put(data.getId(), (Validator) data.getProfile());
        }
        if (log.isDebugEnabled()) {
            for (Integer id: result.keySet()) {
                log.debug("Key validators found in datastore: " + id+":"+result.get(id).getProfileName());                
            }
        }
        return result;
    }

    @Override
    public Map<Integer, Validator> getKeyValidatorsById(Collection<Integer> ids) {
        final List<ProfileData> keyValidators = profileSession.findAllProfiles(Validator.TYPE_NAME);
        final Map<Integer, Validator> result = new HashMap<>();
        for (ProfileData data : keyValidators) {
            result.put(data.getId(), (Validator) data.getProfile());
        }
        if (log.isDebugEnabled()) {
            for (Integer id: result.keySet()) {
                log.debug("Key validators found in datastore: " + id+":"+result.get(id).getProfileName());                
            }
        }
        return result;
    }

    @Override
    public Map<Integer, String> getKeyValidatorIdToNameMap() {
        final HashMap<Integer, String> result = new HashMap<>();
        for (ProfileData data : profileSession.findAllProfiles(Validator.TYPE_NAME)) {
            result.put(data.getId(), data.getProfileName());
        }
        return result;
    }

    @Override
    public Map<String, Integer> getKeyValidatorNameToIdMap() {
        final LinkedHashMap<String, Integer> result = new LinkedHashMap<>();
        List<ProfileData> profiles = profileSession.findAllProfiles(Validator.TYPE_NAME);
        Collections.sort(profiles, new Comparator<ProfileData>() {
            @Override
            public int compare(ProfileData o1, ProfileData o2) {
                return o1.getProfileName().compareToIgnoreCase(o2.getProfileName());
            }
        });
        for (ProfileData data : profiles) {
            result.put(data.getProfileName(), data.getId());
        }
        return result;
    }

    @Override
    public void validateDnsNames(final AuthenticationToken authenticationToken, final CA ca, final EndEntityInformation endEntityInformation,
            final RequestMessage requestMessage) throws ValidationException {
        if (!CollectionUtils.isEmpty(ca.getValidators())) { 
            Validator validator;
            DnsNameValidator dnsNameValidator;
            for (Integer id : ca.getValidators()) {
                validator = getKeyValidatorInternal(id, true);
                if (validator != null && validator.getValidatorSubType().equals(DnsNameValidator.class)) {
                    dnsNameValidator = (DnsNameValidator) validator;
                    final String name = dnsNameValidator.getProfileName();

                    // Filter for base key validator critieria.
                    final List<Integer> certificateProfileIds = dnsNameValidator.getCertificateProfileIds();
                    final boolean allCertProfiles = dnsNameValidator.isAllCertificateProfileIds();
                    if (!allCertProfiles && null != certificateProfileIds
                            && !certificateProfileIds.contains(endEntityInformation.getCertificateProfileId())) {
                        if (log.isDebugEnabled()) {
                            log.debug(intres.getLocalizedMessage("validator.filterconditiondoesnotmatch", name, "applicableCertificateProfiles"));
                        }
                        continue;
                    }
                    CertificateProfile certificateProfile = certificateProfileSession.getCertificateProfile(endEntityInformation.getCertificateProfileId());
                    String subjectAltName = endEntityInformation.getSubjectAltName();
                    List<String> dnsNames = new ArrayList<>();
                    for (String split : subjectAltName.split(", ")) {
                        if (split.trim().toLowerCase().startsWith(CertTools.DNS.toLowerCase())) {
                            dnsNames.add(split.substring(CertTools.DNS.length() + 1));
                        }
                    }
                    //If the certificate profile allows extension override, there may be SANs mixed in among the extensions in the request message
                    if (certificateProfile.getAllowExtensionOverride()) {
                        Extensions extensions = requestMessage.getRequestExtensions();
                        if (extensions != null) {
                            Extension extension = extensions.getExtension(Extension.subjectAlternativeName);
                            if (extension != null) {
                                String extendedSubjectAltName = CertTools.getAltNameStringFromExtension(extension);
                                for (String split : extendedSubjectAltName.split(", ")) {
                                    if (split.trim().toLowerCase().startsWith(CertTools.DNS.toLowerCase())) {
                                        dnsNames.add(split.substring(CertTools.DNS.length() + 1));
                                    }
                                }
                            }
                        }
                    }
                    
                    List<String> messages = dnsNameValidator.validate(dnsNames.toArray(new String[dnsNames.size()]));
                    final String validatorName = dnsNameValidator.getProfileName();
                    if (messages.size() > 0) { // Evaluation has failed.
                        final String message = intres.getLocalizedMessage("validator.caa.validation_failed", validatorName, dnsNameValidator.getIssuer(), messages);
                        final Map<String, Object> details = new LinkedHashMap<String, Object>();
                        details.put("msg", message);
                        auditSession.log(EventTypes.VALIDATOR_VALIDATION_FAILED, EventStatus.FAILURE, ModuleTypes.VALIDATOR, ServiceTypes.CORE, authenticationToken.toString(),
                                String.valueOf(ca.getCAId()), null, endEntityInformation.getUsername(), details);
                        final int index = dnsNameValidator.getFailedAction();
                        performValidationFailedActions(index, message);
                    } else {
                        final String message = intres.getLocalizedMessage("validator.caa.validation_successful", validatorName, dnsNameValidator.getIssuer());
                        log.info(message);
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
    public boolean validatePublicKey(final AuthenticationToken admin, final CA ca, EndEntityInformation endEntityInformation, CertificateProfile certificateProfile, Date notBefore,
            Date notAfter, PublicKey publicKey) throws ValidationException, IllegalValidityException {
        boolean result = true;
        if (ca != null && !CollectionUtils.isEmpty(ca.getValidators())) { // || certificateProfile.isTypeRootCA() || certificateProfile.isTypeSubCA()
            final CertificateValidity certificateValidity = new CertificateValidity(endEntityInformation, certificateProfile, notBefore, notAfter,
                    ca.getCACertificate(), false, false);
            if (log.isDebugEnabled()) {
                log.debug("Validate " + publicKey.getAlgorithm() + " public key with " + publicKey.getFormat() + " format.");
                log.debug("Certificate 'notBefore' " + certificateValidity.getNotBefore());
                log.debug("Certificate 'notAfter' " + certificateValidity.getNotAfter());
            }
            Validator validator;
            KeyValidator keyValidator;
            for (Integer id : ca.getValidators()) {
                validator = getKeyValidatorInternal(id, true);
                if (validator != null && validator.getValidatorSubType().equals(KeyValidator.class)) {
                    keyValidator = (KeyValidator) validator;
                    final String name = keyValidator.getProfileName();
                    if (log.isTraceEnabled()) {
                        log.trace("Try to apply key validator: " + keyValidator.toDisplayString());
                    }
                    try {
                        // Filter for base key validator critieria.
                        final List<Integer> certificateProfileIds = keyValidator.getCertificateProfileIds();
                        final boolean allCertProfiles = keyValidator.isAllCertificateProfileIds();
                        if (!allCertProfiles && null != certificateProfileIds
                                && !certificateProfileIds.contains(endEntityInformation.getCertificateProfileId())) {
                            if (log.isDebugEnabled()) {
                                log.debug(intres.getLocalizedMessage("validator.filterconditiondoesnotmatch", name, "applicableCertificateProfiles"));
                            }
                            continue;
                        }
                        if (!KeyValidatorDateConditions.evaluate(keyValidator.getNotBefore(), certificateValidity.getNotBefore(),
                                keyValidator.getNotBeforeCondition())) {
                            if (log.isDebugEnabled()) {
                                log.debug(intres.getLocalizedMessage("validator.filterconditiondoesnotmatch", name, "notBefore"));
                            }
                            continue;
                        }
                        if (!KeyValidatorDateConditions.evaluate(keyValidator.getNotAfter(), certificateValidity.getNotAfter(),
                                keyValidator.getNotAfterCondition())) {
                            if (log.isDebugEnabled()) {
                                log.debug(intres.getLocalizedMessage("validator.filterconditiondoesnotmatch", name, "notAfter"));
                            }
                            continue;
                        }
                        final String fingerprint = CertTools.createPublicKeyFingerprint(publicKey, "SHA-256");
                        log.info(intres.getLocalizedMessage("validator.key.isbeingprocessed", name, endEntityInformation.getUsername(), fingerprint));
                        List<String> messages = keyValidator.validate(publicKey, certificateProfile);
                        if (messages.size() > 0) {
                            result = false;
                            final String keyValidatorName = keyValidator.getProfileName();
                            if (messages.size() > 0) { // Evaluation has failed.
                                final int index = keyValidator.getFailedAction();
                                final String message = intres.getLocalizedMessage("validator.key.validation_failed", keyValidatorName, messages);
                                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                                details.put("msg", message);
                                auditSession.log(EventTypes.VALIDATOR_VALIDATION_FAILED, EventStatus.FAILURE, ModuleTypes.VALIDATOR, ServiceTypes.CORE, admin.toString(),
                                        String.valueOf(ca.getCAId()), fingerprint, endEntityInformation.getUsername(), details);
                                performValidationFailedActions(index, message);
                            } else {
                                final String message = intres.getLocalizedMessage("validator.key.validation_successful", keyValidatorName, publicKey.getEncoded());
                                log.info(message);
                            }
                        }
                    } catch (ValidatorNotApplicableException e) {
                        // This methods either throws a KeyValidationException, or just logs a message and validation should be considered successful
                        // use method performValidationFailedActions because it's the same actions
                        performValidationFailedActions(keyValidator.getNotApplicableAction(), e.getMessage());
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

    private void performValidationFailedActions(final int index, final String message) throws ValidationException {
        if (KeyValidationFailedActions.LOG_INFO.getIndex() == index) {
            log.info(message);
        } else if (KeyValidationFailedActions.LOG_WARN.getIndex() == index) {
            log.warn(message);
        } else if (KeyValidationFailedActions.LOG_ERROR.getIndex() == index) {
            log.error(message);
        } else if (KeyValidationFailedActions.ABORT_CERTIFICATE_ISSUANCE.getIndex() == index) {
            if (log.isDebugEnabled()) {
                log.debug("Action ABORT_CERTIFICATE_ISSUANCE: "+ message);                    
            }
            throw new ValidationException(message);
        } else {
            // NOOP
            log.debug(message);
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
        if (authorizationSession.isAuthorizedNoLogging(admin, keyValidatorAccessRule)) {
            final boolean rootAccess = authorizationSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource());
            final List<Integer> authorizedCPIDs = certificateProfileSession.getAuthorizedCertificateProfileIds(admin, 0);
            for (final Entry<Integer, String> entry : map.entrySet()) {
                // Check that administrator have access to all certificate profiles referenced by the validator
                Validator val = getValidator(entry.getKey());
                boolean allexists = true;
                for (final Integer nextcpid : val.getCertificateProfileIds()) {
                    if (log.isTraceEnabled()) {
                        log.trace("Validator '"+val.getProfileName()+"' has "+val.getCertificateProfileIds().size()+" no of CPs selected");
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
                            log.debug("Validator have certificate profile "+nextcpid+" selected which admin is not authorized to:"+admin.toString());
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

    /** Adds a key validator or throws an exception. 
     * @return the profile ID
     */
    private int addKeyValidatorInternal(AuthenticationToken admin, Validator keyValidator)
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

    /** Gets a key validator by cache or database, can return null. Puts it into the cache, if not already present. */
    private Validator getKeyValidatorInternal(int id, boolean fromCache) {
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
            log.warn("Validator with id "+id+" didn't return any validator");
        }
        return result;
    }

    /** Assert the administrator is authorized to edit key validators. */
    private void assertIsAuthorizedToEditValidators(AuthenticationToken admin) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(admin, StandardRules.VALIDATOREDIT.resource())) {
            final String message = intres.getLocalizedMessage("store.editkeyvalidatornotauthorized", admin.toString());
            throw new AuthorizationDeniedException(message);
        }
    }
}
