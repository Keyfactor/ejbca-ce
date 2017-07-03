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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map.Entry;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.profiles.ProfileBase;

/**
 * BaseKeyValidator is a basic class that should be inherited by all types
 * of key validator in the system.
 *  
 *
 * @version $Id$
 */
public abstract class KeyValidatorBase extends ProfileBase implements Serializable, Cloneable, Validator {

    private static final long serialVersionUID = -335459158399850925L;

    /** Class logger. */
    private static final Logger log = Logger.getLogger(KeyValidatorBase.class);

    /** List separator. */
    private static final String LIST_SEPARATOR = ";";

    protected static final InternalResources intres = InternalResources.getInstance();

    public static final float LATEST_VERSION = 1F;

    public static final String TYPE = "type";
    protected static final String SETTINGS_TEMPLATE = "settingsTemplate";
    protected static final String DESCRIPTION = "description";
    protected static final String NOT_BEFORE = "notBefore";
    protected static final String NOT_BEFORE_CONDITION = "notBeforeCondition";
    protected static final String NOT_AFTER = "notAfter";
    protected static final String NOT_AFTER_CONDITION = "notAfterCondition";
    protected static final String CERTIFICATE_PROFILE_IDS = "certificateProfileIds";
    protected static final String FAILED_ACTION = "failedAction";

    // Values used for lookup that are not stored in the data hash map.
    private int id;

    /** Certificate profile reference of applied certificate profile. */
    protected CertificateProfile certificateProfile;

    /** Public key reference (set while validate). */
    protected PublicKey publicKey;

    /** List of validation errors. */
    protected List<String> messages = new ArrayList<String>();

    /**
     * Public constructor needed for deserialization.
     */
    public KeyValidatorBase() {
        super();
    }
    
    /**
     * Creates a new instance.
     */
    public KeyValidatorBase(final String name) {
        super(name);
        init();
    }

    /**
     * Creates a new instance with the same attributes as the given one.
     */
    public KeyValidatorBase(final KeyValidatorBase keyValidator) {
        this.data = new LinkedHashMap<Object, Object>(keyValidator.data);
        this.id = keyValidator.id;
    }

    @Override
    public String getProfileType() {
        return Validator.TYPE_NAME;
    }
    
    /**
     * Initializes uninitialized data fields.
     */
    public void init() {
        super.initialize();
        if (null == data.get(VERSION)) {
            data.put(VERSION, new Float(LATEST_VERSION));
        }
        if (null == data.get(SETTINGS_TEMPLATE)) {
            setSettingsTemplate(KeyValidatorSettingsTemplate.USE_CERTIFICATE_PROFILE_SETTINGS.getOption());
        }
        if (null == data.get(DESCRIPTION)) {
            setDescription(StringUtils.EMPTY);
        }
        if (null == data.get(CERTIFICATE_PROFILE_IDS)) {
            setCertificateProfileIds(new ArrayList<Integer>());
        }
        if (null == data.get(NOT_BEFORE_CONDITION)) {
            setNotBeforeCondition(KeyValidatorDateConditions.LESS_THAN.getIndex());
        }
        if (null == data.get(NOT_AFTER_CONDITION)) {
            setNotAfterCondition(KeyValidatorDateConditions.LESS_THAN.getIndex());
        }
        if (null == data.get(FAILED_ACTION)) {
            setFailedAction(KeyValidationFailedActions.DO_NOTHING.getIndex());
        }
    }

    @Override
    public void setKeyValidatorSettingsTemplate() {
    }

    @Override
    public void setCertificateProfile(CertificateProfile certificateProfile) {
        this.certificateProfile = certificateProfile;
    }

    @Override
    public Integer getSettingsTemplate() {
        return (Integer) data.get(SETTINGS_TEMPLATE);
    }

    @Override
    public void setSettingsTemplate(Integer option) {
        data.put(SETTINGS_TEMPLATE, option);
    }

    @Override
    public String getDescription() {
        return (String) data.get(DESCRIPTION);
    }

    @Override
    public void setDescription(String description) {
        data.put(DESCRIPTION, description);
    }

    @Override
    public Date getNotBefore() {
        return (Date) data.get(NOT_BEFORE);
    }

    @Override
    public void setNotBefore(Date date) {
        data.put(NOT_BEFORE, date);
    }

    @Override
    public int getNotBeforeCondition() {
        return ((Integer) data.get(NOT_BEFORE_CONDITION)).intValue();
    }

    @Override
    public void setNotBeforeCondition(int index) {
        data.put(NOT_BEFORE_CONDITION, index);
    }

    @Override
    public Date getNotAfter() {
        return (Date) data.get(NOT_AFTER);
    }

    @Override
    public void setNotAfter(Date date) {
        data.put(NOT_AFTER, date);
    }

    @Override
    public void setNotAfterCondition(int index) {
        data.put(NOT_AFTER_CONDITION, index);
    }

    @Override
    public int getNotAfterCondition() {
        return ((Integer) data.get(NOT_AFTER_CONDITION)).intValue();
    }

    @Override
    public PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public List<Integer> getCertificateProfileIds() {
        final String value = (String) data.get(CERTIFICATE_PROFILE_IDS);
        final List<Integer> result = new ArrayList<Integer>();
        // Can be empty String here.
        if (StringUtils.isNotBlank(value)) {
            final String[] tokens = value.trim().split(LIST_SEPARATOR);
            for (int i = 0, j = tokens.length; i < j; i++) {
                result.add(Integer.valueOf(tokens[i]));
            }
        }
        return result;
    }

    @Override
    public void setCertificateProfileIds(Collection<Integer> ids) {
        final StringBuilder builder = new StringBuilder();
        for (Integer id : ids) {
            if (builder.length() == 0) {
                builder.append(id);
            } else {
                builder.append(LIST_SEPARATOR).append(id);
            }
        }
        data.put(CERTIFICATE_PROFILE_IDS, builder.toString());
    }

    @Override
    public void setFailedAction(int index) {
        data.put(FAILED_ACTION, index);
    }

    public int getFailedAction() {
        return ((Integer) data.get(FAILED_ACTION)).intValue();
    }

    @Override
    public abstract String getTemplateFile();

    @Override
    public void upgrade() {
        if (log.isTraceEnabled()) {
            log.trace(">upgrade: " + getLatestVersion() + ", " + getVersion());
        }
        if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
            // New version of the class, upgrade.
            log.info(intres.getLocalizedMessage("keyvalidator.upgrade", new Float(getVersion())));
            init();
        }
    }

    @Override
    public abstract void before();

    @Override
    public boolean validate(PublicKey publicKey) throws KeyValidationException {
        this.publicKey = publicKey;
        return false;
    }

    @Override
    public abstract void after();

    @Override
    public List<String> getMessages() {
        return messages;
    }
    
    @Override
    public String toDisplayString() {
        final StringBuilder result = new StringBuilder();
        result.append("BaseKeyValidator [id=").append(id).append(", name=").append(getProfileName()).append(", certificateProfile=")
                .append(certificateProfile).append(", applicableCertificateProfileIds=").append(data.get(CERTIFICATE_PROFILE_IDS))
                .append(", notBefore=").append(data.get(NOT_BEFORE)).append(", notBeforeCondition=").append(data.get(NOT_BEFORE_CONDITION))
                .append(", notAfter=").append(data.get(NOT_AFTER)).append(", notAfterCondition=").append(data.get(NOT_AFTER_CONDITION))
                .append(", failedAction=").append(data.get(FAILED_ACTION)).append(", publicKey=").append(publicKey).append(", messages=")
                .append(messages);
        return result.toString();
    }
    
    @Override
    public Validator clone() {
        getType();
        Validator clone;
        try {
            clone = (Validator) getType().newInstance();
        } catch (InstantiationException | IllegalAccessException e) {
            throw new IllegalStateException("Could not instansiate class of type " + getType().getCanonicalName());
        }
        clone.setProfileName(getProfileName());
        clone.setProfileId(getProfileId());

        // We need to make a deep copy of the hashmap here
        LinkedHashMap<Object, Object> dataMap = new LinkedHashMap<>(data.size());
        for (final Entry<Object, Object> entry : data.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof ArrayList<?>) {
                // We need to make a clone of this object, but the stored immutables can still be referenced
                value = ((ArrayList<?>) value).clone();
            }
            dataMap.put(entry.getKey(), value);
        }
        clone.setDataMap(dataMap);
        return clone;
    }
    
    @Override
    protected void saveTransientObjects() {

    }

    @Override
    protected void loadTransientObjects() {
    }
    
    @Override
    public UpgradeableDataHashMap getUpgradableHashmap() {
        return this;
    }
    
}
