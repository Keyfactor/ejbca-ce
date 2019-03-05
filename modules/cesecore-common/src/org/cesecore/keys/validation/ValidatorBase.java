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
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map.Entry;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CAInfo;
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
public abstract class ValidatorBase extends ProfileBase implements Serializable, Cloneable, Validator {

    private static final long serialVersionUID = -335459158399850925L;

    /** Class logger. */
    private static final Logger log = Logger.getLogger(ValidatorBase.class);

    protected static final InternalResources intres = InternalResources.getInstance();

    /** List of applicable issuance phases (see {@link IssuancePhase}). */ 
    private static List<Integer> APPLICABLE_PHASES;
    
    /** List of applicable CA types (see {@link #getApplicableCaTypes()}. */ 
    private static List<Integer> APPLICABLE_CA_TYPES;
        
    public static final float LATEST_VERSION = 7F;

    public static final String TYPE = "type";
    public static final String SETTINGS_TEMPLATE = "settingsTemplate";
    protected static final String PHASE = "phase";
    protected static final String DESCRIPTION = "description";
    protected static final String NOT_BEFORE = "notBefore";
    protected static final String NOT_BEFORE_CONDITION = "notBeforeCondition";
    protected static final String NOT_AFTER = "notAfter";
    protected static final String NOT_AFTER_CONDITION = "notAfterCondition";
    protected static final String ALL_CERTIFICATE_PROFILE_IDS = "allCertificateProfileIds";
    protected static final String CERTIFICATE_PROFILE_IDS = "certificateProfileIds";
    protected static final String FAILED_ACTION = "failedAction";
    protected static final String NOT_APPLICABLE_ACTION = "notApplicableAction";
        
    static {
        APPLICABLE_PHASES = new ArrayList<>();
        // Only DNS validators work with Approval Validation, so don't add it here.
        APPLICABLE_PHASES.add(IssuancePhase.DATA_VALIDATION.getIndex());
        APPLICABLE_PHASES.add(IssuancePhase.PRE_CERTIFICATE_VALIDATION.getIndex());
        APPLICABLE_PHASES.add(IssuancePhase.CERTIFICATE_VALIDATION.getIndex());
        
        APPLICABLE_CA_TYPES = new ArrayList<>();
        APPLICABLE_CA_TYPES.add(CAInfo.CATYPE_X509);
        APPLICABLE_CA_TYPES.add(CAInfo.CATYPE_CVC);
    }

    // Values used for lookup that are not stored in the data hash map.
    private int id;

    /**
     * Public constructor needed for deserialization.
     */
    public ValidatorBase() {
        super();
        init();
    }
    
    /**
     * Creates a new instance.
     */
    public ValidatorBase(final String name) {
        super(name);
        init();
    }
   
    @Override
    public List<Integer> getApplicableCaTypes() {
        return APPLICABLE_CA_TYPES;
    }

    @Override
    public String getProfileType() {
        return Validator.TYPE_NAME;
    }
    
    /**
     * Initializes uninitialized data fields.
     * <p>
     * <strong>WARNING:</strong> This method will be called before the data map is loaded when a validator is cloned (for example when copied from cache).
     */
    @Override
    public void init() {
        super.initialize();
        if (null == data.get(VERSION)) {
            data.put(VERSION, new Float(LATEST_VERSION));
        }
        if (null == data.get(PHASE)) {
            setPhase(getApplicablePhases().get(0));
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
        if (null == data.get(FAILED_ACTION)) {
            setFailedAction(KeyValidationFailedActions.ABORT_CERTIFICATE_ISSUANCE.getIndex());
        }
        if (null == data.get(NOT_APPLICABLE_ACTION)) {
            setNotApplicableAction(KeyValidationFailedActions.ABORT_CERTIFICATE_ISSUANCE.getIndex());
        }
        // Added in v2
        if (null == data.get(ALL_CERTIFICATE_PROFILE_IDS)) {
            setAllCertificateProfileIds(true);
        }
    }

    @Override
    public List<Integer> getApplicablePhases() {
        return APPLICABLE_PHASES;
    }
    
    @Override
    public int getPhase() {
        return ((Integer) data.get(PHASE)).intValue();
    }

    @Override
    public void setPhase(int index) {
        data.put(PHASE, index);
    }
    
    @Override
    public void setKeyValidatorSettingsTemplate(KeyValidatorSettingsTemplate template) {
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
    public boolean isAllCertificateProfileIds() {
        return ((Boolean) data.get(ALL_CERTIFICATE_PROFILE_IDS)).booleanValue();
    }
    
    @Override 
    public void setAllCertificateProfileIds(boolean isAll) {
        data.put(ALL_CERTIFICATE_PROFILE_IDS, Boolean.valueOf(isAll));
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

    @Override
    public int getFailedAction() {
        return ((Integer) data.get(FAILED_ACTION)).intValue();
    }

    @Override
    public void setNotApplicableAction(int index) {
        data.put(NOT_APPLICABLE_ACTION, index);
    }

    @Override
    public int getNotApplicableAction() {
        return ((Integer) data.get(NOT_APPLICABLE_ACTION)).intValue();
    }

    /** Implementation of UpgradableDataHashMap function getLatestVersion */
    @Override
    public float getLatestVersion(){
       return LATEST_VERSION;
    }

    @Override
    public void upgrade() {
        if (log.isTraceEnabled()) {
            log.trace(">upgrade: " + getLatestVersion() + ", " + getVersion());
        }
        super.upgrade();
        if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
            // New version of the class, upgrade.
            log.info(intres.getLocalizedMessage("validator.upgrade", new Float(getVersion())));
            init();
            // Finished upgrade, set new version
            data.put(VERSION, new Float(LATEST_VERSION));
        }
    }

    @Override
    public String toDisplayString() {
        final StringBuilder result = new StringBuilder();
        result.append("BaseKeyValidator [id=").append(id).append(", name=").append(getProfileName()).append(", applicableCertificateProfileIds=").append(data.get(CERTIFICATE_PROFILE_IDS))
                .append(", notBefore=").append(data.get(NOT_BEFORE)).append(", notBeforeCondition=").append(data.get(NOT_BEFORE_CONDITION))
                .append(", notAfter=").append(data.get(NOT_AFTER)).append(", notAfterCondition=").append(data.get(NOT_AFTER_CONDITION))
                .append(", failedAction=").append(data.get(FAILED_ACTION));
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
