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

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.time.DateUtils;
import org.apache.log4j.Logger;
import org.cesecore.util.ui.DateValidator;
import org.cesecore.util.ui.DynamicUiModel;
import org.cesecore.util.ui.DynamicUiProperty;

public abstract class KeyValidatorBase extends ValidatorBase implements KeyValidator {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(KeyValidatorBase.class);
    
    private static final long serialVersionUID = 1L;
    
    /** Dynamic UI model extension. */
    protected DynamicUiModel uiModel;
    
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
    }

    @Override
    public void init() {
        super.init();
        if (null == data.get(PHASE)) {
            setPhase(getApplicablePhases().get(0));
        }
        if (null == data.get(NOT_BEFORE_CONDITION)) {
            setNotBeforeCondition(KeyValidatorDateConditions.LESS_THAN.getIndex());
        }
        if (null == data.get(NOT_AFTER_CONDITION)) {
            setNotAfterCondition(KeyValidatorDateConditions.LESS_THAN.getIndex());
        }
    }
   
    @Override
    public void initDynamicUiModel() {
        uiModel = new DynamicUiModel(data);
        uiModel.add(new DynamicUiProperty<String>("settings"));
        
        final DynamicUiProperty<Integer> issuedBeforeCondition = new DynamicUiProperty<>(Integer.class, NOT_BEFORE_CONDITION, getNotBeforeCondition(), KeyValidatorDateConditions.index());
        final DynamicUiProperty<String> notBefore = new DynamicUiProperty<String>(String.class, NOT_BEFORE, getNotBeforeAsString());
        issuedBeforeCondition.setRenderingHint(DynamicUiProperty.RENDER_SELECT_ONE);
        issuedBeforeCondition.setLabels(KeyValidatorDateConditions.map());
        issuedBeforeCondition.setRequired(true);
        notBefore.setValidator(new DateValidator());
        
        final DynamicUiProperty<Integer> issuedAfterCondition = new DynamicUiProperty<>(Integer.class, NOT_AFTER_CONDITION, getNotAfterCondition(), KeyValidatorDateConditions.index());
        final DynamicUiProperty<String> notAfter = new DynamicUiProperty<String>(String.class, NOT_AFTER, getNotAfterAsString());
        issuedAfterCondition.setRenderingHint(DynamicUiProperty.RENDER_SELECT_ONE);
        issuedAfterCondition.setLabels(KeyValidatorDateConditions.map());
        issuedAfterCondition.setRequired(true);
        notAfter.setValidator(new DateValidator());

        uiModel.add(issuedBeforeCondition);
        uiModel.add(notBefore);
        uiModel.add(issuedAfterCondition);
        uiModel.add(notAfter);
    }

    @Override
    public List<Integer> getApplicablePhases() {
        return new ArrayList<>(Arrays.asList(IssuancePhase.DATA_VALIDATION.getIndex()));
    }
    
    @Override
    public Class<? extends Validator> getValidatorSubType() {
        return KeyValidator.class;
    }
    
    @Override
    public Date getNotBefore() {
        // Prior ECA-6320, dates were stored as serialized java.util.Date
        if (data.get(NOT_BEFORE) instanceof Date) {
            return (Date) data.get(NOT_BEFORE);
        }
        try {
            return parseDate((String)data.get(NOT_BEFORE));
        } catch (ParseException e) {
            log.warn("Could not parse 'notBefore' date from database: '" + (String)data.get(NOT_BEFORE) + "'");
            return null;
        }
    }

    @Override
    public void setNotBefore(Date date) {
        data.put(NOT_BEFORE, date);
    }

    @Override
    public int getNotBeforeCondition() {
        return (int) data.get(NOT_BEFORE_CONDITION);
    }

    @Override
    public void setNotBeforeCondition(int index) {
        data.put(NOT_BEFORE_CONDITION, index);
    }

    @Override
    public Date getNotAfter() {
        // Prior ECA-6320, dates were stored as serialized java.util.Date
        if (data.get(NOT_AFTER) instanceof Date) {
            return (Date) data.get(NOT_AFTER);
        }
        try {
            return parseDate((String)data.get(NOT_AFTER));
        } catch (ParseException e) {
            log.warn("Could not parse 'notAfter' date from database: '" + (String)data.get(NOT_AFTER) + "'");
            return null;
        }
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
        return (int) data.get(NOT_AFTER_CONDITION);
    }

    
    @Override
    public String getNotBeforeAsString() {
        return formatDate(getNotBefore());
    }
    
    @Override
    public String getNotAfterAsString() {
        return formatDate(getNotAfter());
    }

    @Override
    public void setNotBeforeAsString(String formattedDate) {
        try {
            setNotBefore(parseDate(formattedDate));
        } catch (ParseException e) {
            log.debug("Could not parse Date: " + formattedDate);
        }
    }
    
    @Override
    public void setNotAfterAsString(String formattedDate) {
        try {
            setNotAfter(parseDate(formattedDate));
        } catch (ParseException e) {
            log.debug("Could not parse Date: " + formattedDate);
        }
    }
    
    @Override
    public DynamicUiModel getDynamicUiModel() {
        return uiModel;
    }

    /**
     * Parses a date string with the date format list.
     * @param string the formatted date string.
     * @return the date or null, if the date could not be parsed.
     * @throws ParseException if the date couldn't be parsed
     */
    public static Date parseDate(String string) throws ParseException {
        Date result = null;
        if (StringUtils.isNotBlank(string)) {
            final String dateString = string.trim();
                result = DateUtils.parseDate(dateString, DATE_FORMAT);
  
        }
        return result;
    }
    
    public int getKeyValidatorSettingsTemplate() {
        return getSettingsTemplate();
    }
    
    public void setKeyValidatorSettingsTemplate(int settings) {
        setKeyValidatorSettingsTemplate(KeyValidatorSettingsTemplate.fromIndex(settings));
    }
    
    public boolean hasKeyValidatorSettingsTemplate() {
        return getValidatorTypeIdentifier().equalsIgnoreCase(EccKeyValidator.TYPE_IDENTIFIER) ||
                getValidatorTypeIdentifier().equalsIgnoreCase(RsaKeyValidator.TYPE_IDENTIFIER); 
    }
}
