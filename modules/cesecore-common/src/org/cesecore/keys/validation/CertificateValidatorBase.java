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
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.time.DateUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.util.ui.DynamicUiModel;

/**
 * @version $Id$
 *
 */
public abstract class CertificateValidatorBase extends ValidatorBase implements CertificateValidator {

	private static final long serialVersionUID = 1L;

    /** Class logger. */
    private static final Logger log = Logger.getLogger(KeyValidatorBase.class);

    /** List of applicable CA types (see {@link #getApplicableCaTypes()}). */ 
    protected static List<Integer> APPLICABLE_CA_TYPES;
    
    /** List of applicable issuance phases (see {@link IssuancePhase}). */ 
    protected static List<Integer> APPLICABLE_PHASES;
    
    static {
        APPLICABLE_PHASES = new ArrayList<Integer>();
        APPLICABLE_PHASES.add(IssuancePhase.PRE_CERTIFICATE_VALIDATION.getIndex());
        APPLICABLE_PHASES.add(IssuancePhase.CERTIFICATE_VALIDATION.getIndex());
        
        APPLICABLE_CA_TYPES = new ArrayList<Integer>();
        APPLICABLE_CA_TYPES.add(CAInfo.CATYPE_X509);
    }
    
    /** Dynamic UI model extension. */
    protected DynamicUiModel uiModel;
    
    /**
     * Public constructor needed for deserialization.
     */
    public CertificateValidatorBase() {
        super();
    }

    /**
     * Creates a new instance.
     */
    public CertificateValidatorBase(final String name) {
        super(name);
    }

    @Override
    public List<Integer> getApplicableCaTypes() {
        return APPLICABLE_CA_TYPES;
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
    public List<Integer> getApplicablePhases() {
        return APPLICABLE_PHASES;
    }
    
    @Override
    public Class<? extends Validator> getValidatorSubType() {
        return CertificateValidator.class;
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
}
