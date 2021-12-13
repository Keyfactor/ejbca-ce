/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.util.ui;

import org.apache.log4j.Logger;
import org.cesecore.internal.InternalResources;

/**
 * DynamicUiModel / DynamicUiProperty Integer Validator.
 */
public final class IntegerValidator implements DynamicUiPropertyValidator<Integer> {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(IntegerValidator.class);
    
    private static final long serialVersionUID = 8775592914355238649L;

    private static final String VALIDATOR_TYPE = "integerValidator";
    
    private static final InternalResources intres = InternalResources.getInstance();
    
    private String name;
    
    private int min = Integer.MIN_VALUE;
    
    private int max = Integer.MAX_VALUE;
    
    /**
     * Creates an integer validator.
     */
    private IntegerValidator() {
    }
    
    /**
     * Creates an integer validator with a minimum value.
     * 
     * @param min the minimum value (included).
     */
    private IntegerValidator(final int min) {
        this.min = min;
    }
    
    /**
     * Creates an integer validator with a range.
     * 
     * @param min the minimum value (included).
     * @param max the maximum value (included).
     */
    private IntegerValidator(final int min, final int max) {
        this.min = min;
        this.max = max;
    }
    
    @Override
    public void validate(Integer value) throws PropertyValidationException {
        validateInteger(value, name, min, max);
    }

    @Override
    public String getValidatorType() {
        return VALIDATOR_TYPE;
    }
    
    /**
     * Returns an integer validator.
     * 
     * @see Integer#MIN_VALUE
     * @see Integer#MAX_VALUE
     * 
     * @return the new instance.
     */
    public static final IntegerValidator instance() {
        return new IntegerValidator();
    }
    
    /**
     * Returns an integer validator.
     * 
     * @see Integer#MAX_VALUE
     * 
     * @param min the minimum value.
     * @return the new instance.
     */
    public static final IntegerValidator minInstance(final int min) {
        return new IntegerValidator(min);
    }
    
    /**
     * Returns an integer validator.
     * 
     * @see Integer#MIN_VALUE
     * 
     * @param max the maximum value.
     * @return the new instance.
     */
    public static final IntegerValidator maxInstance(final int max) {
        return new IntegerValidator(Integer.MIN_VALUE, max);
    }
    
    /**
     * Returns an integer validator for a range.
     * 
     * @param min the minimum value.
     * @param max the maximum value.
     * 
     * @return the new instance.
     */
    public static final IntegerValidator rangeInstance(final int min, final int max) {
        return new IntegerValidator(min, max);
    }
    
    /**
     * Validates an integer against the given borders.
     * 
     * @param value the integer value.
     * @param min the minimum value.
     * @param max the maximum value.
     * 
     * @throws PropertyValidationException if the validation fails.
     */
    public static void validateInteger(final Integer value, final String name, final int min, final int max) throws PropertyValidationException {
        if (log.isDebugEnabled()) {
            log.debug("Validate Integer " + value + " between [" + min + ", " + max + "].");
        }
        if (value < min) {
            throw new PropertyValidationException(name + ": " + intres.getLocalizedMessage("dynamic.property.validation.integertoosmall.failure", value.toString()));
        }
        if (value > max) {
            throw new PropertyValidationException(name + ": " + intres.getLocalizedMessage("dynamic.property.validation.integertoobig.failure", value.toString()));
        }
    }
    
    @Override
    public String getName() {
        return name;
    }
    
    @Override
    public void setName(String name) {
        this.name = name;
    }

}
