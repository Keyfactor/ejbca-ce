/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.ra.raadmin;

import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;

/**
 * Methods for performing validation against of an end entity against validators
 * 
 * @version $Id$
 */
public final class EndEntityValidationHelper {

    private static final Logger log = Logger.getLogger(EndEntityValidationHelper.class);
    
    private static Map<String,EndEntityFieldValidator> validatorCache = new HashMap<>();
    private static Set<String> nonExistentValidatorsCache = new HashSet<>();
    
    /** Static class, can't be instantiated */
    private EndEntityValidationHelper() { }
    
    /**
     * Checks a value with a set of validators.
     * @param field Name of field that is being checked. Can be a DN component name or another field name.
     * @param validation Map of validator classname and validator data. 
     * @param value Value to validate
     * @throws EndEntityFieldValidatorException if the given value does not pass validation
     */
    public static void checkValue(final String field, final Map<String,Serializable> validation, final String value) throws EndEntityFieldValidatorException {
        for (final Map.Entry<String, Serializable> entry : validation.entrySet()) {
            final String className = entry.getKey();
            
            final EndEntityFieldValidator validator = getValidator(className);
            if (validator != null) {
                final Serializable data = entry.getValue();
                validator.validate(field, data, value);
            }
        }
    }
    
    /**
     * Checks that the given validator data is valid with the given validator.
     * @param field Name of field that is being checked. Can be a DN component name or another field name.
     * @param className Class name of validator.
     * @param validatorData Validator-specific data to check (e.g. a regex for the RegexFieldValidator)
     * @throws EndEntityFieldValidatorException If the given validator data is not valid, or if the validator class was not found
     */
    public static void checkValidator(final String field, final String className, final Serializable validatorData) throws EndEntityFieldValidatorException {
        final EndEntityFieldValidator validator = getValidator(className);
        if (validator == null) {
            throw new EndEntityFieldValidatorException("Validator "+className+" could not be loaded");
        }
        validator.checkValidatorData(field, validatorData);
    }
    
    private static EndEntityFieldValidator getValidator(final String className) {
        final EndEntityFieldValidator existing = validatorCache.get(className);
        if (existing != null) {
            // Already cached
            return existing;
        }
        
        if (nonExistentValidatorsCache.contains(className)) {
            // Give up early
            return null;
        }
        
        final Class<?> klass;
        try {
            klass = Class.forName(className);
        } catch (ClassNotFoundException e) { 
            log.warn("Failed to load validator class "+className, e);
            nonExistentValidatorsCache.add(className);
            return null;
        }
        
        if (!EndEntityFieldValidator.class.isAssignableFrom(klass)) {
            log.warn("Class "+className+" will not be instantiated since it does not implement "+EndEntityFieldValidator.class.getName());
            nonExistentValidatorsCache.add(className);
            return null;
        }
        
        try {
            final EndEntityFieldValidator instance = (EndEntityFieldValidator)klass.newInstance();
            validatorCache.put(className, instance);
            return instance;
        } catch (InstantiationException e) {
            log.warn("Failed to instantiate end entity validation class "+className, e);
            nonExistentValidatorsCache.add(className);
            return null;
        } catch (IllegalAccessException e) {
            log.warn("Failed to instantiate end entity validation class "+className, e);
            nonExistentValidatorsCache.add(className);
            return null;
        }
    }
}
