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
 * DynamicUiModel / DynamicUiProperty String Validator.
 */
public final class StringValidator implements DynamicUiPropertyValidator<String> {
  
    private static final Logger log = Logger.getLogger(StringValidator.class);
    
    private static final long serialVersionUID = -9056661127174836804L;

    private static final String VALIDATOR_TYPE = "stringValidator";
    
    private static final InternalResources intres = InternalResources.getInstance();
    
    private String name;
    
    private int minLength = -1;
    
    private int maxLength = -1;
    
    private String regex;
    
    private String messageKey;

    /**
     * Creates a string validator.
     *  
     * @param minLength minimum length.
     * @param maxLength maximum length.
     * @param regex matching regular expression or null.
     * @param shortName short name to build message resource key.
     */
    private StringValidator(final int minLength, final int maxLength, final String regex, final String shortName) {
        if (maxLength < minLength) {
            throw new IllegalStateException("Maximum string length must not be smaller than its minimum length.");
        }
        this.minLength = minLength;
        this.maxLength = maxLength;
        this.regex = regex;
        messageKey = getMessageKey(shortName);
    }

    @Override
    public void validate(final String value) throws PropertyValidationException {
        validateString(value, name, minLength, maxLength, regex, messageKey);
    }

    @Override
    public String getValidatorType() {
        return VALIDATOR_TYPE;
    }
    
    /**
     * Creates a string validator.
     * 
     * @param minLength minimum length.
     * @param maxLength maximum length.
     * @return the new instance.
     */
    public static final StringValidator instance(final int minLength, final int maxLength) {
        return new StringValidator(minLength, maxLength, null, "");
    }
    
    /**
     * Returns a string validator for ASCII strings.
     * 
     * @param minLength minimum length.
     * @param maxLength maximum length.
     * @return the new instance.
     */
    public static final StringValidator asciiInstance(final int minLength, final int maxLength) {
        return new StringValidator(minLength, maxLength, "\\A\\p{ASCII}*\\z", "stringnotascii");
    }
    
    /**
     * Returns a string validator for base64 encoded strings.
     * 
     * @param minLength minimum length.
     * @param maxLength maximum length.
     * @return the new instance.
     */
    public static final StringValidator base64Instance(final int minLength, final int maxLength) {
        return new StringValidator(minLength, maxLength, "[A-Za-z0-9+/]*", "stringnotbase64");
    }   
    
    /**
     * Returns a string validator for PEM (base64) strings (including optional boundaries).
     * 
     * @param minLength minimum length.
     * @param maxLength maximum length.
     * @return the new instance.
     */
    public static final StringValidator pemInstance(final int minLength, final int maxLength) {
        return new StringValidator(minLength, maxLength, "[A-Za-z0-9+/=\\-\\s]*", "stringnotpem");
    }
    
    /**
     * Returns a string validator for base64url encoded strings.
     * 
     *  @see <a href="https://tools.ietf.org/html/rfc4648#section-5">RFC 4648: Base 64 Encoding with URL and Filename Safe Alphabet</a> 
     *  
     * @param minLength minimum string length or -1 for no constraint.
     * @param maxLength max string length or -1 for no constraint.
     * @return the new validator instance.
     */
    public static final StringValidator base64UrlInstance(final int minLength, final int maxLength) {
        return new StringValidator(minLength, maxLength, "[A-Za-z0-9_\\-=]*", "stringnotbase64url");
    }
    
    public static final void validateString(String value, String name, final int minLength, final int maxLength, final String regex, final String messageKey) throws PropertyValidationException{
        if (log.isDebugEnabled()) {
            log.debug( "Validate string '" + value + "' with min " + minLength + " and max " + maxLength + " characters.");
        }
        if (value != null) {
            value = value.trim();
        }
        if (minLength > 0 && value != null && value.length() < minLength) {
            throw new PropertyValidationException(name + ": " + intres.getLocalizedMessage("dynamic.property.validation.stringtooshort.failure", Integer.toString(minLength)));
        }
        if (maxLength > 0 && value != null && value.length() > maxLength) {
            throw new PropertyValidationException(name + ": " + intres.getLocalizedMessage("dynamic.property.validation.stringtoolong.failure", Integer.toString(maxLength)));
        }
        if (regex != null && regex.length() > 0 && !value.matches(regex)) {
            throw new PropertyValidationException(name + ": " + intres.getLocalizedMessage(messageKey, value));
        }
    }
    
    public static final boolean isAscii(final String value) {
        for (int i = 0; i < value.length(); i++) { 
            if (value.charAt(i) > 127) { 
                return false;
            }
        }
        return true;
    }
    
    private static final String getMessageKey(final String shortName) {
        return "dynamic.property.validation." + shortName + ".failure"; 
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
