/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token.p11;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;

/**
 * @version $Id$
 *
 */
/**
 * Defines how the slot is specified.
 */
public enum Pkcs11SlotLabelType {
    SLOT_LABEL("SLOT_LABEL", "Slot Label", null), 
    SLOT_INDEX("SLOT_INDEX", "Slot Index", IndexValidator.class), 
    SLOT_NUMBER("SLOT_NUMBER", "Slot Number", NumberValidator.class), 
    SUN_FILE("SUN_FILE", "Sun configuration file", null);

    private static final Logger log = Logger.getLogger(Pkcs11SlotLabelType.class);
    
    private static final Map<String, Pkcs11SlotLabelType> keyLookUpMap = new HashMap<String, Pkcs11SlotLabelType>();
    
    private final String description;
    private final String key;
    private final LabelTypeValidator validator;

    static {
        for (Pkcs11SlotLabelType type : Pkcs11SlotLabelType.values()) {
            keyLookUpMap.put(type.getKey(), type);
        }
    }
    
    private Pkcs11SlotLabelType(String key, String _description, Class<? extends LabelTypeValidator> validator) {
        this.description = _description;
        this.key = key;
        if (validator == null) {
            this.validator = null;
        } else {
            try {
                this.validator = validator.newInstance();
            } catch (InstantiationException e) {
                throw new RuntimeException("Could not instansiate " + validator, e);
            } catch (IllegalAccessException e) {
                throw new RuntimeException("Could not instansiate " + validator, e);
            }
        }
    }

    @Override
    public String toString() {
        return this.description;
    }
    
    public String getKey() {
        return key;
    }
    
    public String getDescription() {
        return description;
    }
    
    public static Pkcs11SlotLabelType getFromKey(String key) {
        return keyLookUpMap.get(key);
    }
    
    public boolean isEqual(Pkcs11SlotLabelType otherType) {
        return this.getKey().equals(otherType.getKey());
    }
    
    public boolean validate(String value) {
        if(validator != null) {
            return validator.validate(value);
        } else {
            return true;
        }
    }
    
    private static interface LabelTypeValidator {
        boolean validate(String value);
    }
    
    protected static class NumberValidator implements LabelTypeValidator {
        
        @Override
        public boolean validate(String value) {
            try {
                Long.parseLong(value);
                return true;
            } catch(NumberFormatException e) {
                if(log.isDebugEnabled()) {
                    log.debug(value + " was not a number.", e);
                }
                return false;
            }
        }   
    }

    protected static class IndexValidator extends NumberValidator {
        
        @Override
        public boolean validate(String value) {
            if(value.charAt(0) != 'i') {
                if(log.isDebugEnabled()) {
                    log.debug(value + " did not start with 'i'");
                }
                return false;
            }
            return super.validate(value.substring(1));
        }
    }
    
}
