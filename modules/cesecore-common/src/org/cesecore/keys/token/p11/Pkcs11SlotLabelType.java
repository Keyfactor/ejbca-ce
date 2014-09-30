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
package org.cesecore.keys.token.p11;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;

/**
 * This enum class represents the typing of a slot label. In PKCS#11 an HSM is split up into separate partitions known 
 * as 'slots' and each slot contains a token in a 1:1 relationship. In a fixed HSM (such as a PCI HSM or a NetHSM) the slots
 * can be viewed as partitions on a disk containing a token, while in a SmartCard based solution each slot can be viewed as a 
 * card reader and the physical card as the token. 
 * This is highly relevant, because it does not guarantee for any solution that token always resides in the same slot. Some 
 * fixed HSMs guarantee this (such as SafeNet and Utimaco) while some don't (such as Thales/nCipher). In a smartcard based HSM, naturally
 * cards will continuously switch slots. 
 *
 * For this reason there are at present four different ways of referring to a slot/token, and these are:
 *  * Slot Number   - the numeric representation of a slot. 0-indexed on certain HSMs, not on others.
 *  * Slot Index    - The index of the slot. Nearly always the same as the slot number. 
 *  * Slot Label    - In actuality the label of the token, so will stay constant even if the slot number shifts. 
 *  * Sun File      - Increasingly rare. Slot/token is defined by an external configuration file
 *  
 *  The Pkcs11SlotLabelType is made up of three fields. The first is the key, which is the string format in which the label
 *  type is persisted to the database and will require an upgrade instruction if it is ever changed. The second is a description
 *  which can be used for human friendly labels, and the last is a validator used to validate inputed values (such as checking that
 *  a slot number can be cast to an integer). 
 * 
 * @version $Id$
 *
 */

public enum Pkcs11SlotLabelType {
    SLOT_LABEL("SLOT_LABEL", "Slot Label", LabelValidator.class), 
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
    
    /**
     * 
     * @return the key of this slot label type
     */
    public String getKey() {
        return key;
    }
    
    /**
     * 
     * @return the human friendly description of this slot label type
     */
    public String getDescription() {
        return description;
    }
    
    
    /**
     * Returns a Pkcs11SlotLabelType based on a key
     * 
     * @param key a key, must belong to one of the predefine types.
     * @return the Pkcs11SlotLabelType. Returns null if not found. 
     */
    public static Pkcs11SlotLabelType getFromKey(String key) {
        return keyLookUpMap.get(key);
    }
    
    /**
     * Compares the keys of two slot label types. Defined because .equals for enums are final, which means that
     * .equals isn't always applicable for serialized objects. 
     * 
     * @param otherType the Pkcs11SlotLabelType to compare with
     * @return true if the two types have the same key.
     */
    public boolean isEqual(Pkcs11SlotLabelType otherType) {
        return this.getKey().equals(otherType.getKey());
    }
    
    /**
     * Validates a given value, depending on what validator this enum type was instantiated with. If no validator
     * has been defined, always return true. 
     * 
     * @param value the value to be validated
     * @return true if the value can be used for this type.
     */
    public boolean validate(String value) {
        if(validator != null) {
            return validator.validate(value);
        } else {
            return true;
        }
    }
    
    /**
     * An interface defining the private validator classes.
     * 
     * @version $Id$
     *
     */
    private static interface LabelTypeValidator {
        /**
         * 
         * @param value the value to check
         * @return true if the value is applicable
         */
        boolean validate(String value);
    }
    
    /**
     * Validates true if the inputed string can be cast to long integer.
     * 
     * @version $Id$
     *
     */
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

    /**
     * Validates true if the inputed values is an 'i' followed by a string that can be cast to a long integer. 
     * 
     * @version $Id$
     *
     */
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
    
    protected static class LabelValidator implements LabelTypeValidator {

        @Override
        public boolean validate(String value) {
           //According to the PKCS#11 standard, the label field can be max 32 chars long
            if(value.length() > 32) {
                if(log.isDebugEnabled()) {
                    log.debug("Value " + value + " was longer than the permitted 32 characters.");
                }
                return false;
            } else {
                return true;
            }
        }
        
    }
    
}
