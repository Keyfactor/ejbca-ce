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

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public enum KeyValidatorDateConditions {

    // @formatter:on
    LESS_THAN(0, "VALIDATORDATECONDITION_LESS_THAN"), 
    LESS_OR_EQUAL_THAN(1, "VALIDATORDATECONDITION_LESS_OR_EQUAL"), 
    GREATER_THAN(2, "VALIDATORDATECONDITION_GREATER_THAN"), 
    GREATER_OR_EQUAL_THAN(3, "VALIDATORDATECONDITION_GREATER_OR_EQUAL");
    // @formatter:off

//    /** Default date condition constant for the not before attribute. */
//    public static final KeyValidatorDateConditions DEFAULT_NOT_BEFORE = GREATER_OR_EQUAL_THAN;
//   
//    /** Default date condition constant for the not after attribute. */
//    public static final KeyValidatorDateConditions DEFAULT_NOT_AFTER = LESS_OR_EQUAL_THAN;
   
    /** The unique index. */
    private int index;

    /** The resource key or label. */
    private String label;

    /**
     * Creates a new instance.
     * 
     * @param index index
     * @param label resource key or label.
     */
    private KeyValidatorDateConditions(final int index, final String label) {
        this.index = index;
        this.label = label;
    }

    /**
     * Gets the index.
     * @return
     */
    public int getIndex() {
        return index;
    }

    /**
     * Gets the resource key or label.
     * @return
     */
    public String getLabel() {
        return label;
    }

    /**
     * Gets an Integer list instance containing all index.
     * @return
     */
    public static final List<Integer> index() {
        final List<Integer> result = new ArrayList<Integer>();
        for (KeyValidatorDateConditions condition : values()) {
            result.add(condition.getIndex());
        }
        return result;
    }
    
    /**
     * Evaluates a date matches the given condition. 
     * @param value the reference value.
     * @param testValue the test value.
     * @param index the index of the condition.
     * @return true if the condition matches.
     */
    public static final boolean evaluate(final Date value, final Date testValue, final int index) {
        boolean result = false;
        if (value == null || testValue == null) {
            return true;
        }
        if (index == 0) {
            result = testValue.before(value);
        } else if (index == 1) {
            result = new Date(testValue.getTime() - 1).before(value);
        } else if (index == 2) {
            result = testValue.after(value);
        } else if (index == 3) {
            result = !new Date(value.getTime() + 1).after(testValue);
        }
        return result;
    }
}
