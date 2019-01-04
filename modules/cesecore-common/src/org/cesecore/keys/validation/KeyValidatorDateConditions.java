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

import org.cesecore.util.IndexEnum;

/**
 * This class contains a representation of mathematical conditions, i.e <, <=, >, >=.
 * @version $Id$
 */
public enum KeyValidatorDateConditions implements IndexEnum {
    /**
     * Condition for strictly less than a given date.
     */
    LESS_THAN(0, "VALIDATORDATECONDITION_LESS_THAN", "<"),
    /**
     * Condition for less than or equal to a given date.
     */
    LESS_OR_EQUAL(1, "VALIDATORDATECONDITION_LESS_OR_EQUAL", "≤"),
    /**
     * Condition for strictly greater than a given date.
     */
    GREATER_THAN(2, "VALIDATORDATECONDITION_GREATER_THAN", ">"),
    /**
     * Condition for greater than or equal to a given date.
     */
    GREATER_OR_EQUAL(3, "VALIDATORDATECONDITION_GREATER_OR_EQUAL", "≥");

    private int index;
    private String label;
    private String expression;

    /**
     * Creates a new instance.
     *
     * @param index index
     * @param label resource key or label.
     */
    private KeyValidatorDateConditions(final int index, final String label, final String expression) {
        this.index = index;
        this.label = label;
        this.expression = expression;
    }

    /**
     * Gets the index.
     * @return
     */
    @Override
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
     * Return a key validator date condition given its index.
     */
    public static KeyValidatorDateConditions fromIndex(final int index) {
        for (final KeyValidatorDateConditions condition : KeyValidatorDateConditions.values()) {
            if (condition.getIndex() == index) {
                return condition;
            }
        }
        return null;
    }

    /**
     * Gets an Integer list instance containing all indices.
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

    @Override
    public String toString() {
        return expression;
    }
}
