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
import java.util.List;

import org.cesecore.util.IndexEnum;

/**
 * Contains different actions which occur whenever a Validator in EJBCA fails.
 * @version $Id$
 */
public enum KeyValidationFailedActions implements IndexEnum {
    DO_NOTHING(0, "VALIDATORFAILEDACTION_DO_NOTHING"),
    LOG_INFO(1, "VALIDATORFAILEDACTION_LOG_INFO"),
    LOG_WARN(2, "VALIDATORFAILEDACTION_LOG_WARN"),
    LOG_ERROR(3, "VALIDATORFAILEDACTION_LOG_ERROR"),
    ABORT_CERTIFICATE_ISSUANCE(4, "VALIDATORFAILEDACTION_ABORT_CERTIFICATE_ISSUANCE");

    private int index;
    private String label;

    /**
     * Creates a new instance.
     *
     * @param index index
     * @param label resource key or label.
     */
    private KeyValidationFailedActions(final int index, final String label) {
        this.index = index;
        this.label = label;
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
     * Gets an Integer list instance containing all index.
     * @return
     */
    public static final List<Integer> index() {
        final List<Integer> result = new ArrayList<Integer>();
        for (KeyValidationFailedActions condition : values()) {
            result.add(condition.getIndex());
        }
        return result;
    }

    /**
     * Retrieve an action from its index.
     * @param index the index of the action
     * @return the corresponding action enum or null if not found
     */
    public static KeyValidationFailedActions fromIndex(final int index) {
        for (final KeyValidationFailedActions action : values()) {
            if (action.getIndex() == index) {
                return action;
            }
        }
        return null;
    }
}
