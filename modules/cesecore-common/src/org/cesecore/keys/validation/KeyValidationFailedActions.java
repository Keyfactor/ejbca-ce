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

public enum KeyValidationFailedActions {

    // formatter:on
    DO_NOTHING(0, "VALIDATORFAILEDACTION_DO_NOTHING"), 
    LOG_INFO(1, "VALIDATORFAILEDACTION_LOG_INFO"), 
    LOG_WARN(2, "VALIDATORFAILEDACTION_LOG_WARN"), 
    LOG_ERROR(3, "VALIDATORFAILEDACTION_LOG_ERROR"), 
    ABORT_CERTIFICATE_ISSUANCE(4, "VALIDATORFAILEDACTION_ABORT_CERTIFICATE_ISSUANCE");
    // formatter:off

//    /** Default failed action constant. */
//    public static final KeyValidationFailedActions DEFAULT = DO_NOTHING;
            
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
    private KeyValidationFailedActions(final int index, final String label) {
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
        for (KeyValidationFailedActions condition : values()) {
            result.add(condition.getIndex());
        }
        return result;
    }
}
