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
 * An enum domain class representing all certificate process phases for validators.
 *
 * @version $Id$
 */
public enum IssuancePhase implements IndexEnum {

    // @formatter:off
    DATA_VALIDATION(0, "VALIDATORPHASE_DATA_VALIDATION"),
    PRE_CERTIFICATE_VALIDATION(1, "VALIDATORPHASE_PRE_CERTIFICATE_VALIDATION"),
    CERTIFICATE_VALIDATION(2, "VALIDATORPHASE_CERTIFICATE_VALIDATION");
    // @formatter:on

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
    private IssuancePhase(final int index, final String label) {
        this.index = index;
        this.label = label;
    }

    /**
     * Gets the index.
     * @return the index.
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
     * Gets an Integer list instance containing all indices.
     * @return
     */
    public static final List<Integer> indices() {
        final List<Integer> result = new ArrayList<Integer>();
        for (IssuancePhase phase : values()) {
            result.add(phase.getIndex());
        }
        return result;
    }

    /**
     * Gets the {@link IssuancePhase} object with the given index.
     * @param index the index.
     * @return the validator phase.
     */
    public static final IssuancePhase fromIndex(final int index) {
        for (IssuancePhase phase : values()) {
            if (phase.getIndex() == index) {
                return phase;
            }
        }
        return null;
    }
}
