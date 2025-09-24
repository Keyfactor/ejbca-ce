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

package org.cesecore.certificates.ca;

import java.io.Serializable;

public enum KeepExpiredCertsOnCrlFormat implements Serializable {

    /*
     * Warning!
     * It is important to NOT change the values. These are the values stored in the databases.
     * If you do change them, then there will be a mismatch with the database content.
     */

    CA_DATE(0),
    ARBITRARY_DATE(1);

    private final int value;

    KeepExpiredCertsOnCrlFormat(final int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static KeepExpiredCertsOnCrlFormat fromValue(int value) {
        for (var keepExpiredCertsOnCrlFormat : KeepExpiredCertsOnCrlFormat.values()) {
            if (keepExpiredCertsOnCrlFormat.getValue() == value) {
                return keepExpiredCertsOnCrlFormat;
            }
        }
        throw new IllegalArgumentException("Unknown KeepExpiredCertsOnCrlFormat: " + value);
    }

}
