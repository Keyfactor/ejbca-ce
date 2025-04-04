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

    CA_DATE,
    ARBITRARY_DATE;

    public static KeepExpiredCertsOnCrlFormat fromOrdinal(int value) {
        for (var keepExpiredCertsOnCrlFormat : KeepExpiredCertsOnCrlFormat.values()) {
            if (keepExpiredCertsOnCrlFormat.ordinal() == value) {
                return keepExpiredCertsOnCrlFormat;
            }
        }
        throw new IllegalArgumentException("Unknown KeepExpiredCertsOnCrlFormat: " + value);
    }

}
