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
package org.ejbca.ui.web.rest.api.io.request;

import org.cesecore.certificates.endentity.EndEntityConstants;

public enum EndEntityStatus {
    NEW(EndEntityConstants.STATUS_NEW),
    FAILED(EndEntityConstants.STATUS_FAILED),
    INITIALIZED(EndEntityConstants.STATUS_INITIALIZED),
    INPROCESS(EndEntityConstants.STATUS_INPROCESS),
    GENERATED(EndEntityConstants.STATUS_GENERATED),
    REVOKED(EndEntityConstants.STATUS_REVOKED),
    HISTORICAL(EndEntityConstants.STATUS_HISTORICAL),
    KEYRECOVERY(EndEntityConstants.STATUS_KEYRECOVERY),
    WAITINGFORADDAPPROVAL(EndEntityConstants.STATUS_WAITINGFORADDAPPROVAL);

    private final int statusValue;

    EndEntityStatus(final int statusValue) {
        this.statusValue = statusValue;
    }

    public int getStatusValue() {
        return statusValue;
    }

    /**
     * Resolves the EndEntityStatus using its name or returns null.
     *
     * @param name status name.
     * @return EndEntityStatus using its name or null.
     */
    public static EndEntityStatus resolveEndEntityStatusByName(final String name) {
        for (EndEntityStatus endEntityStatus : values()) {
            if (endEntityStatus.name().equalsIgnoreCase(name)) {
                return endEntityStatus;
            }
        }
        return null;
    }

}
