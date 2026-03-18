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
package org.cesecore.license;

public class LicenseValidationException extends RuntimeException {
    private static final long serialVersionUID = 6784065315018278137L;

    private final LicenseState licenseState;

    public LicenseValidationException(final LicenseState licenseState) {
        super(licenseState.getStatusMessage());
        this.licenseState = licenseState;
    }

    public LicenseValidationException(final LicenseState licenseState, final String message) {
        super(message);
        this.licenseState = licenseState;
    }

    public LicenseState getLicenseState() {
        return licenseState;
    }
}
