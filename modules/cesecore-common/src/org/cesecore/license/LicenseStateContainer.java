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

public class LicenseStateContainer {
    
    private static LicenseState licenseState = LicenseState.MISSING;
    private static String licenseInvalidWarning = "";
    
    public static String getLicenseInvalidWarning() {
        return licenseInvalidWarning;
    }
    
    public static LicenseState getLicenseState() {
        return licenseState;
    }

    public static void setLicenseState(LicenseState licenseState) {
        LicenseStateContainer.licenseState = licenseState;
    }

    public static void setLicenseInvalidWarning(String licenseInvalidWarning) {
        LicenseStateContainer.licenseInvalidWarning = licenseInvalidWarning;
    }    

}
