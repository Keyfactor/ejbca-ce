/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.certificate.ca.its;

/**
 * ITS Application identifiers as specified in ETSI TS 102 965 V2.1.1 and IEEE 1609.2
 * CPOC release 1.2 table 6 page 42
 * app permissions, name, chain length, ssp value, bitmask
 */
public enum ITSApplicationIds {
    // WAVE Security Management as specified in IEEE 1609.2
    SECURITY_MANAGEMENT(35, "Security Management", -1, null, null, false),
    // CA basic service is specified in ETSI EN 302 637-2 
    CA_BASIC_SERVICE(36, "CA Basic Service", 1, "01FFFC", "FF0003", true),
    // DEN basic service is specified in ETSI EN 302 637-3 
    DEN_BASIC_SERVICE(37, "DEN Basic Service", 1, "01FFFFFF", "FF000000", true),
    // TLM service as specified in ETSI TS 103 301 
    TLM_SERVICE(137, "TLM Service", 1, "01E0", "FF1F", true),
    // RLT service as specified in ETSI TS 103 301 [
    RLT_SERVICE(138, "RTL Service", 1, "01C0", "FF3F", true),
    // IVI service as specified in ETSI TS 103 301 - special case parameterize based on country
    IVI_SERVICE(139, "IVI Service", 1, "01000000FFF8", "FF0000000007", true),
    // Infrastructure service is specified in ETSI TS 103 301 
    TLC_REQUEST_SERVICE(140, "TLC Request Service", 1, "02FFFFE0", "FF00001F", true),
    // GeoNetworking Management Communications as specified in ETSI EN 302 636-4-1 
    GN_MGMT(141, "GeoNetworking Management Communications", 1, "", "", true),
    // CRL service as specified in ETSI TS 102 941 
    CRL_SERVICE(622, "CRL Service", -1, null, null, false),
    // Secure certificate request service as specified in ETSI TS 102 941 - only need certIssuePermision to issue EC
    SECURED_CERT_REQUEST_SERVICE(623, "Secured Certificate Request Service", 1, "01C0", "FF3F", true),
    // CTL service as specified in ETSI TS 102 941
    CTL_SERVICE(624, "CTL Service", -1, null, null, false),
    // Infrastructure service is specified in ETSI TS 103 301 
    TLC_STATUS_SERVICE(637, "TLC Status Service", 1, "01", "FF", true),
    // VRU basic service is specified in ETSI TS 103 300-3 
    VRU_SERVICE(638, "VRU Service", -1, null, null, false);

    private final int psId;
    private final String applicationName;
    private final int minChainLength; // not set if -1
    private final String sspValue;
    private final String sspBitmask;
    private final boolean addToCertIssuePermissions;
    
    private ITSApplicationIds(int psId, String applicationName, int minChainLength, String sspValue, String sspBitmask,
            boolean addToCertIssuePermissions) {
        this.psId = psId;
        this.applicationName = applicationName;
        this.minChainLength = minChainLength;
        this.sspValue = sspValue;
        this.sspBitmask = sspBitmask;
        this.addToCertIssuePermissions = addToCertIssuePermissions;
    }

    public int getPsId() {
        return psId;
    }

    public String getApplicationName() {
        return applicationName;
    }
    
    public int getMinChainLength() {
        return minChainLength;
    }

    public String getSspValue() {
        return sspValue;
    }

    public String getSspBitmask() {
        return sspBitmask;
    }

    public boolean isAddToCertIssuePermissions() {
        return addToCertIssuePermissions;
    }

    public static ITSApplicationIds fromPsidValue(int psidValue) {
        for(ITSApplicationIds sc : values()){
            if(sc.getPsId()==psidValue){
                return sc;
            }
        }
        throw new IllegalArgumentException("Invalid Psid SSP value: " + psidValue);
    }
    
}
