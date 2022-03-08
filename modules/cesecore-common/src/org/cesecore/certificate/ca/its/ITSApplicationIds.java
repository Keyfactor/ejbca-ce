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
 * 
 */
public enum ITSApplicationIds {
    // WAVE Security Management as specified in IEEE 1609.2
    SECURITY_MANAGEMENT(35, "Security Management"),
    // CA basic service is specified in ETSI EN 302 637-2 
    CA_BASIC_SERVICE(36, "CA Basic Service"),
    // DEN basic service is specified in ETSI EN 302 637-3 
    DEN_BASIC_SERVICE(37, "DEN Basic Service"),
    // TLM service as specified in ETSI TS 103 301 
    TLM_SERVICE(137, "TLM Service"),
    // RLT service as specified in ETSI TS 103 301 [
    RLT_SERVICE(138, "RTL Service"),
    // IVI service as specified in ETSI TS 103 301 
    IVI_SERVICE(139, "IVI Service"),
    // Infrastructure service is specified in ETSI TS 103 301 
    TLC_REQUEST_SERVICE(140, "TLC Request Service"),
    // GeoNetworking Management Communications as specified in ETSI EN 302 636-4-1 
    GN_MGMT(141, "GeoNetworking Management Communications"),
    // CRL service as specified in ETSI TS 102 941 
    CRL_SERVICE(622, "CRL Service"),
    // Secure certificate request service as specified in ETSI TS 102 941 
    SECURED_CERT_REQUEST_SERVICE(623, "Secured Certificate Request Service"),
    // CTL service as specified in ETSI TS 102 941
    CTL_SERVICE(624, "CTL Service"),
    // Infrastructure service is specified in ETSI TS 103 301 
    TLC_STATUS_SERVICE(637, "TLC Status Service"),
    // VRU basic service is specified in ETSI TS 103 300-3 
    VRU_SERVICE(638, "VRU Service");


    private final int psId;
    private final String applicationName;

    private ITSApplicationIds(final int psId, String applicationName) {
        this.psId = psId;
        this.applicationName = applicationName;
    }

    public int getPsId() {
        return psId;
    }

    public String getApplicationName() {
        return applicationName;
    }
    
    public static ITSApplicationIds fromSspValue(int sspValue) {
        for(ITSApplicationIds sc : values()){
            if(sc.getPsId()==sspValue){
                return sc;
            }
        }
        throw new IllegalArgumentException("Invalid Psid SSP value: " + sspValue);
    }
}
