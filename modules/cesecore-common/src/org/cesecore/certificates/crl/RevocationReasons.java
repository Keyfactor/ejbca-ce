/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.crl;

import java.util.HashMap;
import java.util.Map;

/**
 * An enum for revocation reasons, with a numerical database value and a String value for CLI applications.
 * 
 * @version $Id$
 *
 */
public enum RevocationReasons {
    NOT_REVOKED(-1, "NOT_REVOKED", "the certificate is not revoked"),
    UNSPECIFIED(0, "UNSPECIFIED", "unspecified"),
    KEYCOMPROMISE(1, "KEY_COMPROMISE", "key compromise"),
    CACOMPROMISE(2, "CA_COMPROMISE", "CA compromise"),
    AFFILIATIONCHANGED(3, "AFFILIATION_CHANGED", "affiliation changed"),
    SUPERSEDED(4, "SUPERSEDED", "superseded"),
    CESSATIONOFOPERATION(5, "CESSATION_OF_OPERATION", "cessation of operation"),
    CERTIFICATEHOLD(6, "CERTIFICATE_HOLD", "certificate hold"),
    REMOVEFROMCRL(8, "REMOVE_FROM_CRL", "remove from CRL"),
    PRIVILEGESWITHDRAWN(9, "PRIVILEGES_WITHDRAWN", "privileges withdrawn"),
    AACOMPROMISE(10, "AA_COMPROMISE", "AA compromise");
    
    private final int databaseValue;
    private final String stringValue;
    private final String humanReadable;

    private static final Map<Integer, RevocationReasons> databaseLookupMap = new HashMap<Integer, RevocationReasons>();
    private static final Map<String, RevocationReasons> cliLookupMap = new HashMap<String, RevocationReasons>();

    
    static {
        for(RevocationReasons reason : RevocationReasons.values()) {
            databaseLookupMap.put(reason.getDatabaseValue(), reason);
            cliLookupMap.put(reason.getStringValue(), reason);
        }
    }

    private RevocationReasons(final int databaseValue, final String stringValue, String humanReadable) {
        this.databaseValue = databaseValue;
        this.stringValue = stringValue;
        this.humanReadable = humanReadable;
    }
    
    public int getDatabaseValue() {
        return databaseValue;
    }
    
    public String getHumanReadable() {
        return humanReadable;
    }
    
    public String getStringValue() {
        return stringValue;
    }
    
    /**
     * 
     * @param databaseValue the database value
     * @return the relevant RevocationReasons object, null if none found. 
     */
    public static RevocationReasons getFromDatabaseValue(int databaseValue) {
        return databaseLookupMap.get(databaseValue);
    }
    
    /**
     * 
     * @param cliValue the database value
     * @return the relevant RevocationReasons object, null if none found. 
     */
    public static RevocationReasons getFromCliValue(String cliValue) {
        if(cliValue == null) {
            return null;
        }
        return cliLookupMap.get(cliValue);
    }
}
