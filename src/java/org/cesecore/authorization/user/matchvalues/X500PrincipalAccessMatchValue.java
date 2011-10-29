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
package org.cesecore.authorization.user.matchvalues;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;

/**
 * Match with constants. Observe that these constants are also used as a priority indicator for access rules. The higher values the higher priority.
 * 
 * @version $Id$
 * 
 */
public enum X500PrincipalAccessMatchValue implements AccessMatchValue {
    NONE(0), WITH_COUNTRY(1), WITH_DOMAINCOMPONENT(2), WITH_STATEORPROVINCE(3), WITH_LOCALITY(4), WITH_ORGANIZATION(5), WITH_ORGANIZATIONALUNIT(6), WITH_TITLE(7), WITH_COMMONNAME(
            8), WITH_UID(9), WITH_DNSERIALNUMBER(10), WITH_SERIALNUMBER(11), WITH_DNEMAILADDRESS(12), WITH_RFC822NAME(13), WITH_UPN(14), WITH_FULLDN(15);
    
    private static final Logger log = Logger.getLogger(X500PrincipalAccessMatchValue.class);
    
    private static Map<Integer, X500PrincipalAccessMatchValue> databaseLookup;
    private static Map<String, X500PrincipalAccessMatchValue> nameLookup;
    private int numericValue;
    
    static {
        try {
            AccessMatchValueReverseLookupRegistry.INSTANCE.registerLookupMethod(X509CertificateAuthenticationToken.TOKEN_TYPE,
                    X500PrincipalAccessMatchValue.class.getMethod("matchFromDatabase", Integer.class));
        } catch (SecurityException e) {
            log.error("Failure when registering method", e);
        } catch (NoSuchMethodException e) {
            log.error("Failure when registering method", e);
        }
        
        databaseLookup = new HashMap<Integer, X500PrincipalAccessMatchValue>();
        nameLookup = new HashMap<String, X500PrincipalAccessMatchValue>();
        for(X500PrincipalAccessMatchValue value : X500PrincipalAccessMatchValue.values()) {
            databaseLookup.put(value.numericValue, value);
            nameLookup.put(value.name(), value);
        }
    }
    
    private X500PrincipalAccessMatchValue(int numericValue) {
        this.numericValue = numericValue;
    }

    @Override
    public int getNumericValue() {
        return numericValue;
    }
    
    public static X500PrincipalAccessMatchValue matchFromDatabase(Integer numericValue) {
        return databaseLookup.get(numericValue);
    }
    
    public static X500PrincipalAccessMatchValue matchFromName(String name) {
        return nameLookup.get(name);
    }

    @Override
    public String getTokenType() {
        return X509CertificateAuthenticationToken.TOKEN_TYPE;
    }
}
