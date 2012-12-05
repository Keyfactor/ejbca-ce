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
package org.ejbca.core.ejb.authentication.cli;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;

/**
 * @version $Id$
 *
 */
public enum CliUserAccessMatchValue implements AccessMatchValue {
    USERNAME(0);

    private static final Logger log = Logger.getLogger(CliUserAccessMatchValue.class);
    
    private int numericValue;
    private static Map<Integer, CliUserAccessMatchValue> databaseLookup;
    private static Map<String, AccessMatchValue> nameLookup;

    static {
        /**
         * Create an internal mapping to translate from the database representation of this match value (an int)
         * to an actual match value.
         */
        databaseLookup = new HashMap<Integer, CliUserAccessMatchValue>();
        nameLookup = new HashMap<String, AccessMatchValue>();
        for (CliUserAccessMatchValue value : CliUserAccessMatchValue.values()) {
            databaseLookup.put(value.numericValue, value);
            nameLookup.put(value.name(), value);
        }
        
        /*
         * This match value is registered with the token reverse lookup registry, which will allow it to be looked up from the string
         * return by the getTokenType method implemented from AccessMatchValue.  
         */  
        try {
            AccessMatchValueReverseLookupRegistry.INSTANCE.registerLookupMethod(CliAuthenticationToken.TOKEN_TYPE,
                    CliUserAccessMatchValue.class.getMethod("matchFromDatabase", Integer.class), nameLookup, USERNAME);
        } catch (SecurityException e) {
            log.error("Failure when registering method", e);
        } catch (NoSuchMethodException e) {
            log.error("Failure when registering method", e);
        }
    }

    private CliUserAccessMatchValue(int numericValue) {
        this.numericValue = numericValue;
    }

    @Override
    public int getNumericValue() {
        return numericValue;
    }

    @Override
    public String getTokenType() {
        return CliAuthenticationToken.TOKEN_TYPE;
    }

    public static CliUserAccessMatchValue matchFromDatabase(Integer numericValue) {
        return databaseLookup.get(numericValue);
    }

    @Override
    public boolean isIssuedByCa() {
        return false;
    }

}
