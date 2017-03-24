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
package org.cesecore.authentication.tokens;

import java.util.Arrays;
import java.util.List;

import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;

/**
 * Meta data definition and ServiceLoader marker for {@link org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken}.
 * 
 * @version $Id$
 */
public class AlwaysAllowLocalAuthenticationTokenMetaData extends AuthenticationTokenMetaDataBase {

    private static String TOKEN_TYPE = "AlwaysAllowLocalAuthenticationToken";
    
    private static enum InternalMatchValue implements AccessMatchValue {
        INSTANCE(0), DEFAULT(Integer.MAX_VALUE);

        private final int numericValue;
        
        private InternalMatchValue(final int numericValue) {
            this.numericValue = numericValue;
        }
        
        @Override
        public int getNumericValue() {
            return numericValue;
        }

        @Override
        public String getTokenType() {
            return TOKEN_TYPE;
        }

        @Override
        public boolean isIssuedByCa() {
            return false;
        }

        @Override
        public boolean isDefaultValue() {
            return numericValue == DEFAULT.numericValue;
        }

        @Override
        public List<AccessMatchType> getAvailableAccessMatchTypes() {
            return Arrays.asList();
        }
        
        @Override
        public String normalizeMatchValue(final String value) {
            return null; // does not have a value
        }
    }
    
    public AlwaysAllowLocalAuthenticationTokenMetaData() {
        super(TOKEN_TYPE, Arrays.asList(InternalMatchValue.values()), false);
    }
}
