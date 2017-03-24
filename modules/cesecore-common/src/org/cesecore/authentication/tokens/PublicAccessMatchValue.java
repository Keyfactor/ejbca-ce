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
 * @version $Id: UsernameAccessMatchValue.java 18613 2014-03-17 13:31:40Z mikekushner $
 */
public enum PublicAccessMatchValue implements AccessMatchValue {
    TRANSPORT_ANY(0),
    TRANSPORT_PLAIN(1),
    TRANSPORT_CONFIDENTIAL(2);

    private int numericValue;

    private PublicAccessMatchValue(int numericValue) {
        this.numericValue = numericValue;
    }

    @Override
    public int getNumericValue() {
        return numericValue;
    }

    @Override
    public boolean isDefaultValue() {
        return numericValue == TRANSPORT_ANY.numericValue;
    }

    @Override
    public String getTokenType() {
        return PublicAccessAuthenticationTokenMetaData.TOKEN_TYPE;
    }

    @Override
    public boolean isIssuedByCa() {
        return false;
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
