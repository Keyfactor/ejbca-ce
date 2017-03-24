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
package org.cesecore.mock.authentication.tokens;

import java.util.Arrays;
import java.util.List;

import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;

/**
 * @version $Id$
 *
 */
public enum UsernameAccessMatchValue implements AccessMatchValue {
    USERNAME(0);

    private int numericValue;

    private UsernameAccessMatchValue(int numericValue) {
        this.numericValue = numericValue;
    }

    @Override
    public int getNumericValue() {
        return numericValue;
    }

    @Override
    public boolean isDefaultValue() {
        return true; // Single value
    }

    @Override
    public String getTokenType() {
        return UsernameBasedAuthenticationTokenMetaData.TOKEN_TYPE;
    }

    @Override
    public boolean isIssuedByCa() {
        return false;
    }

    @Override
    public List<AccessMatchType> getAvailableAccessMatchTypes() {
        return Arrays.asList(AccessMatchType.TYPE_EQUALCASE);
    }
    
    @Override
    public String normalizeMatchValue(final String value) {
        return value != null ? value.trim() : null;
    }
}
