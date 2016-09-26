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

import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;

/**
 * @version $Id: UsernameAccessMatchValue.java 18613 2014-03-17 13:31:40Z mikekushner $
 */
public enum PublicAccessMatchValue implements AccessMatchValue {
    // There's a bug that causes TRANSPORT_PLAIN and TRANSPORT_CONFIDENTIAL to only match about half of the access rules (ECA-5120). It's also disabled in PublicAccessAuthenticationToken
    TRANSPORT_ANY(0)/*,
    TRANSPORT_PLAIN(1),
    TRANSPORT_CONFIDENTIAL(2)*/; 

    private int numericValue;

    static {
        AccessMatchValueReverseLookupRegistry.INSTANCE.register(values());
    }

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
        return PublicAccessAuthenticationToken.TOKEN_TYPE;
    }

    @Override
    public boolean isIssuedByCa() {
        return false;
    }
}
