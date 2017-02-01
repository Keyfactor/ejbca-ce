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
package org.ejbca.core.ejb.authentication.cli;

import java.util.Arrays;
import java.util.List;

import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;

/**
 * @version $Id$
 *
 */
public enum CliUserAccessMatchValue implements AccessMatchValue {
    USERNAME(0);

    static {
        AccessMatchValueReverseLookupRegistry.INSTANCE.register(CliUserAccessMatchValue.values());
    }
    
    private final int numericValue;

    private CliUserAccessMatchValue(int numericValue) {
        this.numericValue = numericValue;
    }

    @Override
    public int getNumericValue() {
        return numericValue;
    }

    @Override
    public boolean isDefaultValue() {
        return numericValue == USERNAME.numericValue;
    }

    @Override
    public String getTokenType() {
        return CliAuthenticationToken.TOKEN_TYPE;
    }

    @Override
    public boolean isIssuedByCa() {
        return false;
    }

    @Override
    public List<AccessMatchType> getAvailableAccessMatchTypes() {
        // Always use case sensitive match for usernames
        return Arrays.asList(AccessMatchType.TYPE_EQUALCASE);
    }
}
