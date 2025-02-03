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
package org.ejbca.ui.web.rest.api.io.request;

import org.cesecore.certificates.endentity.EndEntityConstants;

public enum TokenType {
    USERGENERATED(EndEntityConstants.TOKEN_USERGEN),
    P12(EndEntityConstants.TOKEN_SOFT_P12),
    BCFKS(EndEntityConstants.TOKEN_SOFT_BCFKS),
    JKS(EndEntityConstants.TOKEN_SOFT_JKS),
    PEM(EndEntityConstants.TOKEN_SOFT_PEM);

    private final int tokenValue;

    TokenType(final int tokenValue) {
        this.tokenValue = tokenValue;
    }

    public int getTokenValue() {
        return tokenValue;
    }

    /**
     * Resolves the TokenType using its name or returns null.
     *
     * @param name status name.
     * @return TokenType using its name or null.
     */
    public static TokenType resolveEndEntityTokenByName(final String name) {
        for (TokenType tokenType : values()) {
            if (tokenType.name().equalsIgnoreCase(name)) {
                return tokenType;
            }
        }
        return null;
    }

}
