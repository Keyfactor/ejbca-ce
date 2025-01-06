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
