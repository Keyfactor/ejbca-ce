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

package org.ejbca.core.model;

import org.cesecore.certificates.endentity.EndEntityConstants;

/**
 * Legacy constants still being used in code.
 * 
 */
public final class SecConst {

    public static final String[] TOKENTEXTS = {
            "TOKENSOFTUSERGENERATED",
            "TOKENSOFTP12",
            "TOKENSOFTFIPSP12",
            "TOKENSOFTJKS",
            "TOKENSOFTPEM"
    };

    public static final int[] TOKENIDS = {
            EndEntityConstants.TOKEN_USERGEN,
            EndEntityConstants.TOKEN_SOFT_P12,
            EndEntityConstants.TOKEN_SOFT_BCFKS,
            EndEntityConstants.TOKEN_SOFT_JKS,
            EndEntityConstants.TOKEN_SOFT_PEM
    };
    
    /**
     * Constants used in the SignSessionBean indicating the userdata defined CA should be used.
     */
    public static final int CAID_USEUSERDEFINED = 0;

    /**
     * Prevents creation of new SecConst
     */
    private SecConst() {
    }

	// Revocation reasons identifiers
    public static final String[] reasontexts = {
        "REV_UNSPECIFIED",			"REV_KEYCOMPROMISE",	"REV_CACOMPROMISE",
        "REV_AFFILIATIONCHANGED",	"REV_SUPERSEDED",		"REV_CESSATIONOFOPERATION",
        "REV_CERTIFICATEHOLD",		"REV_UNUSED",			"REV_REMOVEFROMCRL",
        "REV_PRIVILEGEWITHDRAWN",	"REV_AACOMPROMISE"
    };


    public static String getKeyStoreTypeAsString(int keystoreType) {
        switch (keystoreType) {
            case EndEntityConstants.TOKEN_SOFT_JKS:
                return "JKS";
            case EndEntityConstants.TOKEN_SOFT_PEM:
                return "PEM";
            case EndEntityConstants.TOKEN_SOFT_P12:
            case EndEntityConstants.TOKEN_USERGEN:
                return "PKCS12";
            case EndEntityConstants.TOKEN_SOFT_BCFKS:
                return "BCFKS";
            default:
                return "UNKNOWN";
        }
    }
}
