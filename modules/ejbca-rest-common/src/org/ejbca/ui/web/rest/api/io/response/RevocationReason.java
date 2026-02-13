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
package org.ejbca.ui.web.rest.api.io.response;

public enum RevocationReason {

    REV_UNSPECIFIED("Unspecified"),
    REV_KEYCOMPROMISE("Key compromise"),
    REV_CACOMPROMISE("CA compromise"),
    REV_AFFILIATIONCHANGED("Affiliation changed"),
    REV_SUPERSEDED("Superseded"),
    REV_CESSATIONOFOPERATION("Cessation of operation"),
    REV_CERTIFICATEHOLD("Certificate hold"),
    REV_REMOVEFROMCRL("Remove from CRL"),
    REV_PRIVILEGEWITHDRAWN("Privileges withdrawn"),
    REV_AACOMPROMISE("AA compromise"),
    UNREVOKE("Unrevoke");

    private final String text;

    RevocationReason(String text) {
        this.text = text;
    }

    public String getText() {
        return text;
    }

    public static String getTextByCode(String code) {
        for (RevocationReason reason : values()) {
            if (reason.name().equals(code)) {
                return reason.text;
            }
        }
        throw new IllegalArgumentException("Invalid code: " + code);
    }
}
