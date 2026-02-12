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
