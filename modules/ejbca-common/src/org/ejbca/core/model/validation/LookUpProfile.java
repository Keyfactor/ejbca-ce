package org.ejbca.core.model.validation;

public enum LookUpProfile {

    SMIME_LOOKUP("SMIME lookup"),
    TLS_LOOKUP("TLS lookup"),
    NONE("");
    
    private final String value;

    private LookUpProfile(String value) {
        this.value = value;
    }
    
    public String getValue() {
        return value;
    }
}
