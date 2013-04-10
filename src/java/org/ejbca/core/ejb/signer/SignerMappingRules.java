package org.ejbca.core.ejb.signer;

public enum SignerMappingRules {
    BASE("/signermapping"),
    DELETE(BASE.resource() + "/delete"),
    MODIFY(BASE.resource() + "/modify"),
    VIEW(BASE.resource() + "/view"),
    ;

    private final String resource;
    
    private SignerMappingRules(String resource) {
        this.resource = resource;
    }

    public String resource() {
        return this.resource;
    }

    public String toString() {
        return this.resource;
    }
}
