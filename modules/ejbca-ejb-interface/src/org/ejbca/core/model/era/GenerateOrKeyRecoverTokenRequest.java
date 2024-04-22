package org.ejbca.core.model.era;

import java.io.Serializable;

public class GenerateOrKeyRecoverTokenRequest implements Serializable {

    private static final long serialVersionUID = 1L;

    private String username;
    private String password;
    private String hardTokenSN;
    private String keySpecification;
    private String altKeySpecification;
    private String keyAlgorithm;
    private String altKeyAlgorithm;

    public GenerateOrKeyRecoverTokenRequest(String username, String password, String hardTokenSN, String keySpecification, String altKeySpecification,
            String keyAlgorithm, String altKeyAlgorithm) {
        this.username = username;
        this.password = password;
        this.hardTokenSN = hardTokenSN;
        this.keySpecification = keySpecification;
        this.altKeySpecification = altKeySpecification;
        this.keyAlgorithm = keyAlgorithm;
        this.altKeyAlgorithm = altKeyAlgorithm;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setHardTokenSN(String hardTokenSN) {
        this.hardTokenSN = hardTokenSN;
    }

    public void setKeySpecification(String keySpecification) {
        this.keySpecification = keySpecification;
    }

    public void setAltKeySpecification(String altKeySpecification) {
        this.altKeySpecification = altKeySpecification;
    }

    public void setKeyAlgorithm(String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
    }

    public void setAltKeyAlgorithm(String altKeyAlgorithm) {
        this.altKeyAlgorithm = altKeyAlgorithm;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getHardTokenSN() {
        return hardTokenSN;
    }

    public String getKeySpecification() {
        return keySpecification;
    }

    public String getAltKeySpecification() {
        return altKeySpecification;
    }

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public String getAltKeyAlgorithm() {
        return altKeyAlgorithm;
    }

}