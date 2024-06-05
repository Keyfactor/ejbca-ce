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
 
 
package org.ejbca.core.model.era;

import java.io.Serializable;

public class GenerateOrKeyRecoverTokenRequest implements Serializable {

    private static final long serialVersionUID = 1L;

    private String username;
    private String password;
    private String hardTokenSN;
    private String keySpecification;
    private String keyAlgorithm;
    private String altKeySpecification;    
    private String altKeyAlgorithm;

    public GenerateOrKeyRecoverTokenRequest(String username, String password, String hardTokenSN, String keySpecification,
            String keyAlgorithm, String altKeySpecification, String altKeyAlgorithm) {
        this.username = username;
        this.password = password;
        this.hardTokenSN = hardTokenSN;
        this.keySpecification = keySpecification;
        this.keyAlgorithm = keyAlgorithm;
        this.altKeySpecification = altKeySpecification;
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

    public void setKeyAlgorithm(String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
    }

    public void setAltKeySpecification(String altKeySpecification) {
        this.altKeySpecification = altKeySpecification;
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

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public String getAltKeySpecification() {
        return altKeySpecification;
    }

    public String getAltKeyAlgorithm() {
        return altKeyAlgorithm;
    }

}