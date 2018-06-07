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

/**
 * JSON input representation of key store enrollment
 * @version $Id$
 *
 */
public class KeyStoreRestRequest {

    private String username;
    private String password;
    private String keyAlg;
    private String keySpec;
    
    public String getUsername() {
        return username;
    }
    
    public void setUsername(String username) {
        this.username = username;
    }
    
    public String getPassword() {
        return password;
    }
    
    public void setPassword(String password) {
        this.password = password;
    }
    
    public String getKeyAlg() {
        return keyAlg;
    }
    
    public void setKeyAlg(String keyAlg) {
        this.keyAlg = keyAlg;
    }
    
    public String getKeySpec() {
        return keySpec;
    }
    
    public void setKeySpec(String keySpec) {
        this.keySpec = keySpec;
    }
}