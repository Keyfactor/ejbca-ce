/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.core.model.ca.catoken;

import java.io.Serializable;

import org.ejbca.core.model.AlgorithmConstants;

/**
 * Holds nonsensitive information about a CAToken.
 *
 * @version $Id$
 */
public class SoftCATokenInfo extends CATokenInfo implements Serializable {
    
    private String signkeyspec = "1024"; 
    private String enckeyspec = "1024"; 
    private String signalgorithm = AlgorithmConstants.KEYALGORITHM_RSA;
    private String encalgorithm = AlgorithmConstants.KEYALGORITHM_RSA;
    
    
    public SoftCATokenInfo(){
    	super();
    	setClassPath(SoftCAToken.class.getName());
    }
    
    /**
     * KeySize data is used when generating CAToken.
     */
    public String getSignKeySpec(){ return signkeyspec; }    
    /**
     * KeySize data is used when generating CAToken.
     */
    public void setSignKeySpec(String keyspec){ this.signkeyspec = keyspec; }
    /**
     * KeySize data is used when generating CAToken.
     */
    public String getEncKeySpec(){ return enckeyspec; }    
    /**
     * KeySize data is used when generating CAToken.
     */
    public void setEncKeySpec(String keyspec){ this.enckeyspec = keyspec; }

    /**
     * Algorithm indicates which type of key that should be generated.
     */
    public String getSignKeyAlgorithm(){ return signalgorithm; }
    
    /**
     * Algorithm indicates which type of key that should be generated.
     */
    public void setSignKeyAlgorithm(String algorithm){ this.signalgorithm = algorithm; }
    /**
     * Algorithm indicates which type of key that should be generated.
     * Currently only RSA keys are supported.
     */
    public String getEncKeyAlgorithm(){ return encalgorithm; }
    
    /**
     * Algorithm indicates which type of key that should be generated.
     * Currently only RSA keys are supported.
     */
    public void setEncKeyAlgorithm(String algorithm){ this.encalgorithm = algorithm; }
}
