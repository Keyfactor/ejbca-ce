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
 
package se.anatom.ejbca.ca.caadmin;

import java.io.Serializable;

/**
 * Holds nonsensitive information about a CAToken.
 *
 * @version $Id: SoftCATokenInfo.java,v 1.2 2004-04-16 07:38:58 anatom Exp $
 */
public class SoftCATokenInfo extends CATokenInfo implements Serializable {
    
    public static final String KEYALGORITHM_RSA = "RSA";

    private int keysize = 1024; 
    private String algorithm = KEYALGORITHM_RSA;
    
    
    public SoftCATokenInfo(){}
    
    /**
     * KeySize data is used when generating CAToken.
     */
    public int getKeySize(){ return keysize; }    
    /**
     * KeySize data is used when generating CAToken.
     */
    public void setKeySize(int keysize){ this.keysize = keysize; }
    
    /**
     * Algorithm indicates which type of key that should be generated.
     * Currently only RSA keys are supported.
     */
    public String getAlgorithm(){ return algorithm; }
    
    /**
     * Algorithm indicates which type of key that should be generated.
     * Currently only RSA keys are supported.
     */
    public void setAlgorithm(String algorithm){ this.algorithm = algorithm; }
}
