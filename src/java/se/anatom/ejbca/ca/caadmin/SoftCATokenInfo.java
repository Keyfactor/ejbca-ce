package se.anatom.ejbca.ca.caadmin;

import java.io.Serializable;

/**
 * Holds nonsensitive information about a CAToken.
 *
 * @version $Id: SoftCATokenInfo.java,v 1.1 2003-09-03 16:21:29 herrvendil Exp $
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
