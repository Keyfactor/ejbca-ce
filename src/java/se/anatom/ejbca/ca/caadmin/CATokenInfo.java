package se.anatom.ejbca.ca.caadmin;

import java.io.Serializable;

/**
 * Holds nonsensitive information about a CAToken.
 *
 * @version $Id: CATokenInfo.java,v 1.2 2003-10-21 13:48:45 herrvendil Exp $
 */
public abstract class CATokenInfo implements Serializable {

    public static final String SIGALG_SHA_WITH_RSA = "SHA1WithRSA";
    
    public static final String[] AVAILABLE_SIGALGS = {SIGALG_SHA_WITH_RSA};
    
    public static final int CATOKENTYPE_P12   = 1;
    public static final int CATOKENTYPE_HSM  = 2;
	public static final int CATOKENTYPE_NULL = 3;
	
    private String signaturealgoritm = null;
    
    public CATokenInfo(){}
    
    /**
     * Method to retrieve which algoritm that should be used for signing of certificates and CRLs.
     */
    public String getSignatureAlgorithm(){ return signaturealgoritm; }
    public void setSignatureAlgorithm(String signaturealgoritm){ this.signaturealgoritm=signaturealgoritm;}
    
}
