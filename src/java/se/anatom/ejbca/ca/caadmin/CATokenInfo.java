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
 * @version $Id: CATokenInfo.java,v 1.3 2004-04-16 07:38:58 anatom Exp $
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
