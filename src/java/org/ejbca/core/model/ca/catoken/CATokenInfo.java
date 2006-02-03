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

/**
 * Holds nonsensitive information about a CAToken.
 *
 * @version $Id: CATokenInfo.java,v 1.2 2006-02-03 12:01:00 anatom Exp $
 */
public abstract class CATokenInfo implements Serializable {

    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
    private static final long serialVersionUID = -8484441028763008079L;

    public static final String SIGALG_SHA1_WITH_RSA = "SHA1WithRSA";
    public static final String SIGALG_SHA256_WITH_RSA = "SHA256WithRSA";
   
    public static final String[] AVAILABLE_SIGALGS = {SIGALG_SHA1_WITH_RSA, SIGALG_SHA256_WITH_RSA};
    
    public static final int CATOKENTYPE_P12          = 1;
    public static final int CATOKENTYPE_HSM          = 2;
	public static final int CATOKENTYPE_NULL         = 3;
	
    private String signaturealgoritm = null;
    
    public CATokenInfo(){}
    
    /**
     * Method to retrieve which algoritm that should be used for signing of certificates and CRLs.
     */
    public String getSignatureAlgorithm(){ return signaturealgoritm; }
    public void setSignatureAlgorithm(String signaturealgoritm){ this.signaturealgoritm=signaturealgoritm;}
    
}
