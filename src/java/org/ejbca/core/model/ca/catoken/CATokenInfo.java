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
 * @version $Id: CATokenInfo.java,v 1.3 2006-10-31 08:19:41 anatom Exp $
 */
public abstract class CATokenInfo extends CATokenConstants implements Serializable {

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

	/** Default algorithm i SHA1WithRSA, can be set to any of the supported constants */
    private String signaturealgoritm = SIGALG_SHA1_WITH_RSA;
	/** Default algorithm i SHA1WithRSA, can be set to any of the supported constants */
    private String encryptionalgoritm = SIGALG_SHA1_WITH_RSA;
    
    public CATokenInfo(){}
    
    /**
     * Method to retrieve which algoritm that should be used for signing certificate.
     */
    public String getSignatureAlgorithm(){ return signaturealgoritm; }
	/** Default algorithm i SHA1WithRSA, can be set to any of the supported constants 
	 * @param signaturealgorithm Any of the supported algorithms CATokenInfo.SIGALG_XX 
	 */
    public void setSignatureAlgorithm(String signaturealgoritm){ this.signaturealgoritm=signaturealgoritm;}
    /**
     * Method to retrieve which algoritm that should be used for encryption certificate.
     */
    public String getEncryptionAlgorithm(){ return encryptionalgoritm; }
	/** Default algorithm i SHA1WithRSA, can be set to any of the supported constants 
	 * @param encryptionalgoritm Any of the supported algorithms CATokenInfo.SIGALG_XX 
	 */
    public void setEncryptionAlgorithm(String encryptionalgoritm){ this.encryptionalgoritm=encryptionalgoritm;}
    
}
