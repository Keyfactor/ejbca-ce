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
 
package se.anatom.ejbca.ca.caadmin.extendedcaservices;

import java.io.Serializable;

import org.bouncycastle.ocsp.BasicOCSPRespGenerator;

/**
 * Class used when requesting OCSP related services from a CA.  
 *
 * @version $Id: OCSPCAServiceRequest.java,v 1.5 2004-04-16 07:38:57 anatom Exp $
 */
public class OCSPCAServiceRequest extends ExtendedCAServiceRequest implements Serializable {    
    
    private BasicOCSPRespGenerator basicRespGen = null;
    private String sigAlg = "SHA1WithRSA";
    private boolean useCACert = false;
    private boolean includeChain = true;
    
    /** Constructor for OCSPCAServiceRequest
     */                   
    public OCSPCAServiceRequest(BasicOCSPRespGenerator basicRespGen, String sigAlg, boolean useCACert, boolean includeChain) {
        this.basicRespGen = basicRespGen;
        this.sigAlg = sigAlg;       
        this.useCACert = useCACert;
        this.includeChain = includeChain;
    }
    public BasicOCSPRespGenerator getOCSPrespGenerator() {
        return basicRespGen;
    }     
    public String getSigAlg() {
        return sigAlg;
    }
    /** If true, the CA certificate should be used to sign the OCSP response.
     * 
     * @return true if the CA cert should be used, false if the OCSPSigner cert shoudl be used.
     */
    public boolean useCACert() {
        return useCACert;
    }
    /** If true, the CA certificate chain is included in the response.
     * 
     * @return true if the CA cert chain should be included in the response.
     */
    public boolean includeChain() {
        return includeChain;
    }
}
