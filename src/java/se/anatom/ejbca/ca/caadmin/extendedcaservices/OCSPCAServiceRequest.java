package se.anatom.ejbca.ca.caadmin.extendedcaservices;

import java.io.Serializable;

import org.bouncycastle.ocsp.BasicOCSPRespGenerator;

/**
 * Class used when requesting OCSP related services from a CA.  
 *
 * @version $Id: OCSPCAServiceRequest.java,v 1.4 2004-01-04 17:37:29 anatom Exp $
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
