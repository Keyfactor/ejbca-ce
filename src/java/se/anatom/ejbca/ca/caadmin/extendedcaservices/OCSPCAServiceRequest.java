package se.anatom.ejbca.ca.caadmin.extendedcaservices;

import java.io.Serializable;

import org.bouncycastle.ocsp.BasicOCSPRespGenerator;

/**
 * Class used when requesting OCSP related services from a CA.  
 *
 * @version $Id: OCSPCAServiceRequest.java,v 1.3 2004-01-02 15:33:15 anatom Exp $
 */
public class OCSPCAServiceRequest extends ExtendedCAServiceRequest implements Serializable {    
    
    private BasicOCSPRespGenerator basicRespGen = null;
    private String sigAlg = "SHA1WithRSA";
    private boolean useCACert = false;
    
    /** Cunstructor for OCSPCAServiceRequest
     */                   
    public OCSPCAServiceRequest(BasicOCSPRespGenerator basicRespGen, String sigAlg) {
        this.basicRespGen = basicRespGen;
        this.sigAlg = sigAlg;       
    }
    /** Cunstructor for OCSPCAServiceRequest
     */                   
    public OCSPCAServiceRequest(BasicOCSPRespGenerator basicRespGen, String sigAlg, boolean useCACert) {
        this.basicRespGen = basicRespGen;
        this.sigAlg = sigAlg;       
        this.useCACert = useCACert;
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
}
