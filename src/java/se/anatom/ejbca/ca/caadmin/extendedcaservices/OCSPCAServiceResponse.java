package se.anatom.ejbca.ca.caadmin.extendedcaservices;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.ocsp.BasicOCSPResp;

/**
 * Class used when delevering OCSP service response from a CA.  
 *
 * @version $Id: OCSPCAServiceResponse.java,v 1.4 2004-01-04 17:37:29 anatom Exp $
 */
public class OCSPCAServiceResponse extends ExtendedCAServiceResponse implements Serializable {    
             
    private List ocspcertificatechain = null;
    private BasicOCSPResp basicResp = null;
    
        
    public OCSPCAServiceResponse(BasicOCSPResp basicResp, List ocspsigningcertificatechain) {
        this.basicResp = basicResp;
        this.ocspcertificatechain = ocspsigningcertificatechain;
    }    
           
    public X509Certificate getOCSPSigningCertificate() { return (X509Certificate) this.ocspcertificatechain.get(0); }
	public Collection getOCSPSigningCertificateChain() { 
        if (ocspcertificatechain != null) {
            return this.ocspcertificatechain;
        } else {
            return new ArrayList();
        }
    }
    public BasicOCSPResp getBasicOCSPResp() { return this.basicResp; }
        
}
