package se.anatom.ejbca.ca.caadmin.extendedcaservices;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;



/**
 * Class used when delevering OCSP service response from a CA.  
 *
 * @version $Id: OCSPCAServiceResponse.java,v 1.1 2003-11-02 15:51:37 herrvendil Exp $
 */
public class OCSPCAServiceResponse extends ExtendedCAServiceResponse implements Serializable {    
             
    private List ocspcertificatechain = null;
    private PrivateKey ocspsigningkey = null;
        
       
    public OCSPCAServiceResponse(List ocspsigningcertificatechain, 
                                 PrivateKey ocspsigningkey){
      this.ocspcertificatechain = ocspsigningcertificatechain;
      this.ocspsigningkey = ocspsigningkey;    
    }    
    
    public X509Certificate getOCSPSigningCertificate(){ return (X509Certificate) this.ocspcertificatechain.get(0); }
	public Collection getOCSPSigningCertificateChain(){ return this.ocspcertificatechain; }
    public PrivateKey getOCSPSigningKey(){ return this.ocspsigningkey; }
        
}
