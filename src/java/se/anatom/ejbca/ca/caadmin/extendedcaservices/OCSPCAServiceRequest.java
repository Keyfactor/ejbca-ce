package se.anatom.ejbca.ca.caadmin.extendedcaservices;

import java.io.Serializable;



/**
 * Class used when requesting OCSP related services from a CA.  
 *
 * @version $Id: OCSPCAServiceRequest.java,v 1.2 2003-12-27 10:56:07 anatom Exp $
 */
public class OCSPCAServiceRequest extends ExtendedCAServiceRequest implements Serializable {    
    
    /** Cunstructor for OCSPCAServiceRequest
     * 
     * @param requesttype not used, 0
     */                   
    public OCSPCAServiceRequest(int requesttype){       
    }    
            

}
