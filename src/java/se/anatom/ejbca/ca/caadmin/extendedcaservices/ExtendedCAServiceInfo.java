package se.anatom.ejbca.ca.caadmin.extendedcaservices;

import java.io.Serializable;



/**
 * Should be enherited by all ExtendedCAServiceInfo Value objects.
 * These classes are used to retrive general information about the service
 * and alse used to send parameters to the service when creating it.  
 *
 * @version $Id: ExtendedCAServiceInfo.java,v 1.2 2003-11-14 14:59:57 herrvendil Exp $
 */
public abstract class ExtendedCAServiceInfo  implements Serializable {    
       	  
    /**
     * Constants indicating the status of the service.     
     */   	  
    public static final int STATUS_INACTIVE = 1;       	  
	public static final int STATUS_ACTIVE   = 2;
	
	public static final int TYPE_OCSPEXTENDEDSERVICE   = OCSPCAService.TYPE; 
	   
	private int status = STATUS_INACTIVE;  
	   
    public ExtendedCAServiceInfo(int status){
      this.status = status;
    }
    
    public int getStatus(){ return this.status; }

}
