package se.anatom.ejbca.ca.caadmin.extendedcaservices;

import java.io.Serializable;
import java.util.List;



/**
 * Class used mostly when creating service. Also used when info about the services 
 * is neesed
 * 
 * 
 * @version $Id: OCSPCAServiceInfo.java,v 1.3 2004-01-02 15:33:15 anatom Exp $
 */
public class OCSPCAServiceInfo extends ExtendedCAServiceInfo implements Serializable {    
       
    public static final String KEYALGORITHM_RSA = "RSA";   
       
    private String subjectdn      = null;
    private String subjectaltname = null;   
	private int    keysize        = 1024;
    private String keyalgorithm   = KEYALGORITHM_RSA; // Currently not used.
    private List   ocspcertchain  = null;
    
    private boolean renew = false;
           
    /**
     * Used when creating new service.
     */
       
    public OCSPCAServiceInfo(int status,
                             String subjectdn, 
                             String subjectaltname, 
                             int keysize, 
                             String keyalgorithm){
      super(status);                       	
      this.subjectdn = subjectdn;
      this.subjectaltname = subjectaltname;    	
      this.keysize = keysize;
      this.keyalgorithm = keyalgorithm; 	 
    }
    
	/**
	 * Used when returning information from service
	 */
       
	public OCSPCAServiceInfo(int status,
							 String subjectdn, 
							 String subjectaltname, 
							 int keysize, 
							 String keyalgorithm,
							 List ocspcertpath){
	  super(status);                       	
	  this.subjectdn = subjectdn;
	  this.subjectaltname = subjectaltname;    	
	  this.keysize = keysize;
	  this.keyalgorithm = keyalgorithm; 	 
	  this.ocspcertchain = ocspcertpath;
	}    
    
    /*
     * Used when updating existing services, only status is used.
     */
    public OCSPCAServiceInfo(int status, boolean renew){
      super(status);	
      this.renew = renew;
    }
    
    public String getSubjectDN(){ return this.subjectdn; }
    public String getSubjectAltName(){ return this.subjectaltname; }
    public int getKeySize(){ return this.keysize; }
    public String getKeyAlgorithm(){ return this.keyalgorithm; }
    public boolean getRenewFlag(){ return this.renew; } 
    public List getOCSPSignerCertificatePath(){ return this.ocspcertchain;}   
    
    

}
