package se.anatom.ejbca.ca.caadmin.extendedcaservices;

import java.io.Serializable;



/**
 * Class used mostly when creating service. Also used when info about the services 
 * is neesed
 * 
 * 
 * @version $Id: OCSPCAServiceInfo.java,v 1.1 2003-11-02 15:51:37 herrvendil Exp $
 */
public class OCSPCAServiceInfo extends ExtendedCAServiceInfo implements Serializable {    
       
    private String subjectdn      = null;
    private String subjectaltname = null;   
	private int    keysize        = 2048;
    private String keyalgorithm   = "RSA"; // Currently not used.
       
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
    
    public String getSubjectDN(){ return this.subjectdn; }
    public String getSubjectAltName(){ return this.subjectaltname; }
    public int getKeySize(){ return this.keysize; }
    public String getKeyAlgorithm(){ return this.keyalgorithm; }
    

}
