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
import java.util.List;



/**
 * Class used mostly when creating service. Also used when info about the services 
 * is neesed
 * 
 * 
 * @version $Id: OCSPCAServiceInfo.java,v 1.4 2004-04-16 07:38:57 anatom Exp $
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
