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
 
package org.ejbca.core.model.ca.caadmin.extendedcaservices;

import java.io.Serializable;
import java.util.List;

import org.ejbca.core.model.ca.catoken.CATokenConstants;



/**
 * Class used mostly when creating service. Also used when info about the services 
 * is neesed
 * 
 * 
 * @version $Id: OCSPCAServiceInfo.java,v 1.2 2006-10-31 08:19:41 anatom Exp $
 */
public class OCSPCAServiceInfo extends ExtendedCAServiceInfo implements Serializable {    
       
    private String subjectdn      = null;
    private String subjectaltname = null;   
	private String keyspec        = "1024"; // Default key length
    private String keyalgorithm   = CATokenConstants.KEYALGORITHM_RSA; // Default key algo
    private List   ocspcertchain  = null;
    
    private boolean renew = false;
           
    /**
     * Used when creating new service.
     */
       
    public OCSPCAServiceInfo(int status,
                             String subjectdn, 
                             String subjectaltname, 
                             String keyspec, 
                             String keyalgorithm){
      super(status);                       	
      this.subjectdn = subjectdn;
      this.subjectaltname = subjectaltname;    	
      this.keyspec = keyspec;
      this.keyalgorithm = keyalgorithm; 	 
    }
    
	/**
	 * Used when returning information from service
	 */
       
	public OCSPCAServiceInfo(int status,
							 String subjectdn, 
							 String subjectaltname, 
							 String keyspec, 
							 String keyalgorithm,
							 List ocspcertpath){
	  super(status);                       	
	  this.subjectdn = subjectdn;
	  this.subjectaltname = subjectaltname;    	
	  this.keyspec = keyspec;
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
    public String getKeySpec(){ return this.keyspec; }
    public String getKeyAlgorithm(){ return this.keyalgorithm; }
    public boolean getRenewFlag(){ return this.renew; } 
    public List getOCSPSignerCertificatePath(){ return this.ocspcertchain;}   
    
    

}
