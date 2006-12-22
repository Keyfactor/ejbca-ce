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
 * @author Philip Vendil
 * @version $Id: XKMSCAServiceInfo.java,v 1.1 2006-12-22 09:20:46 herrvendil Exp $
 */
public class XKMSCAServiceInfo extends ExtendedCAServiceInfo implements Serializable {    
       
    private String subjectdn      = null;
    private String subjectaltname = null;   
	private String keyspec        = "1024"; // Default key length
    private String keyalgorithm   = CATokenConstants.KEYALGORITHM_RSA; // Default key algo
    private List   xkmscertchain  = null;
    
    private boolean renew = false;
           
    /**
     * Used when creating new service.
     */
       
    public XKMSCAServiceInfo(int status,
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
       
	public XKMSCAServiceInfo(int status,
							 String subjectdn, 
							 String subjectaltname, 
							 String keyspec, 
							 String keyalgorithm,
							 List xkmscertchain){
	  super(status);                       	
	  this.subjectdn = subjectdn;
	  this.subjectaltname = subjectaltname;    	
	  this.keyspec = keyspec;
	  this.keyalgorithm = keyalgorithm; 	 
	  this.xkmscertchain = xkmscertchain;
	}    
    
    /*
     * Used when updating existing services, only status is used.
     */
    public XKMSCAServiceInfo(int status, boolean renew){
      super(status);	
      this.renew = renew;
    }
    
    public String getSubjectDN(){ return this.subjectdn; }
    public String getSubjectAltName(){ return this.subjectaltname; }
    public String getKeySpec(){ return this.keyspec; }
    public String getKeyAlgorithm(){ return this.keyalgorithm; }
    public boolean getRenewFlag(){ return this.renew; } 
    public List getXKMSSignerCertificatePath(){ return this.xkmscertchain;}   
    
    

}
