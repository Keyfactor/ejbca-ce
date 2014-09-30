/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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
import java.security.cert.Certificate;
import java.util.List;

import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.util.AlgorithmConstants;

/**
 * Base class for CAServiceInfo used by extended services that does signing 
 * 
 * @version $Id$
 */
public abstract class BaseSigningCAServiceInfo extends ExtendedCAServiceInfo implements Serializable {    
       
    private static final long serialVersionUID = -6607852949410303766L;
    private String subjectdn      = null;
    private String subjectaltname = null;   
	private String keyspec        = "1024"; // Default key length
    private String keyalgorithm   = AlgorithmConstants.KEYALGORITHM_RSA; // Default key algo
    private List<Certificate>   certchain  = null;
    
    private boolean renew = false;
           
    /** Used when creating new service. */
    public BaseSigningCAServiceInfo(int status, String subjectdn, String subjectaltname, String keyspec, String keyalgorithm) {
    	super(status);
    	this.subjectdn = subjectdn;
    	this.subjectaltname = subjectaltname;
    	this.keyspec = keyspec;
    	this.keyalgorithm = keyalgorithm; 	 
    }
    
	/** Used when returning information from service. */
	public BaseSigningCAServiceInfo(int status, String subjectdn, String subjectaltname, String keyspec, String keyalgorithm, List<Certificate> certpath) {
		super(status);
		this.subjectdn = subjectdn;
		this.subjectaltname = subjectaltname;
		this.keyspec = keyspec;
		this.keyalgorithm = keyalgorithm;
		this.certchain = certpath;
	}    
    
    /* Used when updating existing services, only status is used. */
    public BaseSigningCAServiceInfo(int status, boolean renew){
    	super(status);
    	this.renew = renew;
    }
    
    public String getSubjectDN(){ return this.subjectdn; }
    public String getSubjectAltName(){ return this.subjectaltname; }
    public String getKeySpec(){ return this.keyspec; }
    public String getKeyAlgorithm(){ return this.keyalgorithm; }
    public boolean getRenewFlag(){ return this.renew; } 
    public List<Certificate> getCertificatePath(){ return this.certchain;}   
}
