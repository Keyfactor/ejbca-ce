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
 
package org.ejbca.ui.web.admin.loginterface;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.HashMap;

import org.apache.commons.lang.StringUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.model.log.Admin;

/**
 * A class used to improve performance by proxying certificatesnr to subjectdn mappings by minimizing the number of needed lockups over rmi.
 * TODO: No more RMI! Kill this class!
 *
 * @version $Id$
 */
public class SubjectDNProxy implements java.io.Serializable {

	private static final long serialVersionUID = 1L;
	private HashMap<String,String> subjectdnstore;
    private CertificateStoreSession certificatesession;
    private AuthenticationToken admin;

    /** Creates a new instance of SubjectDNProxy with remote access to CA part */
    public SubjectDNProxy(AuthenticationToken admin, CertificateStoreSession certificatesession){
    	// Get the RaAdminSession instance.
    	this.certificatesession = certificatesession;
    	this.subjectdnstore = new HashMap<String,String>();
    	this.admin = admin;
    }

    /**
     * Method that first tries to find subjectDN in local hashmap and if it doesn't exists looks it up over RMI.
     *
     * @param certificatesnr the certificate serial number number to look up.
     * @return the subjectDN or null if no subjectDN is related to the given id
     */
    public String getSubjectDN(String admindata) {
    	String returnval = null;
    	Certificate result = null;
    	// Check if name is in hashmap
    	returnval = (String) subjectdnstore.get(admindata);
    	if(returnval==null){
    		String certdata[] = StringTools.parseCertData(admindata);
    		if(certdata != null){
    			result = certificatesession.findCertificateByIssuerAndSerno(certdata[1], new BigInteger(certdata[0], 16));
    			if(result != null){
    				returnval = CertTools.getSubjectDN(result);
    				subjectdnstore.put(admindata,returnval);
    			} else if(StringUtils.contains(admindata, "SubjectDN")){
    				String subjectdn = admindata.split(":")[4];
    				returnval = subjectdn.substring(subjectdn.indexOf('"')+1, subjectdn.lastIndexOf('"'));
    				subjectdnstore.put(admindata,returnval);
    			}
    		}
    	}
    	return returnval;
    }
}
