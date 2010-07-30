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

package org.ejbca.core.protocol.xkms.generators;

import java.util.ArrayList;
import java.util.Collection;

import javax.ejb.EJBException;

import org.ejbca.config.XkmsConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;

/**
 * Class that parses the property file for the 
 * XKMS configuration
 * 
 * @author Philip Vendil 2006 dec 17
 *
 * @version $Id$
 */

public class XKMSConfig {
	
    private static Integer cAIdUsedForSigning = null;

    /**
     * Method that returns the parameter in the property file
     * xkms.request.requiresignature which indicates
     * that a signature is required for all KISS requests
     */
    public static boolean isSignedRequestRequired(){
    	return XkmsConfiguration.getRequestRequireSignature();
    }

    /**
     * Method that returns the parameter in the property file
     * xkms.response.acceptsignrequest which indicates
     * that the service will sign the responses on requests
     */
    public static boolean acceptSignRequests(){
    	return XkmsConfiguration.getResponseAcceptsignRequest();
    }

    /**
     * Method that returns the parameter in the propertyfile
     * xkms.response.alwayssign which indicates
     * that the service will always sign the responses.
     */
    public static boolean alwaysSignResponses(){
    	return XkmsConfiguration.getResponseAlwaysSign();
    }
    
    /**
     * Method that returns the parameter in the property file
     * xkms.keyusage.signatureisnonrep
     */
    public static boolean signatureIsNonRep(){
    	return XkmsConfiguration.getKeyUsageSignatureIsNonRep();
    }
    
    /**
     * Method that returns the parameter in the property file
     * xkms.response.causedforsigning on which CA that should
     * be used for signing XKMS requests
     */
    public static int cAIdUsedForSigning(Admin admin, CAAdminSession cAAdminSession){
    	if(cAIdUsedForSigning == null){
    		CAInfo info = cAAdminSession.getCAInfo(admin, XkmsConfiguration.getResponseCaUsedForSigning());
    		if(info == null){    		
    			throw new EJBException("Property parameter xkms.response.causedforsigning ("+XkmsConfiguration.getResponseCaUsedForSigning()+") is missconfigured, should contain a existing CA name.");
    		}    	    
    		
    		cAIdUsedForSigning = new Integer(info.getCAId());    		
    	}
    	return cAIdUsedForSigning.intValue();
    }
    

    private static Collection acceptedCAs = null;
    /**
     * Method that returns the parameter in the property file
     * xkms.request.acceptedcas on which CA that should
     * be accepted for signing XKMS requests
     */
    public static Collection getAcceptedCA(Admin admin,CAAdminSession cAAdminSession){
    	if(acceptedCAs == null){
    		acceptedCAs = new ArrayList();
    		String[] cANames = XkmsConfiguration.getRequestAcceptedCas();
    		for(int i=0; i < cANames.length;i++){
    		  CAInfo info = cAAdminSession.getCAInfo(admin, cANames[i]);
    		  if(info == null){    		
    			throw new EJBException("Property parameter xkms.request.acceptedcas is missconfigured, should contain a ';' separated string of existing CA names.");
    		  }
    		  acceptedCAs.add(new Integer(info.getCAId()));
    		}
    	}
    	return acceptedCAs;
    }
    
    /**
     * Method that returns the parameter in the property file
     * xkms.krss.poprequired
     */
    public static boolean isPOPRequired(){
    	return XkmsConfiguration.getKrssPopRequired();
    }
    
    /**
     * Method that returns the parameter in the property file
     * xkms.krss.servergenkeylength
     */
    public static int getServerKeyLength(){
    	return XkmsConfiguration.getKrssServerGenKeyLength();
    }
    
    /**
     * Method that returns the parameter in the propertyfile
     * xkms.krss.allowrevokation
     */
    public static boolean isRevokationAllowed(){
    	return XkmsConfiguration.getKrssAllowRevokation();
    }
    
    /**
     * Method that returns the parameter in the property file
     * xkms.krss.allowautomaticreissue
     */
    public static boolean isAutomaticReissueAllowed(){
    	return XkmsConfiguration.getKrssAllowAutomaticReissue();
    }
    
}
