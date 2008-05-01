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

import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;

/**
 * Class that parses the property file for the 
 * XKMS configuration
 * 
 * 
 * @author Philip Vendil 2006 dec 17
 *
 * @version $Id$
 */

public class XKMSConfig {
	
    // Configuration variables
    private static String REQUIRESIGNATURE   = "@xkms.request.requiresignature@";
    private static String ACCEPTEDCAS        = "@xkms.request.acceptedcas@";
    private static String ACCEPTSIGNREQUEST  = "@xkms.response.acceptsignrequest@";
    private static String ALWAYSSIGN         = "@xkms.response.alwayssign@";
    private static String CAUSEDFORSIGNING   = "@xkms.response.causedforsigning@";
    private static String SIGNATUREISNONREP  = "@xkms.keyusage.signatureisnonrep@";

    private static String POPREQUIRED        = "@xkms.krss.poprequired@";
    private static String SERVERGENKEYLENGTH = "@xkms.krss.servergenkeylength@";
    private static String ALLOWREVOKATION    = "@xkms.krss.allowrevokation@";
    private static String ALLOWAUTOREISSUE   = "@xkms.krss.allowautomaticreissue@";
    
    private static Boolean signReq = null;
    /**
     * Method that returns the parameter in the propertyfile
     * xkms.request.requiresignature which indicates
     * that a signature is required for all KISS requests
     */
    public static boolean isSignedRequestRequired(){
    	if(signReq == null){
    		if(REQUIRESIGNATURE.equalsIgnoreCase("true")){
    			signReq = new Boolean(true);
    		}
    		
    		if(REQUIRESIGNATURE.equalsIgnoreCase("false")){
    			signReq = new Boolean(false);
    		}

    		if(signReq == null){
    			throw new EJBException("Property parameter xkms.request.requiresignature is missconfigured, must be either 'true' or 'false'.");
    		}

    		
    	}

    	return signReq.booleanValue();
    }
    

    private static Boolean acceptSignReq = null;
    /**
     * Method that returns the parameter in the propertyfile
     * xkms.response.acceptsignrequest which indicates
     * that the service will sign the responses on requests
     */
    public static boolean acceptSignRequests(){
    	if(acceptSignReq == null){
    		if(ACCEPTSIGNREQUEST.equalsIgnoreCase("true")){
    			acceptSignReq = new Boolean(true);	
    		}
    		
    		if(ACCEPTSIGNREQUEST.equalsIgnoreCase("false")){
    			acceptSignReq = new Boolean(false);	
    		}

    		if(acceptSignReq == null){
    			throw new EJBException("Property parameter xkms.response.acceptsignrequest is missconfigured, must be either 'true' or 'false'.");
    		}
    		
    	}
    	
    	return acceptSignReq.booleanValue();
    }


    private static Boolean alwaysSignResponses = null;
    /**
     * Method that returns the parameter in the propertyfile
     * xkms.response.alwayssign which indicates
     * that the service will always sign the responses.
     */
    public static boolean alwaysSignResponses(){
    	if(alwaysSignResponses == null){
    		if(ALWAYSSIGN.equalsIgnoreCase("true")){
    			alwaysSignResponses = new Boolean(true);	
    		}
    		
    		if(ALWAYSSIGN.equalsIgnoreCase("false")){
    			alwaysSignResponses = new Boolean(false);	
    		}

    		if(alwaysSignResponses == null){
    			throw new EJBException("Property parameter xkms.response.alwayssign is missconfigured, must be either 'true' or 'false'.");
    		}    	    
    		    		
    	}
    	return alwaysSignResponses.booleanValue();
    }
    

    private static Boolean signIsNonRep = null;
    /**
     * Method that returns the parameter in the propertyfile
     * xkms.keyusage.signatureisnonrep
     */
    public static boolean signatureIsNonRep(){
    	if(signIsNonRep == null){
    		if(SIGNATUREISNONREP.equalsIgnoreCase("true")){
    			signIsNonRep = new Boolean(true);	
    		}
    		
    		if(SIGNATUREISNONREP.equalsIgnoreCase("false")){
    			signIsNonRep = new Boolean(false);	
    		}

    		if(signIsNonRep == null){
    			throw new EJBException("Property parameter xkms.keyusage.signatureisnonrep is missconfigured, must be either 'true' or 'false'.");
    		}    	    
    		   		
    	}
    	    	
    	
    	return signIsNonRep.booleanValue();
    }
    

    private static Integer cAIdUsedForSigning = null;
    /**
     * Method that returns the parameter in the propertyfile
     * xkms.response.causedforsigning on which CA that should
     * be used for signing XKMS requests
     */
    public static int cAIdUsedForSigning(Admin admin,ICAAdminSessionLocal cAAdminSession){
    	if(cAIdUsedForSigning == null){
    		CAInfo info = cAAdminSession.getCAInfo(admin, CAUSEDFORSIGNING);
    		if(info == null){    		
    			throw new EJBException("Property parameter xkms.response.causedforsigning ("+CAUSEDFORSIGNING+") is missconfigured, should contain a existing CA name.");
    		}    	    
    		
    		cAIdUsedForSigning = new Integer(info.getCAId());    		
    	}
    	return cAIdUsedForSigning.intValue();
    }
    

    private static Collection acceptedCAs = null;
    /**
     * Method that returns the parameter in the propertyfile
     * xkms.request.acceptedcas on which CA that should
     * be accepted for signing XKMS requests
     */
    public static Collection getAcceptedCA(Admin admin,ICAAdminSessionLocal cAAdminSession){
    	if(acceptedCAs == null){
    		acceptedCAs = new ArrayList();
    		
    		String[] cANames = ACCEPTEDCAS.split(";");
    		
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
    
    private static Boolean pOPRequired = null;
    /**
     * Method that returns the parameter in the propertyfile
     * xkms.krss.poprequired
     */
    public static boolean isPOPRequired(){
    	if(pOPRequired == null){
    		if(POPREQUIRED.equalsIgnoreCase("true")){
    			pOPRequired = new Boolean(true);	
    		}
    		
    		if(POPREQUIRED.equalsIgnoreCase("false")){
    			pOPRequired = new Boolean(false);	
    		}

    		if(pOPRequired == null){
    			throw new EJBException("Property parameter xkms.krss.poprequired is missconfigured, must be either 'true' or 'false'.");
    		}    	    
    		   		
    	}
    	    	
    	
    	return pOPRequired.booleanValue();
    }

    
    private static Integer serverKeyLength = null;
    /**
     * Method that returns the parameter in the propertyfile
     * xkms.krss.servergenkeylength
     */
    public static int getServerKeyLength(){
    	if(serverKeyLength == null){
            try{
    			serverKeyLength = new Integer(Integer.parseInt(SERVERGENKEYLENGTH));	
            }catch(NumberFormatException e){}
            catch(NullPointerException e){}
    		

    		if(serverKeyLength == null){
    			throw new EJBException("Property parameter xkms.krss.servergenkeylength is missconfigured, must contain digits only.");
    		}    	        		   		
    	}

    	return serverKeyLength.intValue();
    }
    
    private static Boolean allowRevokation = null;
    /**
     * Method that returns the parameter in the propertyfile
     * xkms.krss.allowrevokation
     */
    public static boolean isRevokationAllowed(){
    	if(allowRevokation == null){
    		if(ALLOWREVOKATION.equalsIgnoreCase("true")){
    			allowRevokation = new Boolean(true);	
    		}
    		
    		if(ALLOWREVOKATION.equalsIgnoreCase("false")){
    			allowRevokation = new Boolean(false);	
    		}

    		if(allowRevokation == null){
    			throw new EJBException("Property parameter xkms.krss.allowrevokation is missconfigured, must be either 'true' or 'false'.");
    		}    	       		   		
    	}

    	return allowRevokation.booleanValue();
    }
    
    private static Boolean allowAutoReissue = null;
    /**
     * Method that returns the parameter in the propertyfile
     * xkms.krss.allowautomaticreissue
     */
    public static boolean isAutomaticReissueAllowed(){
    	if(allowAutoReissue == null){
    		if(ALLOWAUTOREISSUE.equalsIgnoreCase("true")){
    			allowAutoReissue = new Boolean(true);	
    		}
    		
    		if(ALLOWAUTOREISSUE.equalsIgnoreCase("false")){
    			allowAutoReissue = new Boolean(false);	
    		}

    		if(allowAutoReissue == null){
    			throw new EJBException("Property parameter xkms.krss.allowautomaticreissue is missconfigured, must be either 'true' or 'false'.");
    		}    	       		   		
    	}

    	return allowAutoReissue.booleanValue();
    }
    
}
