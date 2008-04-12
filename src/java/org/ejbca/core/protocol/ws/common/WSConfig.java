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

package org.ejbca.core.protocol.ws.common;

import javax.ejb.EJBException;

/**
 * Class that parses the property file for the 
 * JAXWS configuration
 * 
 * 
 * @author Philip Vendil 2007 jun 19
 *
 * @version $Id: WSConfig.java,v 1.4 2008-04-12 17:30:13 herrvendil Exp $
 */
public class WSConfig {
	
    // Configuration variables
    private static String APPROVAL_GETHARDTOKENDATA     = "@jaxws.approval.gethardtoken@";
    private static String APPROVAL_GENTOKENCERTIFICATES = "@jaxws.approval.gentokencerts@";
    private static String NUMBEROFREQUREDAPPROVALS      = "@jaxws.numberofrequiredapprovals@";
    private static String NOAUTHONFETCHUSERDATA         = "@jaxws.noauthonfetchuserdata@";
    private static String SETMSLOGONONHOLD              = "@jaxws.gentokens.setmslogononhold@";
    
    private static Boolean approvalGetHardTokenData = null;
    /**
     * Method that returns the parameter in the propertyfile
     * jaxws.approval.gethardtoken if approvals
     * is supported for the getHardTokenData call
     */
    public static boolean isApprovalGetHardTokenData(){
    	if(approvalGetHardTokenData == null){
    		if(APPROVAL_GETHARDTOKENDATA.equalsIgnoreCase("true")){
    			approvalGetHardTokenData = new Boolean(true);
    		}
    		
    		if(APPROVAL_GETHARDTOKENDATA.equalsIgnoreCase("false")){
    			approvalGetHardTokenData = new Boolean(false);
    		}

    		if(approvalGetHardTokenData == null){
    			throw new EJBException("Property parameter jaxws.approval.gethardtokendata is missconfigured, must be either 'true' or 'false'.");
    		}
    	}

    	return approvalGetHardTokenData.booleanValue();
    }
    

    private static Boolean approvalGenTokenCertificates = null;
    /**
     * Method that returns the parameter in the propertyfile
     * jaxws.approval.gentokencerts if approvals
     * is supported for the genTokenCertificates call
     */
    public static boolean isApprovalGenTokenCertificates(){
    	if(approvalGenTokenCertificates == null){
    		if(APPROVAL_GENTOKENCERTIFICATES.equalsIgnoreCase("true")){
    			approvalGenTokenCertificates = new Boolean(true);	
    		}
    		
    		if(APPROVAL_GENTOKENCERTIFICATES.equalsIgnoreCase("false")){
    			approvalGenTokenCertificates = new Boolean(false);	
    		}

    		if(approvalGenTokenCertificates == null){
    			throw new EJBException("Property parameter jaxws.approval.gentokencertificates is missconfigured, must be either 'true' or 'false'.");
    		}    		
    	}
    	
    	return approvalGenTokenCertificates.booleanValue();
    }

    private static Integer numberOfRequredWSApprovals = null;
    /**
     * Method that returns the parameter in the propertyfile
     * jaxws.numberofrequiredapprovals which indicates
     * how many approvals is required for the WS related approvals
     */
    public static int getNumberOfWSApprovals(){
    	if(numberOfRequredWSApprovals == null){
    		
    		try{
    			numberOfRequredWSApprovals = new Integer(NUMBEROFREQUREDAPPROVALS);
    		}catch(NumberFormatException e){}
    		
    		    	
    		if(numberOfRequredWSApprovals == null){
    			throw new EJBException("Property parameter jaxws.numberofrequiredapprovals is missconfigured, must be a number.");
    		}    		
    	}
    	
    	return numberOfRequredWSApprovals.intValue();
    }
    
    private static Boolean noAuthOnFetchUserData = null;
    /**
     * Method that returns the parameter in the propertyfile
     * jaxws.approval.gentokencerts if approvals
     * is supported for the genTokenCertificates call
     */
    public static boolean isNoAuthOnFetchUserData(){
    	if(noAuthOnFetchUserData == null){
    		if(NOAUTHONFETCHUSERDATA.equalsIgnoreCase("true")){
    			noAuthOnFetchUserData = new Boolean(true);	
    		}
    		
    		if(NOAUTHONFETCHUSERDATA.equalsIgnoreCase("false")){
    			noAuthOnFetchUserData = new Boolean(false);	
    		}

    		if(noAuthOnFetchUserData == null){
    			throw new EJBException("Property parameter jaxws.noauthonfetchuserdata is missconfigured, must be either 'true' or 'false'.");
    		}    		
    	}
    	
    	return noAuthOnFetchUserData.booleanValue();
    }
    
    private static Boolean setMSLogonOnHold = null;
    /**
     * Method that returns the parameter in the property file
     * jaxws.approval.setmslogononhold 
     */
    public static boolean isSetMSLogonOnHold(){
    	if(setMSLogonOnHold == null){
    		if(SETMSLOGONONHOLD.equalsIgnoreCase("true")){
    			setMSLogonOnHold = new Boolean(true);	
    		}
    		
    		if(SETMSLOGONONHOLD.equalsIgnoreCase("false")){
    			setMSLogonOnHold = new Boolean(false);	
    		}

    		if(setMSLogonOnHold == null){
    			throw new EJBException("Property parameter jaxws.setmslogononhold is missconfigured, must be either 'true' or 'false'.");
    		}    		
    	}
    	
    	return setMSLogonOnHold.booleanValue();
    }
    
}
