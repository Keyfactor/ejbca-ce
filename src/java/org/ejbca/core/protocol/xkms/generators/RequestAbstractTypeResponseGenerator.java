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

import java.math.BigInteger;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.sign.SernoGenerator;
import org.ejbca.core.protocol.xkms.common.XKMSConstants;
import org.w3._2002._03.xkms_.ObjectFactory;
import org.w3._2002._03.xkms_.RequestAbstractType;
import org.w3._2002._03.xkms_.ResultType;



/**
 * Help method that generates the most basic parts of a xkms message 
 * response
 * 
 * 
 * @author Philip Vendil 2006 sep 27
 *
 * @version $Id: RequestAbstractTypeResponseGenerator.java,v 1.1 2006-12-22 09:21:39 herrvendil Exp $
 */

public abstract class RequestAbstractTypeResponseGenerator extends BaseResponseGenerator{

    private static Logger log = Logger.getLogger(RequestAbstractTypeResponseGenerator.class);
    
    protected static final BigInteger SERVERRESPONSELIMIT = new BigInteger("30");
    

	protected RequestAbstractType req;
	protected ObjectFactory xkmsFactory = new ObjectFactory();
	protected org.w3._2000._09.xmldsig_.ObjectFactory sigFactory = new org.w3._2000._09.xmldsig_.ObjectFactory();
	
	protected String resultMajor = null;
	protected String resultMinor = null;

	
	public RequestAbstractTypeResponseGenerator(RequestAbstractType req){
	  super();		
	  this.req = req;	  	 
	        
	}
	



	/**
	 * Returns the generated response common data that should be sent back to the client
	 * @return the response
	 */
	protected void populateResponse(ResultType result, boolean requestVerifies){
		result.setService(genServiceValue());
		result.setId(genId());
		result.setRequestId(req.getId());					
		result.setOpaqueClientData(req.getOpaqueClientData());
						

		// Nonce is required for two phase commit	
		
		if(!requestVerifies){
			resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
			resultMinor = XKMSConstants.RESULTMINOR_NOAUTHENTICATION;			
		}
 
	}


	protected int getResponseLimit() {
		if(req.getResponseLimit() == null || req.getResponseLimit().compareTo(SERVERRESPONSELIMIT) >= 0){
			return SERVERRESPONSELIMIT.intValue();
		}
		
		return req.getResponseLimit().intValue();
	}


	private String genId() {
		String id = "";
		try {
			id = SernoGenerator.instance().getSerno().toString();
		} catch (Exception e) {
			log.error("Error generating response ID ",e );
		}
		return id;
	}


	private String genServiceValue() {
		return "http://@httpsserver.hostname@:@httpserver.pubhttp@/ejbca/xkms/xkms";
	}
	

	
    /**
     * Method used to set the result of the operation
     */	
    protected void setResult(ResultType result){
    	result.setResultMajor(resultMajor);
    	if(resultMinor != null){
    		result.setResultMinor(resultMinor);
    	}
    }
    

    


	
	
}
