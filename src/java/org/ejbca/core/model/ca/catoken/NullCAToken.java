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
 
package org.ejbca.core.model.ca.catoken;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Properties;


/** This class is used as CAToken for virtual CAs that does not have a keystore, such as external SubCAs.
 * 
 * @version $Id$
 */
public class NullCAToken extends BaseCAToken {

    public static final float LATEST_VERSION = 1; 

    
    public NullCAToken() throws InstantiationException {
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.ICAToken#init(java.util.Properties, java.util.HashMap, java.lang.String, int)
     */
    public void init(Properties properties, HashMap data, String signaturealgorithm, int caid) throws Exception {
    	setJCAProviderName("BC");
    }

   /**
    * Method that generates the keys that will be used by the CAToken.
    */
   public void generateKeys(CATokenInfo catokeninfo) throws Exception{  
      // Do Nothing
   }
   

   
   public CATokenInfo getCATokenInfo(){
     return new NullCATokenInfo();
   }
   
   /**
    * Updates the CAToken data saved in database.
    */
    public void updateCATokenInfo(CATokenInfo catokeninfo){                          
    }
   
   /** Returns null
    *
    * @return PrivateKey object
    */
    public PrivateKey getPrivateKey(int purpose){
      return null;        
    }

    /** Returns null
    *
    * @return PublicKey object
    */
    public PublicKey getPublicKey(int purpose){    
      return null;        
    }
    

    /** Implementation of UpgradableDataHashMap function getLatestVersion */
    public float getLatestVersion(){
       return LATEST_VERSION;
    }

	/** 
	 * @see org.ejbca.core.model.ca.catoken.CATokenContainer#activate(java.lang.String)
	 */
	public void activate(String authenticationcode) throws CATokenAuthenticationFailedException, CATokenOfflineException {
		// Do Nothing		
	}

	/**
	 * @see org.ejbca.core.model.ca.catoken.CATokenContainer#deactivate()
	 */
	public boolean deactivate() {
       // Do Nothing
	   return true;	
	}
    
    
}

