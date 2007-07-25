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


/** Handles maintenance of the soft devices producing signatures and handling the private key
 *  and stored in database.
 * 
 * @version $Id: NullCAToken.java,v 1.3 2007-07-25 08:56:46 anatom Exp $
 */
public class NullCAToken extends BaseCAToken {

    public static final float LATEST_VERSION = 1; 

    
    public NullCAToken() throws InstantiationException {
    }
    
    public NullCAToken(HashMap data) throws InstantiationException {    
    }
    
    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.IHardCAToken#init(java.util.Properties, java.lang.String)
     */
    public void init(Properties properties, HashMap data, String signaturealgorithm) throws Exception {
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
    

    /** Returns the signature Provider that should be used to sign things with
     *  the PrivateKey object returned by this signingdevice implementation.
     * @return String the name of the Provider
     */
    public String getProvider(){
      return "BC";  
    }

    /** Implemtation of UpgradableDataHashMap function getLatestVersion */
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

