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
 
package se.anatom.ejbca.ca.caadmin;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;

import se.anatom.ejbca.ca.exception.CATokenAuthenticationFailedException;
import se.anatom.ejbca.ca.exception.CATokenOfflineException;
/** Handles maintenance of the soft devices producing signatures and handling the private key
 *  and stored in database.
 * 
 * @version $Id: NullCAToken.java,v 1.6 2004-05-10 04:35:10 herrvendil Exp $
 */
public class NullCAToken extends CAToken implements java.io.Serializable{

    public static final float LATEST_VERSION = 1; 

    
    public NullCAToken(){
      data = new HashMap();   
      data.put(CATOKENTYPE, new Integer(CATokenInfo.CATOKENTYPE_NULL));
      data.put(VERSION, new Float(LATEST_VERSION));
    }
    
    public NullCAToken(HashMap data) {
    
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

    /** Implemtation of UpgradableDataHashMap function upgrade. */

    public void upgrade(){
      if(LATEST_VERSION != getVersion()){
        // New version of the class, upgrade

        data.put(VERSION, new Float(LATEST_VERSION));
      }  
    }

	/** 
	 * @see se.anatom.ejbca.ca.caadmin.CAToken#activate(java.lang.String)
	 */
	public void activate(String authenticationcode) throws CATokenAuthenticationFailedException, CATokenOfflineException {
		// Do Nothing		
	}

	/**
	 * @see se.anatom.ejbca.ca.caadmin.CAToken#deactivate()
	 */
	public boolean deactivate() {
       // Do Nothing
	   return true;	
	}
    
    
}

