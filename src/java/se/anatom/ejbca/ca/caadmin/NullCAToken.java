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
/** Handles maintenance of the soft devices producing signatures and handling the private key
 *  and stored in database.
 * 
 * @version $Id: NullCAToken.java,v 1.5 2004-04-16 07:38:58 anatom Exp $
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
   
   /** Returns the private key (if possible) used for signature creation.
    *
    * @return PrivateKey object
    */
    public PrivateKey getPrivateSignKey(){
      return null;        
    }

   /** Returns the public key (if possible) used for signature verification.
    *
    * @return PublicKey object
    */
    public PublicKey getPublicSignKey(){    
      return null;        
    }

   /** Returns the private key (if possible) used for decryption.
    *
    * @return PrivateKey object
    */
    public PrivateKey getPrivateDecKey(){
      return null;        
    }

   /** Returns the public key (if possible) used for encryption.
    *
    * @return PublicKey object
    */
    public PublicKey getPublicEncKey(){
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
    
    
}

