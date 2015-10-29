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
import java.security.KeyPair;

import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceResponse;


/**
 * Class used when delevering key recovery service response from a CA.  
 *
 * @version $Id$
 */
public class KeyRecoveryCAServiceResponse extends ExtendedCAServiceResponse implements Serializable {    
             
	private static final long serialVersionUID = -6164842390930090876L;
    public static final int TYPE_ENCRYPTKEYSRESPONSE = 1;
	public static final int TYPE_DECRYPTKEYSRESPONSE = 1;
    
    private int type;
    private byte[] keydata;
    private KeyPair keypair;
    private String keyAlias;
    private int cryptoTokenId;
    private String publicKeyId;
	
    /** Used when decrypting key recovery data, keydata is read from the database */
    public KeyRecoveryCAServiceResponse(int type, byte[] keydata, final int cryptoTokenId, final String keyAlias, final String publicKeyId) {
       this.type = type;
       this.keydata = keydata;
       this.cryptoTokenId = cryptoTokenId;
       this.keyAlias = keyAlias;
       this.publicKeyId = publicKeyId;
    } 
    
    /** Used when encrypting data, keypair is encrypted to be stored in the database */
    public KeyRecoveryCAServiceResponse(int type, KeyPair keypair, final int cryptoTokenId, final String keyAlias, final String publicKeyId) {
    	this.type = type;
    	this.keypair = keypair;
        this.cryptoTokenId = cryptoTokenId;
        this.keyAlias = keyAlias;
        this.publicKeyId = publicKeyId;
    }  
           
    /**
     * @return type of response, one of the TYPE_ constants.
     */
    public int getType(){
    	return type;
    }
    
    /**
     *  Method returning the encrypted key data if the type of response 
     *  is TYPE_ENCRYPTRESPONSE, null otherwise.
     */
    
    public byte[] getKeyData(){
    	byte[] ret = null;
    	if(type == TYPE_ENCRYPTKEYSRESPONSE) {
        	ret = keydata;
    	}
    	return ret;
    }

    /**
     *  Method returning the decrypted keypair if the type of response 
     *  is TYPE_DECRYPTRESPONSE, null otherwise.
     */
    public KeyPair getKeyPair(){
    	KeyPair ret = null;
    	if(type == TYPE_DECRYPTKEYSRESPONSE) {
        	ret = keypair;    	
    	}
    	return ret;
    }

    public String getKeyAlias() {
        return keyAlias;
    }

    public int getCryptoTokenId() {
        return cryptoTokenId;
    }

    public String getPublicKeyId() {
        return publicKeyId;
    }
 
}
