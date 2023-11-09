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

import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequest;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceTypes;
import org.cesecore.certificates.certificate.request.MsKeyArchivalRequestMessage;


/**
 * Class used when requesting key recovery related services from a CA.  
 *
 * @version $Id$
 */
public class KeyRecoveryCAServiceRequest extends ExtendedCAServiceRequest implements Serializable {    
 
	private static final long serialVersionUID = -5686267640542389771L;
    public static final int COMMAND_ENCRYPTKEYS = 1;
	public static final int COMMAND_DECRYPTKEYS = 2;
    public static final int COMMAND_DECRYPT_MS_KEY_ARCHIVAL_PRIVKEY = 3;
	
    private int command;
    private byte[] keydata;
    private KeyPair keypair;
    private int cryptoTokenId;
    private String keyAlias;
    private MsKeyArchivalRequestMessage msKeyArchivalRequestMessage;
    
    /** Constructor for KeyRecoveryCAServiceRequest used to decrypt data
     */                   
    public KeyRecoveryCAServiceRequest(int command, byte[] keydata, int cryptoTokenId, String keyAlias) {
        this.command = command;
        this.keydata = keydata;
        this.cryptoTokenId = cryptoTokenId;
        this.keyAlias = keyAlias;
    }

    /** Constructor for KeyRecoveryCAServiceRequest used to encrypt data
     */                   
    public KeyRecoveryCAServiceRequest(int command, KeyPair keypair) {
    	this.command = command;
    	this.keypair = keypair;
    }

    /**
     * Constructor used to decrypt private key from MS Key Archival request
     */
    public KeyRecoveryCAServiceRequest(final int command, final MsKeyArchivalRequestMessage msKeyArchivalRequestMessage, final int cryptoTokenId,
            final String keyAlias) {
        this.command = command;
        this.msKeyArchivalRequestMessage = msKeyArchivalRequestMessage;
        this.cryptoTokenId = cryptoTokenId;
        this.keyAlias = keyAlias;
    }
    
    public int getCommand(){
    	return command;    	
    }
    
    /**
     *  Returns data belonging to the decrypt keys request, returns null otherwise.
     */
    
    public  byte[] getKeyData(){
    	byte[] ret = null;
    	if(command == COMMAND_DECRYPTKEYS) {
        	ret = keydata;
    	}
    	return ret;
    }

    /**
     *  Returns data belonging to the encrypt keys request, returns null otherwise.
     */
    public  KeyPair getKeyPair(){
    	KeyPair ret = null;
    	if(command == COMMAND_ENCRYPTKEYS) {
        	ret = keypair;
    	}
    	return ret;
    }

    public MsKeyArchivalRequestMessage getMsKeyArchivalRequestMessage() {
        if (command == COMMAND_DECRYPT_MS_KEY_ARCHIVAL_PRIVKEY) {
            return msKeyArchivalRequestMessage;
        } else {
            return null;
        }
    }
    
    
	public int getCryptoTokenId() {
        return cryptoTokenId;
    }

    public String getKeyAlias() {
        return keyAlias;
    }

    @Override
	public int getServiceType() {
		return ExtendedCAServiceTypes.TYPE_KEYRECOVERYEXTENDEDSERVICE;
	}

}
