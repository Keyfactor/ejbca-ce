package se.anatom.ejbca.ca.caadmin.extendedcaservices;

import java.io.Serializable;
import java.security.KeyPair;


/**
 * Class used when requesting key recovery related services from a CA.  
 *
 * @version $Id: KeyRecoveryCAServiceRequest.java,v 1.1 2004-01-25 09:36:10 herrvendil Exp $
 */
public class KeyRecoveryCAServiceRequest extends ExtendedCAServiceRequest implements Serializable {    
 
	public static final int COMMAND_ENCRYPTKEYS = 1;
	public static final int COMMAND_DECRYPTKEYS = 2;
	
    private int command;
    private byte[] keydata;
    private KeyPair keypair;
    /** Constructor for KeyRecoveryCAServiceRequest
     */                   
    public KeyRecoveryCAServiceRequest(int command, byte[] keydata) {
        this.command = command;
        this.keydata = keydata;
    }

    /** Constructor for KeyRecoveryCAServiceRequest
     */                   
    public KeyRecoveryCAServiceRequest(int command, KeyPair keypair) {
    	this.command = command;
    	this.keypair = keypair;
    }
    
    public int getCommand(){
    	return command;    	
    }
    
    /**
     *  Returns data beloning to the decrypt keys request, returns null oterwise.
     */
    
    public  byte[] getKeyData(){
    	if(command != COMMAND_DECRYPTKEYS)
    	  return null;
    	return keydata;
    }

    /**
     *  Returns data beloning to the encrypt keys request, returns null oterwise.
     */
    
    public  KeyPair getKeyPair(){
    	if(command != COMMAND_ENCRYPTKEYS)
    		return null;
    	return keypair;
    }
    
}
