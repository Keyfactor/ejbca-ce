package se.anatom.ejbca.ca.caadmin.extendedcaservices;

import java.io.Serializable;
import java.security.KeyPair;


/**
 * Class used when delevering key recovery service response from a CA.  
 *
 * @version $Id: KeyRecoveryCAServiceResponse.java,v 1.1 2004-01-25 09:36:10 herrvendil Exp $
 */
public class KeyRecoveryCAServiceResponse extends ExtendedCAServiceResponse implements Serializable {    
             
	public final static int TYPE_ENCRYPTKEYSRESPONSE = 1;
	public final static int TYPE_DECRYPTKEYSRESPONSE = 1;
    
    private int type;
    private byte[] keydata;
    private KeyPair keypair;
	
    public KeyRecoveryCAServiceResponse(int type, byte[] keydata) {
       this.type=type;
       this.keydata=keydata;
    } 
    
    public KeyRecoveryCAServiceResponse(int type, KeyPair keypair) {
    	this.type=type;
    	this.keypair=keypair;
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
    	if(type != TYPE_ENCRYPTKEYSRESPONSE)
    		return null;
    	return keydata;
    }

    /**
     *  Method returning the decrypted keypair if the type of response 
     *  is TYPE_DECRYPTRESPONSE, null otherwise.
     */
    public KeyPair getKeyPair(){
    	if(type != TYPE_DECRYPTKEYSRESPONSE)
    		return null;
    	return keypair;    	
    }
        
}
