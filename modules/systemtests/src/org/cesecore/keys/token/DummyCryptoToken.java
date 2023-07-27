/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.keys.token;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Properties;

import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.BaseCryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.KeyGenParams;


/** This class is used only for testing.
 * 
 * @version $Id$
 */
public class DummyCryptoToken extends BaseCryptoToken {

    private static final long serialVersionUID = -6136504057204777472L;
    
    private int id = 4711;
    
    private PublicKey publicKey = null;
    private PrivateKey privateKey = null;
    
    public DummyCryptoToken() throws InstantiationException {
        try {
            KeyPair keypair = KeyTools.genKeys("512", "RSA");
            this.publicKey = keypair.getPublic();
            this.privateKey = keypair.getPrivate();
           } catch (InvalidAlgorithmParameterException e) {
         // Ignore
        }
       
    }

    @Override
    public void init(Properties properties, byte[] data, int id) throws Exception {
    	this.id = id;
    	// Do nothing
    }

    @Override
    public int getId() {
    	return this.id;
    }
    
    @Override
    public Properties getProperties(){
    	return new Properties();
    }
   
    @Override
    public PrivateKey getPrivateKey(String alias){
      return privateKey;
    }

    @Override
    public PublicKey getPublicKey(String alias){    
      return publicKey;  
    }

    @Override
    public void deleteEntry(final String alias) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {    	
    }

    @Override
    public void generateKeyPair(KeyGenParams keyGenParams, String alias) throws InvalidAlgorithmParameterException, CryptoTokenOfflineException {
        generateKeyPair(keyGenParams.getKeySpecification(), alias);
        
    }
    
    @Override
    public void generateKeyPair( final String keySpec, final String alias) throws InvalidAlgorithmParameterException {     
        KeyPair keypair = KeyTools.genKeys("512", "RSA");
        this.publicKey = keypair.getPublic();
        this.privateKey = keypair.getPrivate();
    }
    
    @Override
    public void generateKeyPair(final AlgorithmParameterSpec spec, final String alias) throws InvalidAlgorithmParameterException,
            CertificateException, IOException, CryptoTokenOfflineException {
        KeyPair keypair = KeyTools.genKeys("512", "RSA");
        this.publicKey = keypair.getPublic();
        this.privateKey = keypair.getPrivate();
    }

    @Override
    public void generateKey(final String algorithm, final int keysize, final String alias) throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, CryptoTokenOfflineException {
        
    }

    @Override
	public void activate(char[] authenticationcode) {
		// Do Nothing		
	}

    @Override
	public void deactivate() {
       // Do Nothing
	}

    @Override
	public byte[] getTokenData() {
    	return null;
	}

    @Override
    public void testKeyPair(final String alias) throws InvalidKeyException, CryptoTokenOfflineException {
      //Do nothing.
    }

    @Override
    public boolean permitExtractablePrivateKeyForTest() {
        return doPermitExtractablePrivateKey();
    }

}

