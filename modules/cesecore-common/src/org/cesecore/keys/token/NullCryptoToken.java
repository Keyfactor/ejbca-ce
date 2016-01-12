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
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


/** This class is used as crypto Token for virtual CAs that does not have a keystore, such as external SubCAs.
 * 
 * @version $Id$
 */
public class NullCryptoToken extends BaseCryptoToken {

    private static final long serialVersionUID = -1L;

    private int id;

    public NullCryptoToken() {
    	super();
    }

    @Override
    public void init(Properties properties, byte[] data, int id) throws Exception {
    	// We only need to set JCA provider, if JCE provider is the same (which is the common case)
    	setJCAProviderName(BouncyCastleProvider.PROVIDER_NAME);
    	this.id = id;
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
      return null;        
    }

    @Override
    public PublicKey getPublicKey(String alias){    
      return null;        
    }
    
    @Override
    public void deleteEntry(final String alias) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, CryptoTokenOfflineException {    	
    }

    @Override
    public void generateKeyPair(final String keySpec, final String alias) throws InvalidAlgorithmParameterException,
            CryptoTokenOfflineException {
    }

    @Override
    public void generateKeyPair(final AlgorithmParameterSpec spec, final String alias) throws InvalidAlgorithmParameterException,
            CertificateException, IOException, CryptoTokenOfflineException {
    }

    @Override
    public void generateKey(final String algorithm, final int keysize, final String alias) throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, CryptoTokenOfflineException {
    }

    @Override
	public void activate(char[] authenticationcode) throws CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException {
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
    public boolean permitExtractablePrivateKeyForTest() {
        return doPermitExtractablePrivateKey();
    }

}

