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

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.core.model.SecConst;


/**
 * @author lars
 * @version $Id: BaseCAToken.java,v 1.8 2006-09-05 13:18:02 primelars Exp $
 */
public abstract class BaseCAToken implements IHardCAToken {

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(BaseCAToken.class);

    final private String sProviderName;
    final private String sSlotLabelKey;

    /** The constructor of HardCAToken should throw an InstantiationException if the token can not
     * be created, if for example depending jar files for the particular HSM is not available.
     * 
     * @throws InstantiationException if the nCipher provider is not available
     */
    public BaseCAToken(String providerClassName, String pn,
                       String slk) throws InstantiationException, IllegalAccessException {
        log.debug("Creating CAToken");
        sProviderName = pn;
        sSlotLabelKey = slk;
        try {
            Provider prov = (Provider)Class.forName(providerClassName).newInstance();
            Security.addProvider( prov );            
        } catch (ClassNotFoundException e) {
            throw new InstantiationException("Class not found: "+providerClassName);
        }
    }

    private KeyStrings keyStrings;
    protected String sSlotLabel;
    private Map mKeys;
	private String mAuthCode;

    private void autoActivate() {
        if ( mKeys==null && mAuthCode!=null )
            try {
                activate(mAuthCode);
            } catch (Exception e) {
                log.debug(e);
            }
    }
    private void testKey( KeyPair pair ) throws Exception {
        final byte input[] = "Lillan gick på vägen ut, mötte där en katt ...".getBytes();
        final byte signBV[];
        {
            Signature signature = Signature.getInstance("SHA1withRSA", getProvider());
            signature.initSign( pair.getPrivate() );
            signature.update( input );
            signBV = signature.sign();
        }{
            Signature signature = Signature.getInstance("SHA1withRSA", "BC");
            signature.initVerify(pair.getPublic());
            signature.update(input);
            if ( !signature.verify(signBV) )
                throw new InvalidKeyException("Not possible to sign and then verify with key pair.");
        }
    }
    /**
     * @param keyStore
     * @param authCode
     * @throws Exception
     */
    protected void setKeys(KeyStore keyStore, String authCode) throws Exception {
        mKeys = null;
        final String keyAliases[] = keyStrings.getAllStrings();
        final Map mTmp = new Hashtable();
        for ( int i=0; i<keyAliases.length; i++ ) {
            PrivateKey privateK =
                (PrivateKey)keyStore.getKey(keyAliases[i],
                                            authCode!=null ? authCode.toCharArray():null);
            PublicKey publicK = readPublicKey(keyStore, keyAliases[i]);
            KeyPair keyPair = new KeyPair(publicK, privateK);
            mTmp.put(keyAliases[i], keyPair);
        }
        for ( int i=0; i<keyAliases.length; i++ ) {
            KeyPair pair = (KeyPair)mTmp.get(keyAliases[i]);
            testKey(pair);
            log.debug("Key with alias "+keyAliases[i]+" tested. toString for private part: "+pair.getPrivate());
        }
        mKeys = mTmp;
        if ( getCATokenStatus()!=IHardCAToken.STATUS_ACTIVE )
            throw new Exception("Activation test failed");
    }

    /**
     * @param keyStore
     * @param alias
     * @return
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    protected PublicKey readPublicKey(KeyStore keyStore, String alias) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return keyStore.getCertificate(alias).getPublicKey();
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.IHardCAToken#init(java.util.Properties, java.lang.String)
     */
    public void init(Properties properties, String signaturealgorithm) {
        log.debug("Properties: "+(properties!=null ? properties.toString() : "null")+". Signaturealg: "+signaturealgorithm);
        keyStrings = new KeyStrings(properties);
        sSlotLabel = properties.getProperty(sSlotLabelKey);
        sSlotLabel = sSlotLabel!=null ? sSlotLabel.trim() : null;
        mAuthCode = properties.getProperty("pin");
        autoActivate();
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.IHardCAToken#activate(java.lang.String)
     */
    public abstract void activate(String authCode) throws CATokenOfflineException, CATokenAuthenticationFailedException;
    
    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.IHardCAToken#deactivate()
     */
    public boolean deactivate(){  
        log.info("De-activating");
        mKeys = null;
        return true;	
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.IHardCAToken#getPrivateKey(int)
     */
    public PrivateKey getPrivateKey(int purpose)
        throws CATokenOfflineException {
    	autoActivate();
        KeyPair keyPair = mKeys!=null ?
            (KeyPair)mKeys.get(keyStrings.getString(purpose)) :
            null;
        if ( keyPair==null )
            throw new CATokenOfflineException("no such key");
        return keyPair.getPrivate();
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.IHardCAToken#getPublicKey(int)
     */
    public PublicKey getPublicKey(int purpose)
        throws CATokenOfflineException {
    	autoActivate();
        KeyPair keyPair = mKeys!=null ?
            (KeyPair)mKeys.get(keyStrings.getString(purpose)) :
            null;
        if ( keyPair==null )
            throw new CATokenOfflineException();
        return keyPair.getPublic();
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.IHardCAToken#getProvider()
     */
    public String getProvider() {
        return sProviderName;
    }

	/* (non-Javadoc)
	 * @see org.ejbca.core.model.ca.caadmin.IHardCAToken#getCATokenStatus()
	 */
    public int getCATokenStatus() {
    	autoActivate();
        {
            String strings[] = keyStrings.getAllStrings();
            int i=0;
            while( strings!=null && i<strings.length && mKeys!=null && mKeys.get(strings[i])!=null )
                i++;            
            if ( strings==null || i<strings.length)
                return IHardCAToken.STATUS_OFFLINE;
        } {
            PrivateKey privateKey;
            PublicKey publicKey;
            try {
                privateKey = getPrivateKey(SecConst.CAKEYPURPOSE_KEYTEST);
                publicKey = getPublicKey(SecConst.CAKEYPURPOSE_KEYTEST);
            } catch (CATokenOfflineException e) {
                privateKey = null;
                publicKey = null;
                log.debug("no test key defined");
            }
            if ( privateKey!=null && publicKey!=null ) {
                //Check that that the testkey is usable by doing a test signature.
                try{
                    testKey(new KeyPair(publicKey, privateKey));
                } catch( Throwable th ){
                    log.error("Error testing activation", th);
                    return IHardCAToken.STATUS_OFFLINE;     
                }
            }
        }
        return IHardCAToken.STATUS_ACTIVE;
    }
}
