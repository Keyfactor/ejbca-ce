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
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;


/**
 * @author lars
 * @version $Id: BaseCAToken.java,v 1.19 2007-07-25 15:13:01 anatom Exp $
 */
public abstract class BaseCAToken implements IHardCAToken {

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(BaseCAToken.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    private String sProviderName;

    private KeyStrings keyStrings;
    protected String sSlotLabel = null;
    private Map mKeys;
	private String mAuthCode;

    public BaseCAToken() throws InstantiationException {
        super();
    }
    public BaseCAToken(String providerClass) throws InstantiationException {
        try {
            Class.forName(providerClass);
        } catch (ClassNotFoundException e) {
            throw new InstantiationException("Class not found: "+providerClass);
        }
    }
    protected void autoActivate() {
        if ( mKeys==null && mAuthCode!=null )
            try {
                activate(mAuthCode);
            } catch (Exception e) {
                log.debug(e);
            }
    }
    private void testKey( KeyPair pair ) throws Exception {
        final byte input[] = "Lillan gick p� v�gen ut, m�tte d�r en katt ...".getBytes();
        final byte signBV[];
        String keyalg = pair.getPublic().getAlgorithm();
        if (log.isDebugEnabled()) {
            log.debug("Testing keys with algorithm: "+keyalg);        	
        }
        String testSigAlg = "SHA1withRSA";
        if (StringUtils.equals(keyalg, "EC")) {
        	testSigAlg = "SHA1withECDSA";
        }
        {
            Signature signature = Signature.getInstance(testSigAlg, getProvider());
            signature.initSign( pair.getPrivate() );
            signature.update( input );
            signBV = signature.sign();
        }{
            Signature signature = Signature.getInstance(testSigAlg, "BC");
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
        final Map<String, KeyPair> mTmp = new Hashtable<String, KeyPair>();
        for ( int i=0; i<keyAliases.length; i++ ) {
            PrivateKey privateK =
                (PrivateKey)keyStore.getKey(keyAliases[i],
                                            (authCode!=null && authCode.length()>0)? authCode.toCharArray():null);
            PublicKey publicK = readPublicKey(keyStore, keyAliases[i]);
            KeyPair keyPair = new KeyPair(publicK, privateK);
            mTmp.put(keyAliases[i], keyPair);
        }
        for ( int i=0; i<keyAliases.length; i++ ) {
            KeyPair pair = mTmp.get(keyAliases[i]);
            testKey(pair);
            if (log.isDebugEnabled()) {
                log.debug("Key with alias "+keyAliases[i]+" tested. toString for private part: "+pair.getPrivate());            	
            }
        }
        mKeys = mTmp;
        if ( getCATokenStatus()!=IHardCAToken.STATUS_ACTIVE )
            throw new Exception("Activation test failed");
    }

    /**
     * @param keyStore
     * @param alias
     * @return Public key
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    protected PublicKey readPublicKey(KeyStore keyStore, String alias) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
    	Certificate cert = keyStore.getCertificate(alias);
    	PublicKey pubk = null;
    	if (cert != null) {
    		pubk = cert.getPublicKey();
    	} else {
    		log.error("Can not read public key certificate  with alias '"+alias+"' from keystore, got null.");
    		if (log.isDebugEnabled()) {
    			Enumeration en = keyStore.aliases();
    			while (en.hasMoreElements()) {
    				log.debug("Existing alias: "+(String)en.nextElement());
    			}
    		}
    	}
    	return pubk;
    }

    protected void init(String sSlotLabelKey, Properties properties, String signaturealgorithm, boolean doAutoActivate) {
    	if (log.isDebugEnabled()) {
    		// We must make sure that we don't put out activation passwords in the log file
    		String pin = properties.getProperty(IHardCAToken.AUTOACTIVATE_PIN_PROPERTY);
    		if (pin != null) {
    			properties.setProperty(IHardCAToken.AUTOACTIVATE_PIN_PROPERTY, "xxxxxx");
    		}
            log.debug("Properties: "+(properties!=null ? properties.toString() : "null")+". Signaturealg: "+signaturealgorithm);
    		if (pin != null) {
    			properties.setProperty(IHardCAToken.AUTOACTIVATE_PIN_PROPERTY, pin);
    		}
    	}
        keyStrings = new KeyStrings(properties);
        if (sSlotLabelKey != null) {
            sSlotLabel = properties.getProperty(sSlotLabelKey);        	
        }
        sSlotLabel = sSlotLabel!=null ? sSlotLabel.trim() : null;
        mAuthCode = properties.getProperty(AUTOACTIVATE_PIN_PROPERTY);
        if ( doAutoActivate )
            autoActivate();
    }
    
    protected void setProvider( String providerClassName ) throws Exception {
        setProvider( (Provider)Class.forName(providerClassName).newInstance() );
    }
    protected void setProvider( Provider prov ) throws Exception {
        sProviderName = prov.getName();
        if ( Security.getProvider(getProvider())==null )
            Security.addProvider( prov );
        if ( Security.getProvider(getProvider())==null )
            throw new Exception("not possible to install provider");
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.IHardCAToken#activate(java.lang.String)
     */
    public abstract void activate(String authCode) throws CATokenOfflineException, CATokenAuthenticationFailedException;
    
    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.IHardCAToken#deactivate()
     */
    public boolean deactivate(){  
		String msg = intres.getLocalizedMessage("catoken.deactivate");
        log.info(msg);
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
    	log.debug(">getCATokenStatus");
    	autoActivate();
    	int ret = IHardCAToken.STATUS_OFFLINE;
    	// If we have no keystrings, no point in continuing...
    	if (keyStrings != null) {
        	String strings[] = keyStrings.getAllStrings();
        	int i=0;
        	while( strings!=null && i<strings.length && mKeys!=null && mKeys.get(strings[i])!=null ) {
        		i++;                    		
        	}
        	// If we don't have any keys for the strings, or we don't have enough keys for the strings, no point in continuing...
        	if ( strings!=null && i>=strings.length) {
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
            			// If we can test the testkey, we are finally active!
            	    	ret = IHardCAToken.STATUS_ACTIVE;
            		} catch( Throwable th ){
            			log.error("Error testing activation", th);
            		}
            	}
        	}
    	}
    	log.debug("<getCATokenStatus: "+ret);
    	return ret;
    }
}
