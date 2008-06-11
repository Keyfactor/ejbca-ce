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
import java.security.ProviderException;
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
import org.ejbca.util.StringTools;


/**
 * @author lars
 * @version $Id$
 */
public abstract class BaseCAToken implements ICAToken {

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(BaseCAToken.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /** Used for signatures */
    private String mJcaProviderName = null;
    /** Used for encrypt/decrypt, can be same as for signatures for example for pkcs#11 */
    private String mJceProviderName = null;

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
            	log.debug("Trying to autoactivate CAToken");
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
                log.debug("Key with alias "+keyAliases[i]+" tested.");            	
            }
        }
        mKeys = mTmp;
        if ( getCATokenStatus()!=ICAToken.STATUS_ACTIVE )
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
            log.error("Can not read public key certificate with alias '"+alias+"' from keystore, got null. If the key of the certificate was generated after the latest application server start then restart the application server.");
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
    		log.debug("Properties: "+(properties!=null ? properties.toString() : "null")+". Signaturealg: "+signaturealgorithm);
    	}
        keyStrings = new KeyStrings(properties);
        if (sSlotLabelKey != null) {
            sSlotLabel = properties.getProperty(sSlotLabelKey);        	
        }
        sSlotLabel = sSlotLabel!=null ? sSlotLabel.trim() : null;
        mAuthCode = BaseCAToken.getAutoActivatePin(properties);
        if ( doAutoActivate ) {
            autoActivate();        	
        }
    }
    
    protected static String getAutoActivatePin(Properties properties) {
    	String ret = null;
    	String pin = properties.getProperty(ICAToken.AUTOACTIVATE_PIN_PROPERTY);
    	if (pin != null) {
    		try {
    			ret = StringTools.pbeDecryptStringWithSha256Aes192(pin);
    			log.debug("Using encrypted autoactivation pin");
    		} catch (Exception e) {
    			log.debug("Using cleartext autoactivation pin");
    		}
    	} else {
			log.debug("Not using autoactivation pin");    		
    	}
		if (ret == null) {
			ret = pin;
		}
    	return ret;
    }
    /** Sets auto activation pin in passed in properties. Also returns the string format of the 
     * autoactivation properties:
     * pin mypassword
     * 
     * @param properties a Properties bag where to set the auto activation pin, can be null if you only want to create the return string, does not set a null or empty password
     * @param pin the activation password
     * @param encrypt if the PIN should be encrypted with a simple built in encryption with only purpose of hiding the password from simple viewing. No strong security from this encryption 
     * @return A string that can be used to "setProperties" of a CAToken or null if pin is null or an empty string, this can safely be ignored if you don't know what to do with it
     */
    public static String setAutoActivatePin(Properties properties, String pin, boolean encrypt) {    	
		String ret = null;
    	if (StringUtils.isNotEmpty(pin)) {
    		String authcode = pin;
    		if (encrypt) {
    			try {
					authcode = StringTools.pbeEncryptStringWithSha256Aes192(pin);
				} catch (Exception e) {
					log.error("Failed to encrypt auto activation pin, using non-ecnrypted instead: ", e);
					authcode = pin;
				}
    		}
    		if (properties != null) {    		
    			properties.setProperty(ICAToken.AUTOACTIVATE_PIN_PROPERTY, authcode);
    		}
    		ret = ICAToken.AUTOACTIVATE_PIN_PROPERTY + " " + authcode;    		
    	}
    	return ret;
    }
    
    /** Sets both signature and encryption providers. If encryption provider is the same as signature provider this 
     * class name can be null.
     * @param jcaProviderClassName signature provider class name
     * @param jceProviderClassName encryption provider class name, can be null
     * @throws ClassNotFoundException 
     * @throws IllegalAccessException 
     * @throws InstantiationException
     * @see {@link #setJCAProvider(Provider)} 
     */
    protected void setProviders(String jcaProviderClassName, String jceProviderClassName) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
    	Provider jcaProvider = (Provider)Class.forName(jcaProviderClassName).newInstance();
        setProvider(jcaProvider);
        mJcaProviderName = jcaProvider.getName(); 
        if (jceProviderClassName != null) {
        	Provider jceProvider = (Provider)Class.forName(jceProviderClassName).newInstance();
            setProvider(jceProvider);        	
            mJceProviderName = jceProvider.getName(); 
        } else {
        	mJceProviderName = null;
        }
    }
    /** If we only have one provider to handle both JCA and JCE, and perhaps it is not so straightforward to 
     * create the provider (for example PKCS#11 provider), we can create the provider in sub class and set it 
     * here, instead of calling setProviders.
     * 
     * @param prov the fully constructed Provider
     * @see #setProviders(String, String)
     */
    protected void setJCAProvider(Provider prov) {
    	setProvider(prov);
    	mJcaProviderName = prov.getName();
    }
    /** If we don't use any of the methods to set a specific provider, but use some already existing provider
     * we should set the name of that provider at least.
     * @param pName the provider name as retriever from Provider.getName()
     */ 
    protected void setJCAProviderName(String pName) {
    	mJcaProviderName = pName;
    }
    private void setProvider(Provider prov) {
    	String pName = prov.getName();
        if (pName.startsWith("Luna")) {
        	// Luna Java provider does not contain support for RSA/ECB/PKCS1Padding but this is 
        	// the same as the alias below on small amounts of data  
            prov.put("Alg.Alias.Cipher.RSA/NONE/NoPadding","RSA//NoPadding");
            prov.put("Alg.Alias.Cipher.1.2.840.113549.1.1.1","RSA//NoPadding");
            prov.put("Alg.Alias.Cipher.RSA/ECB/PKCS1Padding","RSA//PKCS1v1_5");
            prov.put("Alg.Alias.Cipher.1.2.840.113549.3.7","DES3/CBC/PKCS5Padding");
        }
        if ( Security.getProvider(pName)==null )
            Security.addProvider( prov );
        if ( Security.getProvider(pName)==null )
            throw new ProviderException("Not possible to install provider: "+pName);
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.ICAToken#activate(java.lang.String)
     */
    public abstract void activate(String authCode) throws CATokenOfflineException, CATokenAuthenticationFailedException;
    
    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.ICAToken#deactivate()
     */
    public boolean deactivate(){  
		String msg = intres.getLocalizedMessage("catoken.deactivate");
        log.info(msg);
        mKeys = null;
        return true;	
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.ICAToken#getPrivateKey(int)
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
     * @see org.ejbca.core.model.ca.catoken.ICAToken#getPublicKey(int)
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
     * @see org.ejbca.core.model.ca.catoken.ICAToken#getKeyLabel(int)
     */
    public String getKeyLabel(int purpose) {
    	return keyStrings.getString(purpose);
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.ICAToken#getProvider()
     */
    public String getProvider() {
        return mJcaProviderName;
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.ICAToken#getJCEProvider()
     */
    public String getJCEProvider() {
    	// If we don't have a specific JCE provider, it is most likely the same
    	// as the JCA provider
    	if (mJceProviderName == null) {
    		return mJcaProviderName;
    	}
    	return mJceProviderName;
    }

	/* (non-Javadoc)
	 * @see org.ejbca.core.model.ca.caadmin.ICAToken#getCATokenStatus()
	 */
    public int getCATokenStatus() {    	
		if (log.isDebugEnabled()) {
			log.debug(">getCATokenStatus");
		}
    	autoActivate();
    	int ret = ICAToken.STATUS_OFFLINE;
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
            		if (log.isDebugEnabled()) {
            			log.debug("no test key defined");
            		}
            	}
            	if ( privateKey!=null && publicKey!=null ) {
            		//Check that that the testkey is usable by doing a test signature.
            		try{
            			testKey(new KeyPair(publicKey, privateKey));
            			// If we can test the testkey, we are finally active!
            	    	ret = ICAToken.STATUS_ACTIVE;
            		} catch( Throwable th ){
            			log.error("Error testing activation", th);
            		}
            	}
        	}
    	}
		if (log.isDebugEnabled()) {
			log.debug("<getCATokenStatus: "+ret);
		}
    	return ret;
    }
}
