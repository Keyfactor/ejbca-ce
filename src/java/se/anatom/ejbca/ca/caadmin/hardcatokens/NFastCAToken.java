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

 package se.anatom.ejbca.ca.caadmin.hardcatokens;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;

import se.anatom.ejbca.ca.caadmin.IHardCAToken;
import se.anatom.ejbca.ca.exception.CATokenAuthenticationFailedException;
import se.anatom.ejbca.ca.exception.CATokenOfflineException;

/** This class implements support for the nCipher nFast HSM for storing CA keys.
 * This implementation was done by PrimeKey Solutions AB (www.primekey.se) in 2005 
 * and the development was sponsored by Linagora (www.linagora.com).
 * 
 * @author Lars Silvén
 * @version $Id: NFastCAToken.java,v 1.4 2005-11-11 08:53:49 anatom Exp $
 */
public class NFastCAToken implements IHardCAToken {

    /** Log4j instance for Base */
    private static transient final Logger log = Logger.getLogger(NFastCAToken.class);

    static final private String KEYSTORE_STRING = "keyStore";
    static final private String PROVIDER_NAME = "nCipherKM";
    static final private String PROVIDER_CLASS = "com.ncipher.provider.km.nCipherKM"; 

    public NFastCAToken() throws InstantiationException, IllegalAccessException {
        log.info("Creating NFastCAToken");
        try {
            Provider prov = (Provider)Class.forName(PROVIDER_CLASS).newInstance();        
            Security.addProvider( prov );            
        } catch (ClassNotFoundException e) {
            throw new InstantiationException("Class not found: "+PROVIDER_CLASS);
        }
    }

    private KeyStrings keyStrings;
    private String sKeyStore;
    private Map mKeys;

    public void init(Properties properties, String signaturealgorithm) {
        final Object params[] = {properties, signaturealgorithm };
        log.debug(params);
        keyStrings = new KeyStrings(properties);
        sKeyStore = properties.getProperty(KEYSTORE_STRING);
        sKeyStore = sKeyStore!=null ? sKeyStore.trim() : null;
    }

    public void activate(String authCode) throws CATokenOfflineException,
        CATokenAuthenticationFailedException {
        try {
            KeyStore keyStore = KeyStore.getInstance("nCipher.sworld"); 
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            OutputStreamWriter osw = new OutputStreamWriter(baos);
            osw.write(sKeyStore);
            osw.close();
            keyStore.load(new ByteArrayInputStream(baos.toByteArray()),
                          authCode.toCharArray()); 
            String keyAliases[] = keyStrings.getAllStrings();
            mKeys = new Hashtable();
            for ( int i=0; i<keyAliases.length; i++ ) {
                PrivateKey privateK =
                    (PrivateKey)keyStore.getKey(keyAliases[i],
                                                authCode.toCharArray());
                PublicKey publicK =
                    keyStore.getCertificate(keyAliases[i]).getPublicKey();
                KeyPair keyPair = new KeyPair(publicK, privateK);
                mKeys.put(keyAliases[i], keyPair);
            }
        } catch( Exception e ) {
            CATokenAuthenticationFailedException t =
                new CATokenAuthenticationFailedException();
            t.initCause(e);
            mKeys = null;
            throw t;
        }
    }

    public boolean deactivate(){  
        log.info("De-activating NFastCAToken");
        mKeys = null;
        return true;	
    }

    public PrivateKey getPrivateKey(int purpose)
        throws CATokenOfflineException {
        KeyPair keyPair = mKeys!=null ?
            (KeyPair)mKeys.get(keyStrings.getString(purpose)) :
            null;
        if ( keyPair==null )
            throw new CATokenOfflineException();
        return keyPair.getPrivate();
    }

    public PublicKey getPublicKey(int purpose)
        throws CATokenOfflineException {
        KeyPair keyPair = mKeys!=null ?
            (KeyPair)mKeys.get(keyStrings.getString(purpose)) :
            null;
        if ( keyPair==null )
            throw new CATokenOfflineException();
        return keyPair.getPublic();
    }

    public String getProvider() {
        return PROVIDER_NAME;
    }

	/* (non-Javadoc)
	 * @see se.anatom.ejbca.ca.caadmin.IHardCAToken#getCATokenStatus()
	 */
	public int getCATokenStatus() {
		String strings[] = keyStrings.getAllStrings();
		int i=0;
		while( strings!=null && i<strings.length && mKeys!=null && mKeys.get(strings[i])!=null )
			i++;
		if ( i<strings.length )
			return IHardCAToken.STATUS_OFFLINE;
        return IHardCAToken.STATUS_ACTIVE;
	}
}
