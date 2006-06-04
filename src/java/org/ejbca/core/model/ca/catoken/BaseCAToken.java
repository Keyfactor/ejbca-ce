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
 * @version $Id: BaseCAToken.java,v 1.3 2006-06-04 09:18:34 anatom Exp $
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

    protected void setKeys(KeyStore keyStore, String authCode) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
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
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.IHardCAToken#init(java.util.Properties, java.lang.String)
     */
    public void init(Properties properties, String signaturealgorithm) {
        if (log.isDebugEnabled()) {
            log.debug("Properties: "+properties != null ? properties.toString() : "null");
            log.debug("Signaturealg: "+signaturealgorithm);
        }
        keyStrings = new KeyStrings(properties);
        sSlotLabel = properties.getProperty(sSlotLabelKey);
        sSlotLabel = sSlotLabel!=null ? sSlotLabel.trim() : null;
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
        KeyPair keyPair = mKeys!=null ?
            (KeyPair)mKeys.get(keyStrings.getString(purpose)) :
            null;
        if ( keyPair==null )
            throw new CATokenOfflineException();
        return keyPair.getPrivate();
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.IHardCAToken#getPublicKey(int)
     */
    public PublicKey getPublicKey(int purpose)
        throws CATokenOfflineException {
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
        {
            String strings[] = keyStrings.getAllStrings();
            int i=0;
            while( strings!=null && i<strings.length && mKeys!=null && mKeys.get(strings[i])!=null )
                i++;            
            if ( strings==null || i<strings.length)
                return IHardCAToken.STATUS_OFFLINE;
        } {
            PrivateKey pk;
            try {
                pk = getPrivateKey(SecConst.CAKEYPURPOSE_KEYTEST);
            } catch (CATokenOfflineException e) {
                pk = null;
                log.debug("no test key defined");
            }
            if ( pk!=null ) {
                //Check that that the testkey is usable by doing a test signature.
                try{
                    Signature signature = Signature.getInstance("SHA1withRSA", getProvider());
                    signature.initSign( pk );
                    signature.update( "Test".getBytes() );
                    signature.sign();
                } catch( Throwable th ){
                    log.error("Error testing activation", th);
                    return IHardCAToken.STATUS_OFFLINE;     
                }
            }
        }
        return IHardCAToken.STATUS_ACTIVE;
    }
}
