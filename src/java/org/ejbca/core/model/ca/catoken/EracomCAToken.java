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

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.util.Properties;

import org.apache.log4j.Logger;

/** This class implements support for the Eracom HSM for storing CA keys. 
 * The implementation was done by AdNovum Informatik AG and contributed by Philipp Faerber, philipp.faerber(at)adnovum.ch
 * The Eracom HSM is special in such way as the provider is ERACOM.<slot id>.
 * 
 * @author AdNovum Informatik AG
 * @version $Id: EracomCAToken.java,v 1.3 2006-04-19 07:59:29 anatom Exp $
 */
public class EracomCAToken implements IHardCAToken {
    /** Log4j instance */
    private static final Logger log = Logger.getLogger(EracomCAToken.class);
    
    protected String m_keyLabel = null;
    protected String m_slotId;
    protected KeyStore m_keyStore = null;    
    protected boolean m_authenticated = false;    
    private   String m_authenticationCode = null;
    
    /** The constructor of HardCAToken should throw an InstantiationException is the token can not
     * be created, if for example depending jar files for the particular HSM is not available.
     * 
     * @throws InstantiationException if the Eracom provider is not available
     */
    public EracomCAToken() throws InstantiationException, IllegalAccessException {
        log.debug("Creating EracomCAToken");
        // Use slot0, it should always be available, and we need something to try to load in 
        // order to disable the token if Eracom classes are not available to the app server.
        String provider = "au.com.eracom.crypto.provider.slot0.ERACOMProvider";
        try {
            Provider prov = (Provider)Class.forName(provider).newInstance();        
            Security.addProvider( prov );            
        } catch (ClassNotFoundException e) {
            throw new InstantiationException("Class not found: "+provider);
        }
    }
    
    /**
     * This method should initalize this plug-in with the properties configured in the adminweb-GUI.
     * Expected properties are:
     * 
     *  slot=<number of slot containing the key material>
     *  
     *  keylabel=<the label to identify the key within the slot>
     *  
     *  [optional] pin=<the PIN for the slot if you want to enable auto-activation>
     *  
     */
    public void init(Properties properties, String signaturealgorithm) {
        log.debug("init()");

        m_slotId = properties.getProperty("slot");
        log.debug("slot: "+m_slotId);
        if (m_slotId == null) {
            log.error("No slot id (property 'slot') specified for Eracom HSM, will fail to initialize provider.");
        }

        m_keyLabel = properties.getProperty("keylabel");
        log.debug("keylabel: "+m_keyLabel);
        if (m_keyLabel == null) {
            log.error("No keylabel specified for key-pair on Eracom HSM slot "+m_slotId+", will not be able to create CA.");
//          we must not (?) throw exceptions in init function!
//            throw new IllegalArgumentException("No key-pair label property 'keylabel' specified.");
        }
        
        /* this allows to save the PIN in the database as property so we don't have to reenter
         * it on restart. Use this only if the DB is well protected ! */
        m_authenticationCode = properties.getProperty("pin");
        if (m_authenticationCode != null) {
            log.info("Authentication code has been specified via property.");
        }
        
    }
    
    
    /**
     * Should return a reference to the private key.
     */
    public PrivateKey getPrivateKey(int purpose) throws CATokenOfflineException {
        log.debug("getPrivateSignKey("+purpose+"), auth="+m_authenticated);
        
        if(!m_authenticated) {
            autoActivate();            
        }

        Exception e = null;
        PrivateKey privKey = null;
        try {
            privKey = (PrivateKey)m_keyStore.getKey(m_keyLabel, null);
            if (privKey == null) {
                log.error("Private Key with label '"+m_keyLabel+"' not found on Eracom slot "+m_slotId+".");
                throw new KeyStoreException("Private key with label '"+m_keyLabel+"' not found on Eracom slot "+m_slotId+".");
            }
        }
        catch (KeyStoreException kse) {
            e = kse;
        }
        catch (NoSuchAlgorithmException nsae) {
            e = nsae;
        }
        catch (UnrecoverableKeyException uke) {
            e = uke;
        }
        if (e != null) {
            log.error("Could not get private key labelled '"+m_keyLabel+"' from Eracom slot "+m_slotId+".", e);
            // this is silly, we have to wrap the exception into one which
            // the interface allows (would be better to leave it as is.
            throw new IllegalStateException(e.getMessage());
        }
        return privKey;
    }
    
    private void autoActivate() throws CATokenOfflineException {
        if(m_authenticationCode!=null) {
            try {
                activate(m_authenticationCode);
            }
            catch (CATokenAuthenticationFailedException e) {
                log.error("auto-activation of Eracom HSM failed: ", e);
                throw new CATokenOfflineException();
            }
        } else {
            throw new CATokenOfflineException();
        }
    }
    
    /**
     * Should return a reference to the public key.
     */
    public PublicKey getPublicKey(int purpose) throws CATokenOfflineException {
        log.debug("getPublicSignKey(), auth="+m_authenticated);
        if(!m_authenticated) {
            autoActivate();            
        }        
        Exception e = null;
        PublicKey pubKey = null;
        try {
            pubKey = (PublicKey)m_keyStore.getKey(m_keyLabel+"_pub", null);
            if (pubKey == null) {
                log.error("Public key with label '"+m_keyLabel+"_pub' not found on Eracom slot "+m_slotId+".");
                throw new KeyStoreException("Public key with label '"+m_keyLabel+"_pub' not found on Eracom slot "+m_slotId+".");
            }
        }
        catch (KeyStoreException kse) {
            e = kse;
        }
        catch (NoSuchAlgorithmException nsae) {
            e = nsae;
        }
        catch (UnrecoverableKeyException uke) {
            e = uke;
        }
        if (e != null) {
            log.error("Could not get public key labelled '"+m_keyLabel+"_pub' from Eracom slot "+m_slotId+".", e);
            // this is silly, we have to wrap the exception into one which
            // the interface allows (would be better to leave it as is.
            throw new IllegalStateException(e.getMessage());
        }
        return pubKey;
    }
    
    
    /** Should return the signature Provider that should be used to sign things with
     *  the PrivateKey object returned by this signingdevice implementation.
     * @return String the name of the Provider
     */
    public String getProvider() {
        log.debug("getProvider()");
        return "ERACOM."+m_slotId;
    }
    
    /**
     * We have to keep the authentication code ourself, as
     * the framework loses it. At the point this method gets called the
     * second time, there is no authentication code provided anymore
     * (see HardCATokenContainer:188).
     * 
     * This method ignores the 'authenticationcode' parameter.     
     * 
     * 
     * @see org.ejbca.core.model.ca.catoken.IHardCAToken#activate(java.lang.String)
     */
    public void activate(String authenticationcode) throws CATokenAuthenticationFailedException, CATokenOfflineException {
        log.debug("EracomCAToken.activate()");
        
        if (authenticationcode == null) {
            log.error("AuthenticationCode is null, skipping activation.");
        }
		else {
			try {
				/* initialize provider for the correct slot */
				Class cl = Class.forName("au.com.eracom.crypto.provider.slot"+m_slotId+".ERACOMProvider");
				Provider prov = (Provider)cl.newInstance();
				Security.addProvider(prov);
				m_keyStore = KeyStore.getInstance("CRYPTOKI", "ERACOM."+m_slotId);
                log.debug("Loading key from slot"+m_slotId+" using pin.");
				m_keyStore.load(null, authenticationcode.toCharArray());				
				m_authenticated = true;
			}
			catch (Exception e) {
				m_authenticated = false;
				log.error("Failed to initialize Eracom provider slot '"+m_slotId+"'.", e);
				throw new CATokenAuthenticationFailedException("Failed to initialize Eracom provider keystore '"+m_slotId+"'.");
			}
		}
    }
    
    /**
     * @see org.ejbca.core.model.ca.catoken.IHardCAToken#deactivate()
     */
    public boolean deactivate() {
        log.debug("EracomCAToken.deactivate");
        m_authenticated = false;
        
        m_keyStore = null;
        
        return true;
    }
    
	public int getCATokenStatus() {
        log.debug("Eracom "+m_slotId+" status="+(m_authenticated?"ACTIVE":"OFFLINE"));
        return  m_authenticated ? IHardCAToken.STATUS_ACTIVE : IHardCAToken.STATUS_OFFLINE;
	}
}
