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

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.KeyStore.PasswordProtection;
import java.util.HashMap;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalResources;
import org.ejbca.util.keystore.KeyTools;
import org.ejbca.util.keystore.P11Slot;


/**
 * @author lars
 * @version $Id$
 */
public class PKCS11CAToken extends BaseCAToken implements P11Slot.P11SlotUser {

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(PKCS11CAToken.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /** Keys, specific to PKCS#11, that can be defined in CA token properties */
    static final public String SLOT_LABEL_KEY = "slot";
    static final public String SHLIB_LABEL_KEY = "sharedLibrary";
    static final public String ATTRIB_LABEL_KEY = "attributesFile";

    private P11Slot p11slot;

    /**
     * @param providerClass
     * @throws InstantiationException
     */
    public PKCS11CAToken() throws InstantiationException {
        super();
        try {
        	PKCS11CAToken.class.getClassLoader().loadClass(KeyTools.SUNPKCS11CLASS);
        } catch (Throwable t) {
            throw new InstantiationException("Pkcs11 provider class "+KeyTools.SUNPKCS11CLASS+" not found.");
        }
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.BaseCAToken#activate(java.lang.String)
     */
    @Override
    public void activate(String authCode) throws CATokenOfflineException, CATokenAuthenticationFailedException {
        if ( this.p11slot == null ) {
            throw new CATokenOfflineException("Slot not initialized.");
        }
        try {
            final Provider provider = this.p11slot.getProvider();
            char[] authCodeCharArray = (authCode!=null && authCode.length()>0) ? authCode.toCharArray():null;
            final PasswordProtection pwp =new PasswordProtection( authCodeCharArray );
            final KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11",
                                                                          provider,
                                                                          pwp);
            final KeyStore keyStore = builder.getKeyStore();
            log.debug("Loading key from slot '"+this.sSlotLabel+"' using pin.");
            // See ECA-1395 for an explanation of this special handling for the IAIK provider.
            // If the application uses several instances of the IAIKPkcs11 provider, it has two options to get an initialized key store. First, it can get the initialized key store directly from the provider instance. This looks like this
            // KeyStore tokenKeyStore = pkcs11Provider_.getTokenManager().getKeyStore();
            // where pkcs11Provider_ is the instance of the IAIKPkcs11 provider. Second, the application can instantiate the key store as usual and then initialize it. For initialization, the application must provide the name of the instance that this key store shall operate with. Just instantiating the key store is not enough, and if the application calls tokenKeyStore.load(null, null), it always(!) binds the key store to the first instance of the IAIKPkcs11 provider. This is the case, because there is no means for the KeyStoreSPI class to get the instance of the provider that was used to instantiate it. This means, it does not help to provide the provider name and calling KeyStore.getInstance("PKCS11KeyStore", providerName), the call to the load(InputStream, char[]) method with appropriate arguments is required nevertheless. The correct usage will look like this
            // KeyStore cardKeyStore = KeyStore.getInstance("PKCS11KeyStore");
            // String providerName = pkcs11Provider_.getName();
            // ByteArrayInputStream providerNameInpustStream = 
            // new ByteArrayInputStream(providerName.getBytes("UTF-8"));
            // cardKeyStore.load(providerNameInpustStream, null);
            // The password parameter of the load method (this is the second parameter, which is null here) will be used if provided (i.e. if it is not null). If it is null, the default login manager will use the configured method for prompting the PIN on demand. If the application just provides the instance number as a string instead of the complete provider name, the key store will also accept it.            
            if (provider.getClass().getName().equals("iaik.pkcs.pkcs11.provider.IAIKPkcs11") ) {
            	keyStore.load(new ByteArrayInputStream(getProvider().getBytes("UTF-8")), authCodeCharArray);
            } else {
            	// For the Sun provider this works fine to initialize the provider using previously provided protection parameters. 
            	keyStore.load(null, null);
            } 
            setJCAProvider(provider);
            setKeys(keyStore, null);
            pwp.destroy();
        } catch (CATokenOfflineException e) {
            throw e;
        } catch (Throwable t) {
            log.error("Failed to initialize PKCS11 provider slot '"+this.sSlotLabel+"'.", t);
            CATokenAuthenticationFailedException authfe = new CATokenAuthenticationFailedException("Failed to initialize PKCS11 provider slot '"+this.sSlotLabel+"'.");
            authfe.initCause(t);
            throw authfe;
        }
		String msg = intres.getLocalizedMessage("catoken.activated", "PKCS11");
        log.info(msg);
    }
    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.BaseCAToken#deactivate()
     */
    @Override
    public boolean deactivate() throws Exception {
        final boolean result = super.deactivate();
        this.p11slot.logoutFromSlotIfNoTokensActive();
        return result;
    }
    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.ICAToken#init(java.util.Properties, java.util.HashMap, java.lang.String, int)
     */
    public void init(Properties properties, HashMap data, String signaturealgorithm, int caid) throws Exception {
    	// Don't autoactivate this right away, we must dynamically create the auth-provider with a slot
        init("slot", properties, signaturealgorithm, false);
        final boolean isIndex;
        if (this.sSlotLabel == null) {
            this.sSlotLabel = properties.getProperty("slotListIndex");         
            this.sSlotLabel = this.sSlotLabel!=null ? this.sSlotLabel.trim() : "-1";
            isIndex = this.sSlotLabel!=null;
        } else {
            isIndex = false;
        }
        String sharedLibrary = properties.getProperty(PKCS11CAToken.SHLIB_LABEL_KEY);
        String attributesFile = properties.getProperty(PKCS11CAToken.ATTRIB_LABEL_KEY);
        // getInstance will run autoActivate()
        this.p11slot = P11Slot.getInstance(this.sSlotLabel, sharedLibrary, isIndex, attributesFile, this, caid);
    }
    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.BaseCAToken#reset()
     */
    @Override
    public void reset() {
    	if ( this.p11slot!=null ) {
    		this.p11slot.reset();
    	}
    }
}
