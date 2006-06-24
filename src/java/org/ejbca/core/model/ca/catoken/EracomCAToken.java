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
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;

import org.apache.log4j.Logger;

/** This class implements support for the Eracom HSM for storing CA keys. 
 * The implementation was done by AdNovum Informatik AG and contributed by Philipp Faerber, philipp.faerber(at)adnovum.ch
 * The Eracom HSM is special in such way as the provider is ERACOM.<slot id>.
 * 
 * @author AdNovum Informatik AG
 * @version $Id: EracomCAToken.java,v 1.4 2006-06-24 21:38:56 primelars Exp $
 */
public class EracomCAToken extends BaseCAToken implements IHardCAToken {

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(EracomCAToken.class);

    static final private String SLOT_LABEL_KEY = "slot";
    static final private String PROVIDER_CLASS = "au.com.eracom.crypto.provider.slot0.ERACOMProvider"; 

    /**
     * @throws InstantiationException
     * @throws IllegalAccessException
     */
    public EracomCAToken() throws InstantiationException, IllegalAccessException {
        super(PROVIDER_CLASS, null, SLOT_LABEL_KEY);
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.BaseCAToken#activate(java.lang.String)
     */
    public void activate(String authCode) throws CATokenOfflineException,
                                         CATokenAuthenticationFailedException {
        try {
            if ( Security.getProvider(getProvider())==null ) {
                /* initialize provider for the correct slot */
                Class cl = Class.forName("au.com.eracom.crypto.provider.slot"+sSlotLabel+".ERACOMProvider");
                Provider prov = (Provider)cl.newInstance();
                Security.addProvider(prov);
            }
            if ( Security.getProvider(getProvider())==null )
                throw new CATokenOfflineException("not possible to install eracaom provider");
            KeyStore keyStore = KeyStore.getInstance("CRYPTOKI", "ERACOM."+sSlotLabel);
            log.debug("Loading key from slot"+sSlotLabel+" using pin.");
            keyStore.load(null, authCode.toCharArray());
            setKeys(keyStore, authCode);
        }
        catch (Throwable t) {
            log.error("Failed to initialize Eracom provider slot '"+sSlotLabel+"'.", t);
            throw new CATokenAuthenticationFailedException("Failed to initialize Eracom provider keystore '"+sSlotLabel+"'.");
        }

    }
    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.BaseCAToken#readPublicKey(java.security.KeyStore, java.lang.String)
     */
    protected PublicKey readPublicKey(KeyStore keyStore, String alias) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return (PublicKey)keyStore.getKey(alias+"_pub", null);
    }
    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.IHardCAToken#getProvider()
     */
    public String getProvider() {
        log.debug("getProvider()");
        return "ERACOM."+sSlotLabel;
    }

}
