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
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.util.Properties;

import org.apache.log4j.Logger;

/** This class implements support for the Eracom HSM for storing CA keys. 
 * The implementation was done by AdNovum Informatik AG and contributed by Philipp Faerber, philipp.faerber(at)adnovum.ch
 * The Eracom HSM is special in such way as the provider is ERACOM.<slot id>.
 * 
 * @author AdNovum Informatik AG
 * @version $Id: EracomCAToken.java,v 1.5 2007-04-07 21:13:39 primelars Exp $
 */
public class EracomCAToken extends BaseCAToken implements IHardCAToken {

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(EracomCAToken.class);
    private static final String PROVIDER_NAME_PREFIX = "au.com.eracom.crypto.provider.slot";
    private static final String PROVIDER_NAME_SUFIX = ".ERACOMProvider";

    /** The constructor of HardCAToken should throw an InstantiationException if the token can not
     * be created, if for example depending jar files for the particular HSM is not available.
     * @throws InstantiationException
     */
    public EracomCAToken() throws InstantiationException {
        super(PROVIDER_NAME_PREFIX+"0"+PROVIDER_NAME_SUFIX);
        log.debug("Creating EracomCAToken");
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.BaseCAToken#activate(java.lang.String)
     */
    public void activate(String authCode) throws CATokenOfflineException,
                                         CATokenAuthenticationFailedException {
        try {
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
     * @see org.ejbca.core.model.ca.catoken.IHardCAToken#init(java.util.Properties, java.lang.String)
     */
    public void init(Properties properties, String signaturealgorithm) throws Exception {
        init("slot", properties, signaturealgorithm);
        setProvider(PROVIDER_NAME_PREFIX+sSlotLabel+PROVIDER_NAME_SUFIX);
    }

}
