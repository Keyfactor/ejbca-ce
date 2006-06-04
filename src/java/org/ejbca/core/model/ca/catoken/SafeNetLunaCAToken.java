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

import org.apache.log4j.Logger;

/**
 * @author lars
 * @version $Id: SafeNetLunaCAToken.java,v 1.3 2006-06-04 13:02:43 primelars Exp $
 *
 */
public class SafeNetLunaCAToken extends BaseCAToken implements IHardCAToken {

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(SafeNetLunaCAToken.class);

    static final private String SLOT_LABEL_KEY = "slotLabel";
    static final private String PROVIDER_NAME = "LunaJCAProvider";
    static final private String PROVIDER_CLASS = "com.chrysalisits.crypto.LunaJCAProvider"; 

    public SafeNetLunaCAToken() throws InstantiationException, IllegalAccessException {
        super(PROVIDER_CLASS, PROVIDER_NAME, SLOT_LABEL_KEY);
    }

    public void activate(String authCode)
        throws CATokenOfflineException, CATokenAuthenticationFailedException {
        try {
            KeyStore keyStore = KeyStore.getInstance("Luna"); 
            keyStore.load(null, authCode.toCharArray());
            setKeys(keyStore, authCode);
        } catch( Exception e ) {
            log.error("Authentication failed: ", e);
            CATokenAuthenticationFailedException t = new CATokenAuthenticationFailedException(e.getMessage());
            t.initCause(e);
            deactivate();
            throw t;
        }
    }

}
