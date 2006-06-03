/**
 * 
 */
package org.ejbca.core.model.ca.catoken;

import java.security.KeyStore;

import org.apache.log4j.Logger;

/**
 * @author lars
 *
 */
public class SafeNetLunaCAToken extends BaseCAToken implements IHardCAToken {

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(SafeNetLunaCAToken.class);

    static final private String SLOT_LABEL_KEY = "slotLabelKey";
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
