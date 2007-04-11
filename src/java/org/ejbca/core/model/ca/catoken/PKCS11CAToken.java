/**
 * 
 */
package org.ejbca.core.model.ca.catoken;

import java.security.KeyStore;
import java.security.Security;
import java.security.KeyStore.PasswordProtection;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.ui.cli.KeyStoreContainer;

import sun.security.pkcs11.SunPKCS11;

/**
 * @author lars
 *
 */
public class PKCS11CAToken extends BaseCAToken {

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(EracomCAToken.class);

    /**
     * @param providerClass
     * @throws InstantiationException
     */
    public PKCS11CAToken() throws InstantiationException {
        super();
        try {
            SunPKCS11.class.getClass();
        } catch (Throwable t) {
            throw new InstantiationException("SUN pkcs11 wrapper class \"SunPKCS11\" not found.");
        }
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.BaseCAToken#activate(java.lang.String)
     */
    @Override
    public void activate(String authCode) throws CATokenOfflineException,
                                         CATokenAuthenticationFailedException {
        try {
            final PasswordProtection pwp =new PasswordProtection(authCode.toCharArray());
            final KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11",
                                                                          Security.getProvider(getProvider()),
                                                                          pwp);
            final KeyStore keyStore = builder.getKeyStore();
            log.debug("Loading key from slot"+sSlotLabel+" using pin.");
            keyStore.load(null, null);
            setKeys(keyStore, null);
            pwp.destroy();
        } catch (Throwable t) {
            log.error("Failed to initialize Eracom provider slot '"+sSlotLabel+"'.", t);
            throw new CATokenAuthenticationFailedException("Failed to initialize Eracom provider keystore '"+sSlotLabel+"'.");
        }
    }

    /* (non-Javadoc)
     * @see org.ejbca.core.model.ca.catoken.IHardCAToken#init(java.util.Properties, java.lang.String)
     */
    public void init(Properties properties, String signaturealgorithm) throws Exception {
        init("slot", properties, signaturealgorithm);
        setProvider( KeyStoreContainer.getP11AuthProvider(Integer.parseInt(sSlotLabel),
                                                          properties.getProperty("sharedLibrary")) );
    }
}
