/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.util.keystore;

import java.io.IOException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.KeyStore.CallbackHandlerProtection;

import javax.security.auth.callback.CallbackHandler;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.keys.token.CachingKeyStoreWrapper;
import org.cesecore.keys.token.p11.Pkcs11SlotLabel;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.keys.util.KeyStoreTools;

/**
 * @version $Id$
 */
public class KeyStoreToolsFactory {
    private static final Logger log = Logger.getLogger(KeyStoreToolsFactory.class);

    private static KeyStoreTools getInstance(final String slot, final Pkcs11SlotLabelType slotLabelType, final String libName,
            final String attributesFile, final KeyStore.ProtectionParameter protectionParameter, final String privateKeyLabel) throws Exception,
            IOException {
        final Provider provider = Pkcs11SlotLabel.getP11Provider(slot, slotLabelType, libName, attributesFile, privateKeyLabel);
        final String providerName = provider.getName();
        log.debug("Adding provider with name: " + providerName);
        if (Security.getProvider(providerName) == null) {
            Security.addProvider(provider);
        } else {
            log.debug("Provider already exists, not adding.");
        }

        return getInstance(providerName, protectionParameter);
    }
    private static KeyStoreTools getInstance(final String providerName,
                                         final KeyStore.ProtectionParameter protectionParameter) throws Exception, IOException {
        // Make a default password callback handler, if we don't specify one on the command line
        KeyStore.ProtectionParameter pp = protectionParameter;
        if (pp == null) {
            CallbackHandler cbh = null;
            try {
                // We will construct the PKCS11 text callback handler (sun.security...) using reflection, because 
                // the sun class does not exist on other JDKs than sun, and we want to be able to compile everything on i.e. IBM JDK.
                //   return new SunPKCS11(new ByteArrayInputStream(baos.toByteArray()));
                //final Class<?> implClass = Class.forName(SUNTEXTCBHANDLERCLASS);
                //cbh = (CallbackHandler)implClass.newInstance();
                
                // Nope: we have a better approach from EJBCA 3.9, we made our own callback handler
                cbh = new PasswordCallBackHandler();
            } catch (Exception e) {
                IOException ioe = new IOException("Error constructing pkcs11 password callback handler: "+e.getMessage());
                ioe.initCause(e);
                throw ioe;
            } 
            pp = new CallbackHandlerProtection(cbh);            
        }
        Provider provider = Security.getProvider(providerName);
        KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11", provider, pp);
        final KeyStore keyStore = builder.getKeyStore();
        return new KeyStoreTools(new CachingKeyStoreWrapper(keyStore, true), providerName);
    }

    /**
     * @param p11moduleFileName
     * @param storeID
     * @param slotLabelType the slot label type
     * @param attributesFile
     * @param pp
     * @param privateKeyLabel 
     * @return
     * @throws Exception
     */
    public static KeyStoreTools getInstance(
            final String p11moduleFileName,
            final String storeID, final Pkcs11SlotLabelType slotLabelType,
            final String attributesFile, final KeyStore.ProtectionParameter pp,
            final String privateKeyLabel) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        return getInstance(storeID, slotLabelType, p11moduleFileName, attributesFile, pp, privateKeyLabel);
    }
    /**
     * @param p11moduleFileName
     * @param storeID
     * @param slotLabelType
     * @param attributesFile
     * @param pp
     * @return
     * @throws Exception
     */
    public static KeyStoreTools getInstance(
            final String p11moduleFileName,
            final String storeID,
            final Pkcs11SlotLabelType slotLabelType,
            final String attributesFile,
            final KeyStore.ProtectionParameter pp) throws Exception {
        return getInstance(p11moduleFileName, storeID, slotLabelType, attributesFile, pp, null);
    }
}
