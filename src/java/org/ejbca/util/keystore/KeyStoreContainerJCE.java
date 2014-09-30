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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;

/** A keystore container for Java keystores such as the nCipher JCE provider.
 * 
 * @version $Id$
 */
public class KeyStoreContainerJCE extends KeyStoreContainerBase {
   
    private char passPhraseGetSetEntry[] = null;
    private KeyStoreContainerJCE( final KeyStore _keyStore,
                                  final String _providerName,
                                  final String _ecryptProviderName,
                                  final byte storeID[]) throws Exception {
        super( _keyStore, _providerName, _ecryptProviderName );
       
        load(storeID);
    }

    /** Use KeyStoreContainer.getInstance to get an instance of this class
     * @see KeyStoreContainer#getInstance(String, String, String, String)
     */
    static KeyStoreContainer getInstance(final String keyStoreType,
                                         final String providerClassName,
                                         final String encryptProviderClassName,
                                         final byte storeID[]) throws Exception {
        return getIt( keyStoreType,
                      providerClassName,
                      encryptProviderClassName,
                      storeID );
    }
    static KeyStoreContainer getIt(final String keyStoreType,
                                   final String providerClassName,
                                   final String encryptProviderClassName,
                                   final byte storeID[]) throws Exception {
        final String providerName = getProviderName(providerClassName);
        final String ecryptProviderName; {
            String tmp;
            try {
                tmp = getProviderName(encryptProviderClassName);
            } catch( ClassNotFoundException e ) {
                tmp = providerName;
            }
            ecryptProviderName = tmp;
        }
        System.err.println("Creating KeyStore of type "+keyStoreType+" with provider "+providerName+(storeID!=null ? (" with ID "+new String(storeID)) : "")+'.');
        final KeyStore keyStore = KeyStore.getInstance(keyStoreType, providerName);
        return new KeyStoreContainerJCE( keyStore,
                                         providerName,
                                         ecryptProviderName,
                                         storeID);
    }
    private void setPassWord(boolean isKeystoreException) throws IOException {
        System.err.println((isKeystoreException ? "Setting key entry in keystore" : "Loading keystore")+". Give password of inserted card in slot:");
        final char result[] = System.console().readPassword();
        if ( isKeystoreException ) {
            this.passPhraseGetSetEntry = result;
        } else {
            setPassPhraseLoadSave(result);
        }
    }
    protected void load(byte storeID[]) throws Exception {
        try {
            loadHelper(storeID);
        } catch( IOException e ) {
            setPassWord(false);
            loadHelper(storeID);
        }
    }
    private void loadHelper(byte storeID[]) throws Exception, IOException {
        this.keyStore.load(storeID!=null ? new ByteArrayInputStream(storeID):null, getPassPhraseLoadSave());
    }
    private static String getProviderName( String className ) throws Exception {
        Provider provider = (Provider)Class.forName(className).getConstructor(new Class[0]).newInstance(new Object[0]);
        Security.addProvider(provider);
        return provider.getName();
    }
    /* (non-Javadoc)
     * @see org.ejbca.util.keystore.KeyStoreContainer#getPassPhraseGetSetEntry()
     */
    public char[] getPassPhraseGetSetEntry() {
        return this.passPhraseGetSetEntry;
    }
    /* (non-Javadoc)
     * @see org.ejbca.util.keystore.KeyStoreContainer#storeKeyStore()
     */
    public byte[] storeKeyStore() throws Exception {
        System.err.println("Next line will contain the identity identifying the keystore:");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        this.keyStore.store(baos, getPassPhraseLoadSave());
        System.out.print(new String(baos.toByteArray()));
        System.out.flush();
        System.err.println();
        return baos.toByteArray();
    }
    void setKeyEntry(String alias, Key key, Certificate chain[]) throws Exception {
        try {
            this.keyStore.setKeyEntry(alias, key, this.passPhraseGetSetEntry, chain);
        } catch (KeyStoreException e) {
            setPassWord(true);
            this.keyStore.setKeyEntry(alias, key, this.passPhraseGetSetEntry, chain);
        }
    }
    /* (non-Javadoc)
     * @see org.ejbca.util.keystore.KeyStoreContainer#getKey(java.lang.String)
     */
    public Key getKey(String alias) throws Exception {
        try {
            return this.keyStore.getKey(alias, this.passPhraseGetSetEntry);
        } catch (UnrecoverableKeyException e1) {
            setPassWord(true);
            return this.keyStore.getKey(alias, this.passPhraseGetSetEntry );
        }
    }

}
