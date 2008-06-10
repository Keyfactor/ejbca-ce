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
package org.ejbca.util.keystore;

import java.io.IOException;
import java.security.AuthProvider;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.KeyStore.CallbackHandlerProtection;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

/** A keystore container for PCKS#11 keystores i.e. the java PKCS#11 wrapper
 * 
 * @version $Id$
 */
public class KeyStoreContainerP11 extends KeyStoreContainer {
    /** The name of Suns textcallbackhandler (for pkcs11) implementation */
    private static final String SUNTEXTCBHANDLERCLASS = "com.sun.security.auth.callback.TextCallbackHandler";

	private KeyStoreContainerP11( KeyStore _keyStore,
			String _providerName,
			String _ecryptProviderName) throws NoSuchAlgorithmException, CertificateException, IOException{
		super( _keyStore, _providerName, _ecryptProviderName );
		load();
	}
	protected void load() throws NoSuchAlgorithmException, CertificateException, IOException {
		this.keyStore.load(null, null);
	}
	
	/** Use KeyStoreContainer.getInstance to get an instance of this class
	 * @see KeyStoreContainer#getInstance(String, String, String, String)
	 */
	static KeyStoreContainer getInstance(final String slot,
			final String libName,
			final boolean isIx,
			final KeyStore.ProtectionParameter protectionParameter) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, LoginException {
		AuthProvider provider = KeyTools.getP11AuthProvider(slot, libName, isIx);
		final String providerName = provider.getName();
		Security.addProvider(provider);

		// Make a default password callback handler, if we don't specify one on the command line
		KeyStore.ProtectionParameter pp = protectionParameter;
		if (pp == null) {
			CallbackHandler cbh = null;
			try {
				// We will construct the PKCS11 text callback handler (sun.security...) using reflection, because 
				// the sun class does not exist on other JDKs than sun, and we want to be able to compile everything on i.e. IBM JDK.
				//   return new SunPKCS11(new ByteArrayInputStream(baos.toByteArray()));
				final Class implClass = Class.forName(SUNTEXTCBHANDLERCLASS);
				cbh = (CallbackHandler)implClass.newInstance();
			} catch (Exception e) {
				System.err.println("Error constructing pkcs11 text callback handler:");
				e.printStackTrace();
				IOException ioe = new IOException("Error constructing pkcs11 text callback handler: "+e.getMessage());
				ioe.initCause(e);
				throw ioe;
			} 
			// The above code replaces the single line:
			//final CallbackHandler cbh = new TextCallbackHandler();        	
			pp = new CallbackHandlerProtection(cbh);        	
		}
		KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11", provider, pp);
		final KeyStore keyStore = builder.getKeyStore();
		return new KeyStoreContainerP11( keyStore, providerName, providerName );
	}
	public byte[] storeKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		this.keyStore.store(null, null);
		return new byte[0];
	}
	void setKeyEntry(String alias, Key key, Certificate chain[]) throws IOException, KeyStoreException {
		this.keyStore.setKeyEntry(alias, key, null, chain);
	}
	public Key getKey(String alias) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, IOException {
		return this.keyStore.getKey(alias, null);
	}
	public char[] getPassPhraseGetSetEntry() {
		return null;
	}

}
