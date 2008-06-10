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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import org.ejbca.ui.cli.util.ConsolePasswordReader;
import org.ejbca.ui.cli.util.PasswordReader;

/** A keystore container for Java keystores such as the nCipher JCE provider.
 * 
 * @version $Id$
 */
public class KeyStoreContainerJCE extends KeyStoreContainer {
	private final PasswordReader passwordReader;
	private char passPhraseLoadSave[] = null;
	private char passPhraseGetSetEntry[] = null;
	private KeyStoreContainerJCE( final KeyStore _keyStore,
			final String _providerName,
			final String _ecryptProviderName,
			final byte storeID[],
			final PasswordReader _passwordReader) throws NoSuchAlgorithmException, CertificateException, IOException{
		super( _keyStore, _providerName, _ecryptProviderName );
		this.passwordReader = _passwordReader!=null ? _passwordReader : new ConsolePasswordReader();
		load(storeID);
	}

	/** Use KeyStoreContainer.getInstance to get an instance of this class
	 * @see KeyStoreContainer#getInstance(String, String, String, String)
	 */
	static KeyStoreContainer getInstance(final String keyStoreType,
			final String providerClassName,
			final String encryptProviderClassName,
			final byte storeID[]) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, NoSuchProviderException, IOException, IllegalArgumentException, SecurityException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException, ClassNotFoundException {
		return getIt( keyStoreType,
				providerClassName,
				encryptProviderClassName,
				storeID,
				null );
	}
	static KeyStoreContainer getIt(final String keyStoreType,
			final String providerClassName,
			final String encryptProviderClassName,
			final byte storeID[],
			final PasswordReader passwordReader) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, NoSuchProviderException, IOException, IllegalArgumentException, SecurityException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException, ClassNotFoundException {
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
				storeID,
				passwordReader);
	}
	private void setPassWord(boolean isKeystoreException) throws IOException {
		System.err.println((isKeystoreException ? "Setting key entry in keystore" : "Loading keystore")+". Give password of inserted card in slot:");
		final char result[] = passwordReader.readPassword();
		if ( isKeystoreException )
			this.passPhraseGetSetEntry = result;
		else
			this.passPhraseLoadSave = result;
	}
	protected void load(byte storeID[]) throws NoSuchAlgorithmException, CertificateException, IOException {
		try {
			loadHelper(storeID);
		} catch( IOException e ) {
			setPassWord(false);
			loadHelper(storeID);
		}
	}
	private void loadHelper(byte storeID[]) throws NoSuchAlgorithmException, CertificateException, IOException {
		this.keyStore.load(storeID!=null ? new ByteArrayInputStream(storeID):null, this.passPhraseLoadSave);
	}
	private static String getProviderName( String className ) throws IllegalArgumentException, SecurityException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException, ClassNotFoundException {
		Provider provider = (Provider)Class.forName(className).getConstructor(new Class[0]).newInstance(new Object[0]);
		Security.addProvider(provider);
		return provider.getName();
	}
	public char[] getPassPhraseGetSetEntry() {
		return passPhraseGetSetEntry;
	}
	public char[] getPassPhraseLoadSave() {
		return passPhraseLoadSave;
	}
	public byte[] storeKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		System.err.println("Next line will contain the identity identifying the keystore:");
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		this.keyStore.store(baos, this.passPhraseLoadSave);
		System.out.print(new String(baos.toByteArray()));
		System.out.flush();
		System.err.println();
		return baos.toByteArray();
	}
	void setKeyEntry(String alias, Key key, Certificate chain[]) throws IOException, KeyStoreException {
		try {
			this.keyStore.setKeyEntry(alias, key, this.passPhraseGetSetEntry, chain);
		} catch (KeyStoreException e) {
			setPassWord(true);
			this.keyStore.setKeyEntry(alias, key, this.passPhraseGetSetEntry, chain);
		}
	}
	public Key getKey(String alias) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, IOException {
		try {
			return this.keyStore.getKey(alias, this.passPhraseGetSetEntry);
		} catch (UnrecoverableKeyException e1) {
			setPassWord(true);
			return this.keyStore.getKey(alias, this.passPhraseGetSetEntry );
		}
	}

}
