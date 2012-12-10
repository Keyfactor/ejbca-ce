/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.dbprotection;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import javax.crypto.Mac;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.token.CryptoToken;

/**
 * Used as base class for JPA data beans that has a rowProtection column. The JPA class should extend this class and implement the simple methods:
 * 
 * <pre>
 * &#064;Transient
 * &#064;Override
 * String getProtectString(int version) {
 *	 return &quot;concatenation of fields to be integrity protected. Must be deterministic and can change with different version of rowprotection.&quot;;
 *	 // Example from CertificateProfileData
 *	 // StringBuilder build = new StringBuilder();
 *	 // What is important to protect here is the data that we define, id, name and certificate profile data
 *	 // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
 *	 // build.append(getId()).append(getCertificateProfileName()).append(getData());
 *	 // return build.toString();
 * }
 * 
 * &#064;Transient
 * &#064;Override
 * int getProtectVersion() {
 *	 return 1;
 * }
 * 
 * &#064;PrePersist
 * &#064;PreUpdate
 * &#064;Transient
 * &#064;Override
 * void protectData() {
 *	 super.protectData();
 * }
 * 
 * &#064;PostLoad
 * &#064;Transient
 * &#064;Override
 * void verifyData() {
 *	 super.verifyData();
 * }
 * 
 * &#064;Override
 * &#064;Transient
 * protected String getRowId() {
 *	 return String.valueOf(getPrimaryKey());
 * }
 * </pre>
 * 
 * The protection has the form: 1:1:123:fba85c2439055448ffbf22b57aa565a7b6279df2 Where the first field is the version of protected string, can be
 * updated with new fields etc, defined by the extending class The second field is the version of protection, can be different algorithms etc The
 * third field is the keyid used, so different rows can be protected with different keys (key rollover etc) The fourth field is the protection itself,
 * hmac, digital signature etc.
 * 
 * Based on CESeCore version:
 *	  ProtectedData.java 897 2011-06-20 11:17:25Z johane
 * 
 * @version $Id$
 */
public abstract class ProtectedData {

	private static final Logger log = Logger.getLogger(ProtectedData.class);

	/** Internal localization of logs and errors */
	private static final InternalResources INTRES = InternalResources.getInstance();

	/** Needed by JPA */
	public ProtectedData() {
	}

	/**
	 * asks the data class for the string to be protected. Version is -1 for a new row to be protected, and otherwise a version given earlier from the
	 * data class when storing the row.
	 * 
	 * @param version the version of the string that is protected, used as input when verifying data. -1 when getting protection string for data to be
	 *			inserted or updated. -1 means that the data class should use it's latest version of protect string
	 * @return String to be integrity protected, i.e. input to hmac.
	 */
	protected abstract String getProtectString(int rowversion);

	/**
	 * asks the data class for the version of the string that is protected, used as input to getProtectString() when verifying data. This is used so
	 * that the data class can alter itself with new fields, but still be backwards compatible and verify older database data. Called when getting the
	 * version for inserts or updates.
	 * 
	 * @return int version the latest version of protection string.
	 */
	protected abstract int getProtectVersion();

	/**
	 * The extending class must have a database column "rowProtection" that can be read and set.
	 */
	abstract public void setRowProtection(final String rowProtection);

	abstract public String getRowProtection();

	/**
	 * Returns id of the row in the database, in case of failure we can see in the log which row failed to verify
	 * 
	 * @return id of database row, specific for implementing class.
	 */
	protected abstract String getRowId();

	/** @return the database table name. Should be overridden by classes that does not share the same name as the database table it maps to (for example by subclassing). */
	protected String getTableName() {
		return this.getClass().getSimpleName();
	}

	protected void protectData() {
		if ( !ProtectedDataConfiguration.useDatabaseIntegrityProtection(getTableName()) ) {
			return;
		}
		final int rowversion = getProtectVersion();
		final String str = getProtectString(rowversion);
		// Always protect new and updated rows with default keyid
		final int keyid = ProtectedDataConfiguration.instance().getKeyId(getTableName()).intValue();
		// HMAC or digital signature
		final int protectVersion = ProtectedDataConfiguration.instance().getProtectVersion(keyid).intValue();
		final String protection = calculateProtection(protectVersion, keyid, str);
		final String pstring = rowversion + ":" + protectVersion + ":" + keyid + ":" + protection;
		if (log.isTraceEnabled()) {
			log.trace("Protected string (" + this.getClass().getName() + "): " + str);
			log.trace("Protecting row string with protection '" + protection + "': " + pstring);
		}
		setRowProtection(pstring);
	}

	protected void verifyData() {
		if ( !ProtectedDataConfiguration.useDatabaseIntegrityVerification(getTableName()) ) {
			return;
		}
		final String prot = getRowProtection();
		if ( prot==null ) {
			throwException("non null", "null", null);
			return;
		}
		final int verindex = prot.indexOf(":");
		final int rowversion = Integer.parseInt(prot.substring(0, verindex));
		final String str = getProtectString(rowversion);
		// calculate expected protection on this, here we need the keyid
		final int index1 = prot.indexOf(':', verindex + 1);
		// HMAC or digital signature
		final int protectVersion = Integer.parseInt(prot.substring(verindex + 1, index1));
		final int index2 = prot.indexOf(':', index1 + 1);
		final int keyid = Integer.parseInt(prot.substring(index1 + 1, index2));
		if (log.isTraceEnabled()) {
			log.trace("Verifying row string (" + this.getClass().getName() + "): " + str);
			log.trace("RowProtection: " + prot);
			log.trace("ProtectVersion: " + protectVersion);
			log.trace("KeyId: " + keyid);
		}
		verifyProtection(prot, str, protectVersion, keyid);
	}
	void throwException( String data, String realprot, Exception cause) throws DatabaseProtectionError {
		final String msg = INTRES.getLocalizedMessage("databaseprotection.errorverify", data, realprot, this.getClass().getName(),getRowId());
		log.error(msg);
		if ( !ProtectedDataConfiguration.errorOnVerifyFail() ) {
			return;
		}
		final DatabaseProtectionError dpe = new DatabaseProtectionError(msg, this);
		if ( cause!=null ) {
			dpe.initCause(cause);
		}
		throw dpe;
	}
	private void verifyProtection(final String prot, final String data, final int protectVersion, final int keyid) {
		// Strip away the first stuff
		final int index = prot.lastIndexOf(':');
		final String realprot = prot.substring(index + 1);
		final boolean result;
		try {
			switch( protectVersion ) {
			case 1:
				result = verifyHmac(realprot, data, keyid, protectVersion);
				break;
			case 2:
				result = verifySignature(realprot, data, keyid);
				break;
			default:
				result = false;
				break;
			}
		} catch (Exception e) { // DatabaseProtectionError will not be caught since it is a RuntimeException
			throwException( data, realprot, e );
			return;
		}
		if ( !result ) {
			throwException( data, realprot, null );
			return;
		}
		if ( log.isTraceEnabled() ) {
			log.trace("Verifying row string ok");
		}
	}

	private static boolean verifyHmac(final String macInHex, final String data, final int keyid, final int protectVersion) {
		// For HMAC (and possibly others) we need to calculate the protection and compare
		final String mustbeprot = calculateProtection(protectVersion, keyid, data);
		return mustbeprot.equals(macInHex);
	}

	private static boolean verifySignature(final String signatureInHex, final String data, final int keyid) throws Exception {
		// For signature protection we don't need to calculate the protection again, we only have to verify 
		// the signature, and for that we do not need the private key, only the public
		// Decrypt the signature (realprot) and extract the desired hash
		final CryptoToken token = ProtectedDataConfiguration.instance().getCryptoToken(keyid);
		final Signature signature = Signature.getInstance("SHA256WithRSA");
		final PublicKey pubKey = token.getPublicKey(ProtectedDataConfiguration.instance().getKeyLabel(keyid));
		signature.initVerify(pubKey);
		signature.update(data.getBytes("UTF-8"));
		return signature.verify(Hex.decode(signatureInHex));
	}

	private static String calculateProtection(final int protectVersion, final int keyid, final String toBesigned) {
		if (log.isTraceEnabled()) {
			log.trace("Using keyid " + keyid + " to calculate protection.");
		}
		try {
			final CryptoToken token = ProtectedDataConfiguration.instance().getCryptoToken(keyid);
			if ( token==null ) {
				final String msg = INTRES.getLocalizedMessage("databaseprotection.notokenwithid", Integer.valueOf(keyid));
				log.error(msg);
				if (ProtectedDataConfiguration.errorOnVerifyFail()) {
					throw new DatabaseProtectionError(msg);
				}
				return msg;
			}
			switch( protectVersion ) {
			case 1: {
				final Key key = token.getKey(ProtectedDataConfiguration.instance().getKeyLabel(keyid));
				final Mac mac = Mac.getInstance("HmacSHA256");
				mac.init(key);
				final byte[] bytes = mac.doFinal(toBesigned.getBytes("UTF-8"));
				return new String(Hex.encode(bytes));
			}
			case 2: {
				final PrivateKey key = token.getPrivateKey(ProtectedDataConfiguration.instance().getKeyLabel(keyid));
				final Signature signature = Signature.getInstance("SHA256WithRSA", token.getSignProviderName());
				signature.initSign(key);
				signature.update(toBesigned.getBytes("UTF-8"));
				final byte[] bytes = signature.sign();
				return new String(Hex.encode(bytes));
			}
			default: {
				throw new DatabaseProtectionError("Unknown protectVersion: " + protectVersion);
			}
			}
		} catch (Exception e) { // DatabaseProtectionError will not be caught since it is a RuntimeException
			log.error(e);
			throw new DatabaseProtectionError(e);
		}
	}
}
