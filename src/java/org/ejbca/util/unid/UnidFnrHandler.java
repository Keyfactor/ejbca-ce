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

package org.ejbca.util.unid;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.sql.PreparedStatement;
import java.util.Date;
import java.util.Vector;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.protocol.ExtendedUserDataHandler;
import org.ejbca.core.protocol.IRequestMessage;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.util.CertTools;
import org.ejbca.util.JDBCUtil;
import org.ejbca.util.JDBCUtil.Preparer;
import org.ejbca.util.passgen.LettersAndDigitsPasswordGenerator;

/**
 * Adds items to the Unid-Fnr DB.
 * @author lars
 * @version $Id$
 */
public class UnidFnrHandler implements ExtendedUserDataHandler {
	private static final Logger LOG = Logger.getLogger(UnidFnrHandler.class);
	private static final Pattern onlyDecimalDigits = Pattern.compile("^[0-9]+$");
	private final Storage storage;

	/**
	 * Used by EJBCA
	 */
	public UnidFnrHandler() {
		super();
		this.storage = new MyStorage();
	}
	/**
	 * Used by unit test.
	 * @param _storage
	 */
	public UnidFnrHandler(Storage _storage) {
		super();
		this.storage = _storage;
	}
	private static class InputSerialNumber {
		final String fnr;
		final String lra;
		private InputSerialNumber(String _fnr, String _lra) {
			this.fnr = _fnr;
			this.lra = _lra;
		}
		static InputSerialNumber getIt(String inputSerialNr) {
			if ( inputSerialNr.length()!=17 ) {
				return null;
			}
			if ( inputSerialNr.charAt(11)!='-' ) {
				return null;
			}
			final String fnr = inputSerialNr.substring(0, 11);
			if ( !hasOnlyDecimalDigits(fnr) ) {
				return null;
			}
			final String lra = inputSerialNr.substring(12);
			if ( !hasOnlyDecimalDigits(lra) ) {
				return null;
			}
			return new InputSerialNumber(fnr, lra);
		}
	}
	private class RequestMessageAdapter implements IRequestMessage {
		final private IRequestMessage original;
		final private X509Name dn;
		RequestMessageAdapter(IRequestMessage req, X509Name _dn) {
			this.original = req;
			this.dn = _dn;
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#getUsername()
		 */
		@Override
		public String getUsername() {
			return this.original.getUsername();
		}

		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#getPassword()
		 */
		@Override
		public String getPassword() {
			return this.original.getPassword();
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#getIssuerDN()
		 */
		@Override
		public String getIssuerDN() {
			return this.original.getIssuerDN();
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#getSerialNo()
		 */
		@Override
		public BigInteger getSerialNo() {
			return this.original.getSerialNo();
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#getRequestDN()
		 */
		@Override
		public String getRequestDN() {
			final X509Name name = getRequestX509Name();
			if ( name==null ) {
				return null;
			}
			return CertTools.stringToBCDNString(name.toString());
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#getRequestX509Name()
		 */
		@Override
		public X509Name getRequestX509Name() {
			return this.dn;
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#getRequestAltNames()
		 */
		@Override
		public String getRequestAltNames() {
			return this.original.getRequestAltNames();
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#getRequestValidityNotBefore()
		 */
		@Override
		public Date getRequestValidityNotBefore() {
			return this.original.getRequestValidityNotBefore();
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#getRequestValidityNotAfter()
		 */
		@Override
		public Date getRequestValidityNotAfter() {
			return this.original.getRequestValidityNotAfter();
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#getRequestExtensions()
		 */
		@Override
		public X509Extensions getRequestExtensions() {
			return this.original.getRequestExtensions();
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#getCRLIssuerDN()
		 */
		@Override
		public String getCRLIssuerDN() {
			return this.original.getCRLIssuerDN();
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#getCRLSerialNo()
		 */
		@Override
		public BigInteger getCRLSerialNo() {
			return this.original.getCRLSerialNo();
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#getRequestPublicKey()
		 */
		@Override
		public PublicKey getRequestPublicKey() throws InvalidKeyException,
				NoSuchAlgorithmException, NoSuchProviderException {
			return this.original.getRequestPublicKey();
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#verify()
		 */
		@Override
		public boolean verify() throws InvalidKeyException,
				NoSuchAlgorithmException, NoSuchProviderException {
			return this.original.verify();
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#requireKeyInfo()
		 */
		@Override
		public boolean requireKeyInfo() {
			return this.original.requireKeyInfo();
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#setKeyInfo(java.security.cert.Certificate, java.security.PrivateKey, java.lang.String)
		 */
		@Override
		public void setKeyInfo(Certificate cert, PrivateKey key, String provider) {
			this.original.setKeyInfo(cert, key, provider);
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#getErrorNo()
		 */
		@Override
		public int getErrorNo() {
			return this.original.getErrorNo();
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#getErrorText()
		 */
		@Override
		public String getErrorText() {
			return this.original.getErrorText();
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#getSenderNonce()
		 */
		@Override
		public String getSenderNonce() {
			return this.original.getSenderNonce();
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#getTransactionId()
		 */
		@Override
		public String getTransactionId() {
			return this.original.getTransactionId();
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#getRequestKeyInfo()
		 */
		@Override
		public byte[] getRequestKeyInfo() {
			return this.original.getRequestKeyInfo();
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#getPreferredDigestAlg()
		 */
		@Override
		public String getPreferredDigestAlg() {
			return this.original.getPreferredDigestAlg();
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#includeCACert()
		 */
		@Override
		public boolean includeCACert() {
			return this.original.includeCACert();
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#getRequestType()
		 */
		@Override
		public int getRequestType() {
			return this.original.getRequestType();
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#getRequestId()
		 */
		@Override
		public int getRequestId() {
			return this.original.getRequestId();
		}
		/* (non-Javadoc)
		 * @see org.ejbca.core.protocol.IRequestMessage#createResponseMessage(java.lang.Class, org.ejbca.core.protocol.IRequestMessage, java.security.cert.Certificate, java.security.PrivateKey, java.lang.String)
		 */
		@Override
		public IResponseMessage createResponseMessage(Class responseClass,
				IRequestMessage req, Certificate cert, PrivateKey signPriv,
				String provider) {
			return this.original.createResponseMessage(responseClass, req, cert, signPriv, provider);
		}		
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.ExtendedUserDataHandler#handleIt(org.bouncycastle.asn1.x509.X509Name, java.lang.String)
	 */
	@Override
	public IRequestMessage handleIt(IRequestMessage req, String certificateProfileName) throws HandlerException {
		final X509Name dn = req.getRequestX509Name();
		LOG.debug("take care of :'"+dn+"' and '"+certificateProfileName+"'");
		final String unidPrefix = getPrefixFromCertProfileName(certificateProfileName);
		if ( unidPrefix==null ) {
			return req;
		}
		final Vector<String> v = dn.getValues();
		final Vector<Object> o = dn.getOIDs();
		if( v.size()!=o.size() ) {
			throw new Error("the BC X509Name object is corrupt.");
		}
		for ( int i=0; i<v.size(); i++ ) {
			if ( o.get(i).equals(X509Name.SERIALNUMBER) ) {
				final String newSerial = storeUnidFrnAndGetNewSerialNr(v.get(i), unidPrefix);
				if ( newSerial!=null ) {
					v.set(i, newSerial);
					return new RequestMessageAdapter( req, new X509Name(o,v) );
				}
			}
		}
		return req;
	}
	private static boolean hasOnlyDecimalDigits(String s, int first, int last) {
		return hasOnlyDecimalDigits( s.substring(first, last));
	}
	static boolean hasOnlyDecimalDigits(String s) {
		return onlyDecimalDigits.matcher(s).matches();
	}
	private String getPrefixFromCertProfileName(String certificateProfileName) {
		if ( certificateProfileName.length()<10 ) {
			return null;
		}
		if ( certificateProfileName.charAt(4)!='-' ) {
			return null;
		}
		if ( certificateProfileName.charAt(9)!='-' ) {
			return null;
		}
		if ( !hasOnlyDecimalDigits(certificateProfileName, 0, 4) ) {
			return null;
		}
		if ( !hasOnlyDecimalDigits(certificateProfileName, 5, 9) ) {
			return null;
		}
		return certificateProfileName.substring(0, 10);
	}
	private String storeUnidFrnAndGetNewSerialNr(String inputSerialNr, String unidPrefix) throws HandlerException {
		final InputSerialNumber isn = InputSerialNumber.getIt(inputSerialNr);
		if ( isn==null ) {
			return null;
		}
		final String random = new LettersAndDigitsPasswordGenerator().getNewPassword(6, 6);
		final String unid = unidPrefix + isn.lra + random;
		this.storage.storeIt(unid, isn.fnr);
		return unid;
	}
	/**
	 * To be implemented by unit test.
	 */
	public interface Storage {
		/**
		 * @param unid
		 * @param fnr
		 * @throws HandlerException
		 */
		void storeIt(String unid, String fnr) throws HandlerException;
	}
	private static class MyStorage implements Storage {
		private final String dataSource;

		public MyStorage() {
			super();
			this.dataSource = CmpConfiguration.getUNID_DS();
			try {
				JDBCUtil.execute(
						"CREATE TABLE UnidFnrMapping( unid varchar(250) NOT NULL DEFAULT '', fnr varchar(250) NOT NULL DEFAULT '', PRIMARY KEY (unid) )",
						new DoNothingPreparer(), this.dataSource );
			} catch (Exception e) {
				// table probably already created.
			}
		}
		private class DoNothingPreparer implements Preparer {
			public DoNothingPreparer() {
				// do nothing
			}
			/* (non-Javadoc)
			 * @see org.ejbca.util.JDBCUtil.Preparer#prepare(java.sql.PreparedStatement)
			 */
			@Override
			public void prepare(PreparedStatement ps) {
				// do nothing
			}
			/* (non-Javadoc)
			 * @see org.ejbca.util.JDBCUtil.Preparer#getInfoString()
			 */
			@Override
			public String getInfoString() {
				return null;
			}
		}
		private class MyPreparer implements Preparer {
			final private String unid;
			final private String fnr;

			MyPreparer(String _unid, String _fnr) {
				this.unid = _unid;
				this.fnr = _fnr;
			}
			/* (non-Javadoc)
			 * @see org.ejbca.util.JDBCUtil.Preparer#prepare(java.sql.PreparedStatement)
			 */
			@Override
			public void prepare(PreparedStatement ps) throws Exception {
				ps.setString(1, this.unid);
				ps.setString(2, this.fnr);
			}
			/* (non-Javadoc)
			 * @see org.ejbca.util.JDBCUtil.Preparer#getInfoString()
			 */
			@Override
			public String getInfoString() {
				return "Unid: '"+this.unid+" FNR: '"+this.fnr+"'";
			}
		}
		/* (non-Javadoc)
		 * @see org.ejbca.util.unid.UnidFnrHandler.Storage#storeIt(java.lang.String, java.lang.String)
		 */
		@Override
		public void storeIt(String unid, String fnr) throws HandlerException {
			try {
				JDBCUtil.execute(
						"INSERT INTO UnidFnrMapping (unid,fnr) VALUES (?,?)",
						new MyPreparer(unid,fnr), this.dataSource );
			} catch (Exception e) {
				final HandlerException e1 = new HandlerException("Failed to store unid fnr data.");
				e1.initCause(e);
				throw e1;
			}
		}
	}
}
