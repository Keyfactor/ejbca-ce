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

package org.ejbca.core.protocol.unid;

import java.sql.PreparedStatement;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.util.CeSecoreNameStyle;
import org.ejbca.core.protocol.ExtendedUserDataHandler;
import org.ejbca.util.JDBCUtil;
import org.ejbca.util.JDBCUtil.Preparer;
import org.ejbca.util.passgen.LettersAndDigitsPasswordGenerator;

/**
 * Adds items to the Unid-Fnr DB.
 * 
 * @version $Id$
 */
public class UnidFnrHandler implements ExtendedUserDataHandler {
	private static final Logger LOG = Logger.getLogger(UnidFnrHandler.class);
	private static final Pattern onlyDecimalDigits = Pattern.compile("^[0-9]+$");
	private Storage storage;

	/**
	 * Used by EJBCA
	 */
	public UnidFnrHandler() {
		super();
		this.storage = null;
	}
	/**
	 * Used by unit test.
	 * @param _storage
	 */
	public UnidFnrHandler(Storage _storage) {
		super();
		this.storage = _storage;
	}
	
	@Override
	public RequestMessage processRequestMessage(RequestMessage req, String certificateProfileName, String unidDataSource) throws HandlerException {
	    
	    if(this.storage == null) {
	        this.storage = new MyStorage(unidDataSource);
	    }
	    
		final X500Name dn = req.getRequestX500Name();
		if (LOG.isDebugEnabled()) {
			LOG.debug(">processRequestMessage:'"+dn+"' and '"+certificateProfileName+"'");
		}
		final String unidPrefix = getPrefixFromCertProfileName(certificateProfileName);
		if ( unidPrefix==null ) {
			return req;
		}
        final ASN1ObjectIdentifier[] oids = dn.getAttributeTypes();
		X500NameBuilder nameBuilder = new X500NameBuilder(new CeSecoreNameStyle());
		boolean changed = false;
		for ( int i=0; i<oids.length; i++ ) {
			if ( oids[i].equals(CeSecoreNameStyle.SERIALNUMBER) ) {
			    RDN[] rdns = dn.getRDNs(oids[i]);
			    String value = rdns[0].getFirst().getValue().toString();
				final String newSerial = storeUnidFrnAndGetNewSerialNr(value, unidPrefix);
				if ( newSerial!=null ) {
					nameBuilder.addRDN(oids[i], newSerial);
					changed = true;
				}
			} else {
			    nameBuilder.addRDN(dn.getRDNs(oids[i])[0].getFirst());
			}
		}
		if(changed) {
		    req = new RequestMessageSubjectDnAdapter( req, nameBuilder.build());
		}
		return req;
	}
	private static boolean hasOnlyDecimalDigits(String s, int first, int last) {
		return hasOnlyDecimalDigits( s.substring(first, last));
	}
	private static boolean hasOnlyDecimalDigits(String s) {
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
	/**
	 * @param inputSerialNr SN of subject DN in the incoming request
	 * @param unidPrefix Prefix of the unid
	 * @return the serial number of the subject DN of the certificate that will be created. Null if the format of the SN is not fnr-lra.
	 * Returning null means that the handler should not do anything (SN in DN not changed and nothing stored to DB).
	 * @throws HandlerException if unid-fnr can't be stored in DB. This will prevent any certificate to be created.
	 */
	private String storeUnidFrnAndGetNewSerialNr(String inputSerialNr, String unidPrefix) throws HandlerException {
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
		final String random = new LettersAndDigitsPasswordGenerator().getNewPassword(6, 6);
		final String unid = unidPrefix + lra + random;
		this.storage.storeIt(unid, fnr);
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
	/**
	 * Runtime implementation. Junit test will have another implementation.
	 *
	 */
	private static class MyStorage implements Storage {
		private final String dataSource;

		public MyStorage(String datasource) {
			super();
			this.dataSource = datasource;
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
			@Override
			public void prepare(PreparedStatement ps) {
				// do nothing
			}
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
			
			@Override
			public void prepare(PreparedStatement ps) throws Exception {
				ps.setString(1, this.unid);
				ps.setString(2, this.fnr);
			}
			
			@Override
			public String getInfoString() {
				return "Unid: '"+this.unid+" FNR: '"+this.fnr+"'";
			}
		}
		
		@Override
		public void storeIt(String unid, String fnr) throws HandlerException {
			try {
				JDBCUtil.execute(
						"INSERT INTO UnidFnrMapping (unid,fnr) VALUES (?,?)",
						new MyPreparer(unid,fnr), this.dataSource );
			} catch (Exception e) {
				final HandlerException e1 = new HandlerException("Failed to store unid fnr data: "+unid+", "+fnr+". Datasource='"+this.dataSource+"'.");
				e1.initCause(e);
				throw e1;
			}
		}
	}
}
