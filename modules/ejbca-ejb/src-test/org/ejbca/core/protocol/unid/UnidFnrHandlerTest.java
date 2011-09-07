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

package org.ejbca.core.protocol.unid;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Vector;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.ejbca.core.protocol.ExtendedUserDataHandler.HandlerException;
import org.ejbca.core.protocol.cmp.ICrmfRequestMessage;
import org.ejbca.core.protocol.unid.UnidFnrHandler.Storage;
import org.junit.Test;

/**
 * Testing of {@link UnidFnrHandler} .
 * @author primelars
 * @version $Id$
 */
public class UnidFnrHandlerTest {
	
    @Test
    public void test01() throws Exception {
    	final String unidPrefix = "1234-5678-";
    	final String fnr = "90123456789";
    	final String lra = "01234";
    	final MyStorage storage = new MyStorage(unidPrefix, fnr, lra);
    	final RequestMessage reqIn = new MyIRequestMessage(fnr+'-'+lra);
    	final UnidFnrHandler handler = new UnidFnrHandler(storage);
    	final RequestMessage reqOut = handler.processRequestMessage(reqIn, unidPrefix+"_a_profile_name");
    	assertEquals(storage.unid, reqOut.getRequestX509Name().getValues(X509Name.SN).firstElement());
    }
    
	private static class MyStorage implements Storage {
		final private String unidPrefix;
		final private String fnr;
		final private String lra;
		String unid;
		MyStorage( String _unidPrefix, String _fnr, String _lra) {
			this.unidPrefix = _unidPrefix;
			this.fnr = _fnr;
			this.lra = _lra;
		}
		@Override
		public void storeIt(String _unid, String _fnr) throws HandlerException {
			assertEquals(this.fnr, _fnr);
			assertEquals(this.unidPrefix, _unid.substring(0, 10));
			assertEquals(this.lra, _unid.substring(10, 15));
			this.unid = _unid;
		}
	}
	private static class MyIRequestMessage implements ICrmfRequestMessage {
		final X509Name dn;

		MyIRequestMessage(String serialNumber) {
			final Vector<DERObjectIdentifier> oids = new Vector<DERObjectIdentifier>();
			final Vector<String> values = new Vector<String>();
			oids.add(X509Name.SN);
			values.add(serialNumber);
			this.dn = new X509Name(oids, values);
		}
		@Override
		public String getUsername() {
			return null;
		}
		@Override
		public String getPassword() {
			return null;
		}
		@Override
		public String getIssuerDN() {
			return null;
		}
		@Override
		public BigInteger getSerialNo() {
			return null;
		}
		@Override
		public String getRequestDN() {
			return null;
		}
		@Override
		public X509Name getRequestX509Name() {
			return this.dn;
		}

		@Override
		public String getRequestAltNames() {
			return null;
		}
		@Override
		public Date getRequestValidityNotBefore() {
			return null;
		}
		@Override
		public Date getRequestValidityNotAfter() {
			return null;
		}
		@Override
		public X509Extensions getRequestExtensions() {
			return null;
		}
		@Override
		public String getCRLIssuerDN() {
			return null;
		}
		@Override
		public BigInteger getCRLSerialNo() {
			return null;
		}
		@Override
		public PublicKey getRequestPublicKey() throws InvalidKeyException,
				NoSuchAlgorithmException, NoSuchProviderException {
			return null;
		}
		@Override
		public boolean verify() throws InvalidKeyException,
				NoSuchAlgorithmException, NoSuchProviderException {
			return false;
		}
		@Override
		public boolean requireKeyInfo() {
			return false;
		}
		@Override
		public void setKeyInfo(Certificate cert, PrivateKey key, String provider) {
			// do nothing
		}
		@Override
		public int getErrorNo() {
			return 0;
		}
		@Override
		public String getErrorText() {
			return null;
		}
		@Override
		public String getSenderNonce() {
			return null;
		}
		@Override
		public String getTransactionId() {
			return null;
		}
		@Override
		public byte[] getRequestKeyInfo() {
			return null;
		}
		@Override
		public String getPreferredDigestAlg() {
			return null;
		}
		@Override
		public boolean includeCACert() {
			return false;
		}
		@Override
		public int getRequestType() {
			return 0;
		}
		@Override
		public int getRequestId() {
			return 0;
		}
		@Override
		public CertificateResponseMessage createResponseMessage(Class responseClass,
				RequestMessage req, Certificate cert, PrivateKey signPriv,
				String provider) {
			return null;
		}
		@Override
		public int getPbeIterationCount() {
			return 0;
		}
		@Override
		public String getPbeDigestAlg() {
			return null;
		}
		@Override
		public String getPbeMacAlg() {
			return null;
		}
		@Override
		public String getPbeKeyId() {
			return null;
		}
		@Override
		public String getPbeKey() {
			return null;
		}
	}
}
