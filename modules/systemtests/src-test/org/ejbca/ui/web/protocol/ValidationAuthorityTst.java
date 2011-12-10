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

package org.ejbca.ui.web.protocol;

import java.net.HttpURLConnection;
import java.net.URI;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.bouncycastle.util.Arrays;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.util.CertTools;
import org.ejbca.core.protocol.certificatestore.HashID;
import org.junit.Assert;

/**
 * This class is needed because a junit test class can not have a reference to an enum.
 * Classes having enum references will produce extra classes with '$1' appended to the class name.
 * The junit framework can't stand these extra classes if they have "Test" in the name.
 * 
 * @author Lars Silven PrimeKey
 * @version $Id$
 */
class ValidationAuthorityTst {
	private final static Logger log = Logger.getLogger(ValidationAuthorityTst.class);
	static String testCRLStore(X509Certificate caCert, CrlStoreSessionRemote crlSession, String port) throws Exception {
        // Before running this we need to make sure the certificate cache is refreshed, there may be a cache delay which is acceptable in real life, 
        // but not when running JUnit tests  
		final String sURI = "http://localhost:" + port + "/crls/search.cgi?reloadcache=true";
		log.debug("Reload cache URL: '"+sURI+"'.");
		final HttpURLConnection connection = (HttpURLConnection)new URI(sURI).toURL().openConnection();
		connection.connect();
		log.debug("reloadcache returned code: "+connection.getResponseCode());
		// Now on to the actual tests, with fresh caches
		String problems = new String();
		problems += testCRLStore( RFC4387URL.sKIDHash, false, caCert, crlSession, port);
		problems += testCRLStore( RFC4387URL.iHash, false, caCert, crlSession, port);
		problems += testCRLStore( RFC4387URL.sKIDHash, true, caCert, crlSession, port);
		problems += testCRLStore( RFC4387URL.iHash, true, caCert, crlSession, port);
		if ( !problems.isEmpty() ) {
			return problems; // some tests has failed
		}
		return null; // everything OK
	}
	private static String testCRLStore( RFC4387URL urlType, boolean isDelta, X509Certificate caCert, CrlStoreSessionRemote crlSession, String port) throws Exception {
		final HashID id;
		switch( urlType ) {
		case sKIDHash:
			id = HashID.getFromKeyID(caCert);
			break;
		case iHash:
			id = HashID.getFromSubjectDN(caCert);
			break;
		default:
			throw new Error("this should never happen");
		}
		final String sURI = urlType.appendQueryToURL("http://localhost:" + port + "/crls/search.cgi", id, isDelta);
		log.debug("URL: '"+sURI+"'.");
		final HttpURLConnection connection = (HttpURLConnection)new URI(sURI).toURL().openConnection();
		connection.connect();
		final int responseCode = connection.getResponseCode();
		if ( HttpURLConnection.HTTP_OK!=responseCode ) {
			if ( responseCode==HttpURLConnection.HTTP_NOT_FOUND ) {
				return "crlstore test not done because crlstore not enabled. To run the test set 'crlstore.enabled' in ./conf/crl.properties and then 'ant deploy' and restart appserver.";
			}
			return " Fetching CRL with '"+sURI+"' is not working. responseCode="+connection.getResponseCode();
		}
		// Check that the returned file type is correct
		final String filename = connection.getHeaderField("Content-disposition");		
		String shouldBe = "attachment; filename="+(isDelta?"delta":"")+"crl" + id.b64 + ".crl";
		// Due to url encoding we need to replace %2B with + in the returned filename
		shouldBe = shouldBe.replace("%2B", "+");
		Assert.assertEquals("File extension must be .crl", shouldBe, filename);
		final byte fromBean[] = crlSession.getLastCRL(CertTools.getSubjectDN(caCert), isDelta);
		final byte fromURL[] = new byte[connection.getContentLength()];
		connection.getInputStream().read(fromURL);
		if ( !Arrays.areEqual(fromBean, fromURL) ) {
			return " CRL from URL and bean are not equal for '"+sURI+"'.";
		}
		return "";
	}
}
