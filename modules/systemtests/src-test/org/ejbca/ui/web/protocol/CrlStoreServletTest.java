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

package org.ejbca.ui.web.protocol;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.bouncycastle.util.Arrays;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.HashID;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.crl.PublishingCrlSessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Testing of CrlStoreServlet
 * 
 * @version $Id$
 * 
 */
public class CrlStoreServletTest extends CaTestCase {
	private final static Logger log = Logger.getLogger(CrlStoreServletTest.class);

	private final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
	private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
	private final ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
	private final CrlStoreSessionRemote crlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
	private final PublishingCrlSessionRemote publishingCrlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublishingCrlSessionRemote.class);

	private final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken("CrlStoreServletTest");

	@Override
	@Before
	public void setUp() throws Exception{
		super.setUp();
	}

	@Override
	@After
	public void tearDown() throws Exception {
		super.tearDown();
	}

	@Test
	public void testCRLStore() throws Exception {
		log.trace(">testCRLStore()");
		final X509Certificate cacert = (X509Certificate)getTestCACert();
		final String result = testCRLStore(cacert, CertificateConstants.NO_CRL_PARTITION);
		assertNull(result, result);
		log.trace("<testCRLStore()");
	}
	
	@Test
    public void testCRLStoreWithPartitions() throws Exception {
        log.trace(">testCRLStore()");
        // Given
        final X509CAInfo caInfo = (X509CAInfo) caSession.getCAInfo(admin, getTestCAId());
        caInfo.setUseCrlDistributionPointOnCrl(true);
        caInfo.setUsePartitionedCrl(true);
        caInfo.setDefaultCRLDistPoint("http://frontend.example.com/search.cgi?abc=xyz&partition=*");
        caInfo.setCrlPartitions(1);
        caInfo.setRetiredCrlPartitions(0);
        caAdminSession.editCA(admin, caInfo);
        assertTrue("CRL generation failed", publishingCrlSession.forceCRL(admin, getTestCAId()));
        assertTrue("Delta CRL generation failed", publishingCrlSession.forceDeltaCRL(admin, getTestCAId()));
        final X509Certificate cacert = (X509Certificate)getTestCACert();
        // When
        final String result = testCRLStore(cacert, 1);
        // Then
        assertNull(result, result);
        log.trace("<testCRLStore()");
    }

	@Override
    public String getRoleName() {
		return this.getClass().getSimpleName();
	}
	
	private String getBaseUrl(boolean local) {
	    final String port = configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP);
        final String remotePort = local ? "8080" : SystemTestsConfiguration.getRemotePortHttp(port);
        final String remoteHost = local ? "127.0.0.1" : SystemTestsConfiguration.getRemoteHost("localhost");
        final String contextRoot = "/ejbca/publicweb/crls";
        String url = "http://"+remoteHost+":" + remotePort + contextRoot + "/search.cgi";
        try {
            if (((HttpURLConnection)new URL(url).openConnection()).getResponseCode() != 200) {
                url = "http://localhost:8080/crls/search.cgi"; // Fallback, like if we run tests on a stand-alone VA
            }
        } catch (Exception e) {
            url = "http://localhost:8080/crls/search.cgi"; // Fallback, like if we run tests on a stand-alone VA
        }
        return url;
	}

    private String testCRLStore(final X509Certificate caCert, final int crlPartitionIndex) throws Exception {
        // Before running this we need to make sure the certificate cache is refreshed, there may be a cache delay which is acceptable in real life, 
        // but not when running JUnit tests  
        final String sURI = getBaseUrl(false) + "?reloadcache=true";
        log.debug("Reload cache URL: '"+sURI+"'.");
        final HttpURLConnection connection = (HttpURLConnection)new URI(sURI).toURL().openConnection();
        connection.connect();
        log.debug("reloadcache returned code: "+connection.getResponseCode());
        // Now on to the actual tests, with fresh caches
        final StringWriter sw = new StringWriter();
        final PrintWriter pw = new PrintWriter(sw);
        testCRLStore(pw, RFC4387URL.sKIDHash, crlPartitionIndex, false, caCert);
        testCRLStore(pw, RFC4387URL.iHash, crlPartitionIndex, false, caCert);
        testCRLStore(pw, RFC4387URL.sKIDHash, crlPartitionIndex, true, caCert);
        testCRLStore(pw, RFC4387URL.iHash, crlPartitionIndex, true, caCert);
        pw.flush();
        final String problems = sw.toString();
        if ( !problems.isEmpty() ) {
            return problems; // some tests has failed
        }
        return null; // everything OK
    }
    
    private void testCRLStore(final PrintWriter pw, final RFC4387URL urlType, final int crlPartitionIndex, final boolean isDelta, final X509Certificate caCert) throws Exception {
        final HashID id;
        final boolean aliasTest;
        switch( urlType ) {
        case sKIDHash:
            id = HashID.getFromKeyID(caCert);
            aliasTest = true;
            break;
        case iHash:
            id = HashID.getFromSubjectDN(caCert);
            aliasTest = false;
            break;
        default:
            throw new IllegalStateException("this should never happen");
        }
        final String caSubjectDN = caCert.getSubjectDN().getName();
        {
            final String sURI = urlType.appendQueryToURL(getBaseUrl(false), id, crlPartitionIndex, isDelta);
            testUri(pw, sURI, caSubjectDN, crlPartitionIndex, isDelta);
        }
        if ( !aliasTest ) {
            return;
        }
        // The code below needs to be commented out if you run the test against a remote host (i.e. different container/VM)
        final String alias = "alias";
        {
            final String sURI = getBaseUrl(true) + "?setAlias="+alias+"="+id.getB64url();
            final HttpURLConnection connection = (HttpURLConnection)new URI(sURI).toURL().openConnection();
            connection.connect();
            if ( connection.getResponseCode()!=HttpURLConnection.HTTP_OK ) {
                pw.println("Not possible to set alias");
                return;
            }
        }
        final String sURI = getBaseUrl(false) + "?alias="+alias+(isDelta ? "&delta=" : "");
        testUri(pw, sURI, caSubjectDN, crlPartitionIndex, isDelta);
    }
    
    private void testUri(final PrintWriter pw, final String sURI, final String caSubjectDN, final int crlPartitionIndex, final boolean isDelta) throws Exception {
        log.debug("Testing URL: '"+sURI+"'.");
        final HttpURLConnection connection = (HttpURLConnection)new URI(sURI).toURL().openConnection();
        connection.connect();
        final int responseCode = connection.getResponseCode();
        if ( HttpURLConnection.HTTP_OK!=responseCode ) {
            pw.println(" Fetching CRL with '"+sURI+"' is not working. responseCode="+responseCode);
            log.debug("Response code " + responseCode + " with message " + connection.getResponseMessage());
            return;
        }

        final byte fromBean[] = crlSession.getLastCRL(caSubjectDN, crlPartitionIndex, isDelta);
        final byte fromURL[] = new byte[connection.getContentLength()];
        connection.getInputStream().read(fromURL);
        if ( !Arrays.areEqual(fromBean, fromURL) ) {
            pw.println(" CRL from URL and bean are not equal for '"+sURI+"'.");
        }
    }
}
