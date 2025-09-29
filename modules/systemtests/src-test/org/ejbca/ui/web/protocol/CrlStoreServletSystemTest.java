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
import static org.junit.Assert.fail;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.Arrays;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.HashID;
import org.cesecore.certificates.crl.CrlMetadataHolderDto;
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

import com.keyfactor.util.CertTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.certificate.SimpleCertGenerator;

/**
 * Testing of CrlStoreServlet.
 * 
 * @version $Id$
 * 
 */
public class CrlStoreServletSystemTest extends CaTestCase {
	private final static Logger log = Logger.getLogger(CrlStoreServletSystemTest.class);

	private final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
	private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
	private final ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
	private final CrlStoreSessionRemote crlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
	private final PublishingCrlSessionRemote publishingCrlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublishingCrlSessionRemote.class);

	private final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken("CrlStoreServletSystemTest");

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

	//@Test
	public void testCRLStore() throws Exception {
		log.trace(">testCRLStore()");
		final X509Certificate cacert = (X509Certificate)getTestCACert();
		final String result = testCRLStore(cacert, CertificateConstants.NO_CRL_PARTITION, true);
		assertNull(result, result);
		log.trace("<testCRLStore()");
	}
	
	//@Test
    public void testCRLStoreWithPartitions() throws Exception {
        log.trace(">testCRLStore()");
        // Given
        final X509CAInfo caInfo = (X509CAInfo) caSession.getCAInfo(admin, getTestCAId());
        caInfo.setUseCrlDistributionPointOnCrl(true);
        caInfo.setUsePartitionedCrl(true);
        caInfo.setDefaultCRLDistPoint("http://frontend.example.com/search.cgi?abc=xyz&partition=*");
        caInfo.setCrlPartitions(1);
        caInfo.setSuspendedCrlPartitions(0);
        caAdminSession.editCA(admin, caInfo);
        assertTrue("CRL generation failed", publishingCrlSession.forceCRL(admin, getTestCAId()));
        assertTrue("Delta CRL generation failed", publishingCrlSession.forceDeltaCRL(admin, getTestCAId()));
        final X509Certificate cacert = (X509Certificate)getTestCACert();
        // When
        final String result = testCRLStore(cacert, 1, true);
        // Then
        assertNull(result, result);
        log.trace("<testCRLStore()");
    }
	
	@Test
    public void testCRLStoreExternalRootCa() throws Exception {
	    
	    String caName = this.getClass().getName() + "testCRLStoreExternalRootCa";
	    String caSubjectDn = "CN=" + caName;
	    Date now = null;
	    byte[] der = null;
	    
	    try {
	        caSession.removeCA(admin, caSubjectDn.hashCode());
	    } catch (Exception e) {
	        
	    }
	    try {
    	    KeyPairGenerator  kpGen = KeyPairGenerator.getInstance("RSA", "BC");
    	    kpGen.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
    	    KeyPair keyPair =  kpGen.generateKeyPair();
    	    
            X509Certificate rootCaCertificate = SimpleCertGenerator.forTESTCaCert().setCa(true)
                                                                .setEntityPubKey(keyPair.getPublic())
                                                                .setIssuerPrivKey(keyPair.getPrivate())
                                                                .setIssuerDn(caSubjectDn)
                                                                .setSubjectDn(caSubjectDn)
                                                                .setValidityDays(3650)
                                                                .setSignatureAlgorithm("SHA256WithRSA")
                                                                .generateCertificate();
            
            X500Name issuer = new X500Name(caSubjectDn);
            now = new Date();
            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, now);
            crlBuilder.setNextUpdate(now);
            crlBuilder.addExtension(Extension.cRLNumber, false, new ASN1Integer(BigInteger.valueOf(1)));
    
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.getPrivate());
            X509CRLHolder crlHolder = crlBuilder.build(signer);
    
            JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider("BC");
            X509CRL crl = converter.getCRL(crlHolder);
    
            der = crl.getEncoded();
            caAdminSession.importCACertificate(admin, 
                    caName, Collections.singleton(EJBTools.wrap(rootCaCertificate)));
            
            String cafp = CertTools.getFingerprintAsString(rootCaCertificate);
            crlSession.storeCRL(admin, der, cafp, 1, caSubjectDn, 
                    0, now, now, -1);
            final String result = testCRLStore(rootCaCertificate, CertificateConstants.NO_CRL_PARTITION, false);
            assertNull(result, result);
	    } finally {
            Thread.sleep(1000);
            crlSession.delete(new CrlMetadataHolderDto(CertTools.getFingerprintAsString(der), caSubjectDn, 1, -1, now.getTime()), admin);
            caSession.removeCA(admin, caSubjectDn.hashCode());
        }
     
    }
	
	//@Test
    public void testCRLStoreExternalSubCaFullChain() throws Exception {
	    
	}
	
	//@Test
    public void testCRLStoreExternalSubCaOnlyCert() throws Exception {
        
    }

	@Override
    public String getRoleName() {
		return this.getClass().getSimpleName();
	}
	
	/** Sends a request with the given URL and returns the response code, or 0 on connection failure */
	private int getUrlResponse(final String url) {
	    try {
            return ((HttpURLConnection)new URL(url).openConnection()).getResponseCode();
        } catch (Exception e) {
            return 0;
        }
	}
	
	private String getBaseUrl(boolean local) {
	    final String port = configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP);
        final String remotePort = local ? "8080" : SystemTestsConfiguration.getRemotePortHttp(port);
        final String remoteHost = local ? "127.0.0.1" : SystemTestsConfiguration.getRemoteHost("localhost");
        final String contextRoot = WebConfiguration.DEFAULT_CRLSTORE_CONTEXTROOT;
        String url = "http://"+remoteHost+":" + remotePort + contextRoot + "/search.cgi";
        if (getUrlResponse(url) != 200) {
            url = "http://localhost:8080/crls/search.cgi"; // Fallback, like if we run tests on a stand-alone VA
        }
        final int response = getUrlResponse(url);
        if (response != 200) {
            fail("Test environment not correctly configured. Got HTTP error code " + response + " when contacting CRL store servlet on " + url);
        }
        return url;
	}

    private String testCRLStore(final X509Certificate caCert, final int crlPartitionIndex, final boolean testDeltaCrl) throws Exception {
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
        if (testDeltaCrl) {
            testCRLStore(pw, RFC4387URL.sKIDHash, crlPartitionIndex, true, caCert);
            testCRLStore(pw, RFC4387URL.iHash, crlPartitionIndex, true, caCert);
        }
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
        final String caSubjectDN = caCert.getSubjectX500Principal().getName();
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
        final String sURI = getBaseUrl(false) + "?alias="+alias+(isDelta ? "&delta=" : "") + "&partition=" + crlPartitionIndex;
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
