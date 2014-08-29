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

package org.ejbca.ui.web.pub.cluster;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.commons.fileupload.util.Streams;
import org.apache.log4j.Logger;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorSessionRemote;
import org.cesecore.certificates.ocsp.OcspTestUtils;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @version $Id$
 */
public class WebEjbcaHealthCheckTest extends WebHealthTestAbstract {

    private static final Logger log = Logger.getLogger(WebEjbcaHealthCheckTest.class);

    private static final String CA_DN = "CN=WebEjbcaHealthCheckTestCA";
    private static final String SIGNER_DN = "CN=WebEjbcaHealthCheckTestOcspSigner";

    private ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class,
            EjbRemoteHelper.MODULE_TEST);

    private static final String TESTCLASSNAME = WebEjbcaHealthCheckTest.class.getSimpleName();
    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(
            WebEjbcaHealthCheckTest.class.getSimpleName());
    private static int cryptoTokenId;
    private static int internalKeyBindingId;
    private static X509Certificate ocspSigningCertificate;
    private static X509CA x509ca;

    @BeforeClass
    public static void beforeClass() throws Exception {
        x509ca = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(authenticationToken, CA_DN);
        cryptoTokenId = CryptoTokenTestUtils.createSoftCryptoToken(authenticationToken, TESTCLASSNAME);
        internalKeyBindingId = OcspTestUtils.createInternalKeyBinding(authenticationToken, cryptoTokenId,
                OcspKeyBinding.IMPLEMENTATION_ALIAS, TESTCLASSNAME, "RSA2048", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);  
        ocspSigningCertificate = OcspTestUtils.createOcspSigningCertificate(authenticationToken, OcspTestUtils.OCSP_END_USER_NAME, SIGNER_DN, internalKeyBindingId, x509ca.getCAId());
        OcspTestUtils.updateInternalKeyBindingCertificate(authenticationToken, internalKeyBindingId);
        OcspTestUtils.setInternalKeyBindingStatus(authenticationToken, internalKeyBindingId, InternalKeyBindingStatus.ACTIVE);
        final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CertificateStoreSessionRemote.class);
        //Store the CA Certificate.
        certificateStoreSession.storeCertificate(authenticationToken, x509ca.getCACertificate(), "foo", "1234", CertificateConstants.CERT_ACTIVE,
                CertificateConstants.CERTTYPE_ROOTCA, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "footag", new Date().getTime());
        OcspResponseGeneratorSessionRemote ocspResponseGeneratorSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(OcspResponseGeneratorSessionRemote.class);
        ocspResponseGeneratorSession.reloadOcspSigningCache();
    }
    
    @AfterClass
    public static void afterClass() throws Exception {
        InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);       
        try {
            internalCertificateStoreSession.removeCertificate(ocspSigningCertificate);
        } catch (Exception e) {
            //Ignore any failures.
        }       
        try {
            internalCertificateStoreSession.removeCertificate(x509ca.getCACertificate());
        } catch (Exception e) {
            //Ignore any failures.
        }
        InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementSessionRemote.class);
        AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(TESTCLASSNAME);
        internalKeyBindingMgmtSession.deleteInternalKeyBinding(authenticationToken, internalKeyBindingId);
        cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, cryptoTokenId);
        OcspTestUtils.deleteCa(authenticationToken, x509ca);
    }
    
    @Before
    public void setUp() throws Exception {
        httpPort = SystemTestsConfiguration.getRemotePortHttp(configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP));
        final String remoteHost = SystemTestsConfiguration.getRemoteHost("localhost");
        httpReqPath = "http://"+remoteHost+":" + httpPort + "/ejbca/publicweb/healthcheck/ejbcahealth";
    }

    @After
    public void tearDown() throws Exception {
    }

    
    /** Returns a connected HttpURLConnection, that must be closed with con.diconnect() when you are done 
     * 
     * @param url The URL to connect to 
     * @return HttpURLConnection that you can use
     * @throws IOException In case the connection can not be opened
     */
    private HttpURLConnection getHttpURLConnection(String url) throws IOException {
        final HttpURLConnection con;
        URL u = new URL(url);
        con = (HttpURLConnection)u.openConnection();
        con.setRequestMethod("GET");
        con.getDoOutput();
        con.connect();
        return con;
    }

    /**
     * Creates a number of threads that bombards the health check servlet 1000
     * times each
     */
    @Test
    public void testEjbcaHealthHttp() throws Exception {
        log.trace(">testEjbcaHealthHttp()");
        // Make a quick test first that it works at all before starting all threads
        final HttpURLConnection con = getHttpURLConnection(httpReqPath);
        int ret = con.getResponseCode();
        log.debug("HTTP response code: "+ret+". Response message: "+con.getResponseMessage());
        assertEquals("Response code", 200, ret);
        String retStr = Streams.asString(con.getInputStream());
        log.debug("Return String: "+retStr);
        assertEquals("ALLOK", retStr);
        con.disconnect();

        // Create several threads to test
        long before = System.currentTimeMillis();
        createThreads();
        long after = System.currentTimeMillis();
        long diff = after - before;
        log.info("All threads finished. Total time: " + diff + " ms");
        assertTrue("Healt check test(s) timed out, took "+diff+" ms to complete.", diff < 40L*1000L);
        log.trace("<testEjbcaHealthHttp()");
    }

}
