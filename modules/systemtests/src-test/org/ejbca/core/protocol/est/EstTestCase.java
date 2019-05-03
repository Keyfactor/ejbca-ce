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

package org.ejbca.core.protocol.est;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.provider.X509TrustManagerAcceptAll;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Helper class for EST Junit tests. 
 * You can run this test against a EST Proxy instead of direct to the CA by setting the system property httpEstProxyURL, 
 * for example to "https://ra-host:8442/.well-known/est"
 * 
 * @version $Id: CmpTestCase.java 32112 2019-04-11 10:36:33Z tarmo_r_helmes $
 */
public abstract class EstTestCase extends CaTestCase {

    private static final Logger log = Logger.getLogger(EstTestCase.class);

    protected static final String CP_DN_OVERRIDE_NAME = "CP_DN_OVERRIDE_NAME";
    protected static final String EEP_DN_OVERRIDE_NAME = "EEP_DN_OVERRIDE_NAME";
    protected int eepDnOverrideId;
    protected int cpDnOverrideId;

    protected final String httpReqPath; // = "https://127.0.0.1:8442/.well-known/est/";
    private final String EST_HOST; // = "127.0.0.1";

    protected final CertificateStoreSession certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    protected final ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    protected final EndEntityManagementSession endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    protected final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    protected final CertificateProfileSession certProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    protected final EndEntityProfileSession endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);

    protected final static AuthenticationToken ADMIN = new TestAlwaysAllowLocalAuthenticationToken("EstTestCase");

    public EstTestCase() {
        final String httpServerPubHttps = SystemTestsConfiguration.getRemotePortHttp(this.configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTPS));
        this.EST_HOST = SystemTestsConfiguration.getRemoteHost(this.configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME));
        this.httpReqPath = "https://" + this.EST_HOST + ":" + httpServerPubHttps + "/.well-known/est/";
    }
    
    @Override
    protected void setUp() throws Exception { // NOPMD: this is a test base class
        super.setUp();
        cleanup();
        // Configure a Certificate profile (CmpRA) using ENDUSER as template and
        // check "Allow validity override".
        this.cpDnOverrideId = addCertificateProfile(CP_DN_OVERRIDE_NAME);
        this.eepDnOverrideId = addEndEntityProfile(EEP_DN_OVERRIDE_NAME, this.cpDnOverrideId);
    } 
    
    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        cleanup();
    }
    
    private void cleanup() throws AuthorizationDeniedException {
        endEntityProfileSession.removeEndEntityProfile(ADMIN, EEP_DN_OVERRIDE_NAME);
        certProfileSession.removeCertificateProfile(ADMIN, CP_DN_OVERRIDE_NAME);
    }


    
    /**
     * Adds a certificate profile for end entities and sets {@link CertificateProfile#setAllowDNOverride(boolean)} to true.
     * 
     * @param name the name.
     * @return the id of the newly created certificate profile.
     */
    protected final int addCertificateProfile(final String name) {
        assertTrue("Certificate profile with name " + name + " already exists. Clear test data first.", this.certProfileSession.getCertificateProfile(name) == null);
        final CertificateProfile result = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        result.setAllowDNOverride(true);
        int id = -1;
        try {
            this.certProfileSession.addCertificateProfile(ADMIN, name, result);
            id = this.certProfileSession.getCertificateProfileId(name);
            log.info("Certificate profile '" + name + "' and id " + id + " created.");
        } catch (AuthorizationDeniedException | CertificateProfileExistsException e) {
            log.error(e.getMessage(), e);
            fail(e.getMessage());
        }
        return id;
    }
    
    /**
     * Adds a certificate profile and sets {@link CertificateProfile#setAllowDNOverride(boolean)} to true.
     * 
     * @param name the name of the certificate profile.
     * @return the ID of the newly created certificate profile.
     */
    /**
     * Adds an end entity profile and links it with the default certificate profile for test {@link EndEntityProfile#setDefaultCertificateProfile(int)}.
     * 
     * @param name the name of the end entity profile.
     * @param certificateProfileId the default certificate profiles ID.
     * @return the ID of the newly created end entity profile. 
     */
    protected final int addEndEntityProfile(final String name, final int certificateProfileId) {
        assertTrue("End entity profile with name " + name + " already exists. Clear test data first.", this.endEntityProfileSession.getEndEntityProfile(name)  == null);
        // Create profile that is just using CP_DN_OVERRIDE_NAME
        final EndEntityProfile result = new EndEntityProfile(true);
        result.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(certificateProfileId));
        int id = 0;
        try {
            this.endEntityProfileSession.addEndEntityProfile(ADMIN,name, result);
            id = this.endEntityProfileSession.getEndEntityProfileId(name);
        } catch (AuthorizationDeniedException | EndEntityProfileExistsException | EndEntityProfileNotFoundException e) {
            log.error(e.getMessage(), e);
            fail(e.getMessage());
        }
        return id;
    }
        
    class SimpleVerifier implements HostnameVerifier {
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }

    protected byte[] sendEstHttps(byte[] message, int httpRespCode, String estAlias, String operation) throws IOException, NoSuchAlgorithmException, KeyManagementException {
        // POST the ESTrequest
        final String urlString = getProperty("httpEstProxyURL", this.httpReqPath) + estAlias + '/' + operation;
        log.info("http URL: " + urlString);
        URL url = new URL(urlString);

        // Create TLS context that accepts all CA certificates and does not use client cert authentication
        SSLContext context = SSLContext.getInstance("TLS");
        TrustManager[] tm = new X509TrustManager[] {new X509TrustManagerAcceptAll()};
        context.init(null, tm, new SecureRandom());
        SSLSocketFactory factory = context.getSocketFactory();
        HttpsURLConnection.setDefaultSSLSocketFactory(factory);

        final HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
        con.setHostnameVerifier(new SimpleVerifier()); // no hostname verification for testing

        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-type", "application/est");
        con.connect();
        // POST it
        OutputStream os = con.getOutputStream();
        os.write(message);
        os.close();

        assertEquals("Unexpected HTTP response code.", httpRespCode, con.getResponseCode());
        // Only try to read the response if we expected a 200 (ok) response
        if (httpRespCode != 200) {
            return null;
        }
        // Check returned headers as specified in RFC7030
        assertNotNull("No content type in response.", con.getContentType());
        assertTrue(con.getContentType().startsWith("application/est"));
        final String cacheControl = con.getHeaderField("Cache-Control");
        assertNotNull("'Cache-Control' header is not present.", cacheControl);
        assertEquals("no-cache", cacheControl);
        final String pragma = con.getHeaderField("Pragma");
        assertNotNull(pragma);
        assertEquals("no-cache", pragma);
        // Now read in the bytes
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and CMP requests are small enough
        InputStream in = con.getInputStream();
        int b = in.read();
        while (b != -1) {
            baos.write(b);
            b = in.read();
        }
        baos.flush();
        in.close();
        byte[] respBytes = baos.toByteArray();
        assertNotNull(respBytes);
        assertTrue(respBytes.length > 0);
        return respBytes;
    }


    private static String getProperty(String key, String defaultValue) {
        //If being run from command line
        String result = System.getProperty(key);
        log.debug("System.getProperty("+key+"): " + result);
        if (result == null) {
            //If being run from Eclipse
            final String testProperties = System.getProperty("sun.java.command");
            int cutFrom = testProperties.indexOf(key + "=");
            if (cutFrom >= 0) {
                int to = testProperties.indexOf(" ", cutFrom + key.length() + 1);
                result = testProperties.substring(cutFrom + key.length() + 1, (to >= 0 ? to : testProperties.length())).trim();
            }
        }
        return StringUtils.defaultIfEmpty(result, defaultValue);
    }


}
