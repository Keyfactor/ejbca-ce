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

package org.ejbca.ui.web.pub;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Collections;
import java.util.Properties;

import org.apache.commons.fileupload.util.Streams;
import org.cesecore.CaTestUtils;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementProxySessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeProxySessionRemote;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.publisher.PublisherProxySessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.model.ca.publisher.LdapPublisher;
import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.KeyGenParams;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * System tests for the health check servlet.
 *
 * @version $Id$
 */

public class HealthCheckSystemTest {
    
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("HealthCheckTest"));


    private static final CaSessionRemote CA_SESSION = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final ConfigurationSessionRemote CONFIG_SESSION = EjbRemoteHelper.INSTANCE.getRemoteSession(
            ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final CryptoTokenManagementSessionRemote CRYPTO_TOKEN_MANAGEMENT_SESSION = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private static final CryptoTokenManagementProxySessionRemote CRYPTO_TOKEN_MANAGEMENT_PROXY_SESSION = EjbRemoteHelper.INSTANCE.getRemoteSession(
            CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final EnterpriseEditionEjbBridgeProxySessionRemote ENTERPRISE_EJB_BRIDGE_SESSION = EjbRemoteHelper.INSTANCE.getRemoteSession(
            EnterpriseEditionEjbBridgeProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final PublisherProxySessionRemote PUBLISHER_PROXY_SESSION = EjbRemoteHelper.INSTANCE.getRemoteSession(
            PublisherProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private static final String HTTP_HOST = SystemTestsConfiguration.getRemoteHost(CONFIG_SESSION.getProperty(WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME));
    private static final String HTTP_PORT = SystemTestsConfiguration.getRemotePortHttp(CONFIG_SESSION.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP));
    private static final String HTTP_REQ_PATH = "http://" + HTTP_HOST + ":" + HTTP_PORT + "/ejbca/publicweb/healthcheck/ejbcahealth";

    private static final String KEY_DATABASEPROTECTION_ENABLESIGN_AUDITRECORDDATA = "databaseprotection.enablesign.AuditRecordData";
    private static final String KEY_DATABASEPROTECTION_KEYID_AUDITRECORDDATA = "databaseprotection.keyid.AuditRecordData";
    private static final String KEY_HEALTHCHECK_PUBLISHERCONNECTIONS = "healthcheck.publisherconnections";

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    private HttpURLConnection performHealthCheckGetRequest() throws IOException {
        final URL url = new URL(HTTP_REQ_PATH);
        final HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.getDoOutput();
        connection.connect();
        connection.disconnect();
        return connection;
    }

    private HttpURLConnection performHealthCheckGetRequestWithFalseFlag(String flagName) throws IOException {
        final URL url = new URL(HTTP_REQ_PATH + "?" + flagName + "=false");
        final HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.getDoOutput();
        connection.connect();
        connection.disconnect();
        return connection;
    }
    
    private HttpURLConnection performHealthCheckGetRequestWithParams(String paramString) throws IOException {
        final URL url = new URL(HTTP_REQ_PATH + "?" + paramString);
        final HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.getDoOutput();
        connection.connect();
        connection.disconnect();
        return connection;
    }
    
    /**
     * This is a basic happy-path test of the health check servlet.
     */
    @Test
    public void testAllOk() throws IOException {
        final HttpURLConnection response = performHealthCheckGetRequest();
        assertEquals("Response code was not 200", 200, response.getResponseCode());
        final String responseStr = Streams.asString(response.getInputStream());
        assertTrue("Response did not contain OK, was: " + responseStr, responseStr.contains("ALLOK"));
    }

    /**
     * This test creates a CA with a non-auto activated crypto token, sets it offline then verifies that healthcheck doesn't care when "ca=false"
     */
    @Test
    public void testHealthCheckWithCaCheckDisabled() throws Exception {
        final String caName = "testCaHealthCheck";
        CaTestCase.createTestCA(caName);
        CAInfo caInfo = CA_SESSION.getCAInfo(admin, caName);
        try {
            // Remove auto activate
            final CryptoToken cryptoToken = CRYPTO_TOKEN_MANAGEMENT_PROXY_SESSION.getCryptoToken(caInfo.getCAToken().getCryptoTokenId());
            final Properties props = cryptoToken.getProperties();
            props.remove(CryptoToken.AUTOACTIVATE_PIN_PROPERTY);
            cryptoToken.setProperties(props);
            CRYPTO_TOKEN_MANAGEMENT_PROXY_SESSION.mergeCryptoToken(cryptoToken);
            // Set CA's crypto token offline
            CRYPTO_TOKEN_MANAGEMENT_SESSION.deactivate(admin, caInfo.getCAToken().getCryptoTokenId());
            final HttpURLConnection response = performHealthCheckGetRequestWithFalseFlag("ca");
            assertEquals("Response code was not 200", 200, response.getResponseCode());
        } finally {
            CaTestCase.removeTestCA(caName);
        }
    }
    
    /**
     * This test creates a non-auto activated crypto token, sets it offline then verifies that healthcheck fails
     */
    @Test
    public void testHealthCheckCryptoToken() throws Exception {
        String tokenName = "healthCheckTest";
        int tokenId = CryptoTokenTestUtils.createSoftCryptoToken(admin, tokenName);
        try {
            CRYPTO_TOKEN_MANAGEMENT_SESSION.createKeyPair(admin, tokenId, "testKey", KeyGenParams.builder("RSA2048").build());
            final HttpURLConnection response = performHealthCheckGetRequestWithParams("token=" + tokenName + "&key=testKey");
            assertEquals("Response code was not 200", 200, response.getResponseCode());
        } finally {
            CryptoTokenTestUtils.removeCryptoToken(admin, tokenId);
        }
    }
    
    /**
     * This test creates a non-auto activated crypto token, sets it offline then verifies that healthcheck fails
     */
    @Test
    public void testHealthCheckCryptoTokenOffline() throws Exception {
        String tokenName = "healthCheckTest";
        int tokenId = CryptoTokenTestUtils.createSoftCryptoToken(admin, tokenName);
        try {
            CRYPTO_TOKEN_MANAGEMENT_SESSION.createKeyPair(admin, tokenId, "testKey", KeyGenParams.builder("RSA2048").build());
            
            // Set crypto token offline
            final CryptoToken cryptoToken = CRYPTO_TOKEN_MANAGEMENT_PROXY_SESSION.getCryptoToken(tokenId);
            final Properties props = cryptoToken.getProperties();
            props.remove(CryptoToken.AUTOACTIVATE_PIN_PROPERTY);
            cryptoToken.setProperties(props);
            CRYPTO_TOKEN_MANAGEMENT_PROXY_SESSION.mergeCryptoToken(cryptoToken);
            CRYPTO_TOKEN_MANAGEMENT_SESSION.deactivate(admin, tokenId);
            
            final HttpURLConnection response = performHealthCheckGetRequestWithParams("token=" + tokenName + "&key=testKey");
            
            assertEquals("Response code was not 500", 500, response.getResponseCode());
        } finally {
            CryptoTokenTestUtils.removeCryptoToken(admin, tokenId);
        }
    }
    
    /**
     * This test creates a CA with a non-auto activated crypto token, sets it offline then verifies that healthcheck tosses its cookies.
     */
    @Test
    public void testCaHealthCheck() throws Exception {
        final String caName = "testCaHealthCheck";
        CaTestCase.createTestCA(caName);
        CAInfo caInfo = CA_SESSION.getCAInfo(admin, caName);
        try {
            // Remove auto activate
            final CryptoToken cryptoToken = CRYPTO_TOKEN_MANAGEMENT_PROXY_SESSION.getCryptoToken(caInfo.getCAToken().getCryptoTokenId());
            final Properties props = cryptoToken.getProperties();
            props.remove(CryptoToken.AUTOACTIVATE_PIN_PROPERTY);
            cryptoToken.setProperties(props);
            CRYPTO_TOKEN_MANAGEMENT_PROXY_SESSION.mergeCryptoToken(cryptoToken);
            // Set CA's crypto token offline
            CRYPTO_TOKEN_MANAGEMENT_SESSION.deactivate(admin, caInfo.getCAToken().getCryptoTokenId());
            final HttpURLConnection response = performHealthCheckGetRequest();
            assertEquals("Response code was not 500", 500, response.getResponseCode());
            final String responseStr = Streams.asString(response.getErrorStream());
            assertTrue("Response did not contain correct error message, was: " + responseStr, responseStr.contains("CA: Error CA Token is disconnected"));
        } finally {
            CaTestCase.removeTestCA(caName);
        }
    }
    
    /**
     * This test creates two CAs and checks them both
     */
    @Test
    public void testHealthCheckWithMultipleCasAndOneOffline() throws Exception {
        CaTestCase.createTestCA("testHealthCheck1");
        CaTestCase.createTestCA("testHealthCheck2");
        try {
            // Set CA's crypto token offline
            CAInfo caInfo = CA_SESSION.getCAInfo(admin, "testHealthCheck2");
            final CryptoToken cryptoToken = CRYPTO_TOKEN_MANAGEMENT_PROXY_SESSION.getCryptoToken(caInfo.getCAToken().getCryptoTokenId());
            final Properties props = cryptoToken.getProperties();
            props.remove(CryptoToken.AUTOACTIVATE_PIN_PROPERTY);
            cryptoToken.setProperties(props);
            CRYPTO_TOKEN_MANAGEMENT_PROXY_SESSION.mergeCryptoToken(cryptoToken);
            CRYPTO_TOKEN_MANAGEMENT_SESSION.deactivate(admin, caInfo.getCAToken().getCryptoTokenId());
            
            // testHealthCheck1 is fine
            final HttpURLConnection response1 = performHealthCheckGetRequestWithParams("ca=testHealthCheck1");
            assertEquals("Response code was not 200", 200, response1.getResponseCode());
            
            // testHealthCheck1 is offline
            final HttpURLConnection response2 = performHealthCheckGetRequestWithParams("ca=testHealthCheck1&ca=testHealthCheck2");
            assertEquals("Response code was not 500", 500, response2.getResponseCode());
        } finally {
            CaTestCase.removeTestCA("testHealthCheck1");
            CaTestCase.removeTestCA("testHealthCheck2");
        }
    }
    
    /**
     * This test creates two CAs and checks them both
     */
    @Test
    public void testHealthCheckWithMultipleCas() throws Exception {
        CaTestCase.createTestCA("testHealthCheck1");
        CaTestCase.createTestCA("testHealthCheck2");
        try {
            // Remove auto activate
            final HttpURLConnection response = performHealthCheckGetRequestWithParams("ca=testHealthCheck1&ca=testHealthCheck2");
            assertEquals("Response code was not 200", 200, response.getResponseCode());
        } finally {
            CaTestCase.removeTestCA("testHealthCheck1");
            CaTestCase.removeTestCA("testHealthCheck2");
        }
    }
    
    
    @Test
    public void testPublisherHealthCheck() throws Exception {
        // Make sure that publishers are checked by health check
        String originalValue = CONFIG_SESSION.getProperty(KEY_HEALTHCHECK_PUBLISHERCONNECTIONS);
        if (!"true".equals(originalValue)) {
            CONFIG_SESSION.updateProperty(KEY_HEALTHCHECK_PUBLISHERCONNECTIONS, "true");
        }
        // Create a random publisher that's not connected to anything.
        final LdapPublisher ldapPublisher = new LdapPublisher();
        ldapPublisher.setHostnames("nowhere");
        final String publisherName = "testPublisherHealthCheck";
        int publisherId = PUBLISHER_PROXY_SESSION.addPublisher(admin, publisherName, ldapPublisher);
        final String caName = "testPublisherHealthCheck";
        CaTestCase.createTestCA(caName);
        final CAInfo caInfo = CA_SESSION.getCAInfo(admin, caName);
        caInfo.setCRLPublishers(Collections.singletonList(publisherId));
        CA_SESSION.editCA(admin, caInfo);
        try {
            final HttpURLConnection response = performHealthCheckGetRequest();
            assertEquals("Response code was not 500", 500, response.getResponseCode());
            final String responseStr = Streams.asString(response.getErrorStream());
            assertTrue("Response did not contain correct error message, was: " + responseStr,
                    responseStr.contains("Error when testing the connection with publisher"));
        } finally {
            PUBLISHER_PROXY_SESSION.removePublisherInternal(admin, publisherName);
            CaTestCase.removeTestCA(caName);
            CONFIG_SESSION.updateProperty(KEY_HEALTHCHECK_PUBLISHERCONNECTIONS, originalValue);
        }
    }

    @Test
    public void testHealthCheckWithPublisherCheckDisabled() throws Exception {
        // Make sure that publishers are not checked by health check when disabled
        String originalValue = CONFIG_SESSION.getProperty(KEY_HEALTHCHECK_PUBLISHERCONNECTIONS);
        if (!"true".equals(originalValue)) {
            CONFIG_SESSION.updateProperty(KEY_HEALTHCHECK_PUBLISHERCONNECTIONS, "true");
        }
        // Create a random publisher that's not connected to anything.
        final LdapPublisher ldapPublisher = new LdapPublisher();
        ldapPublisher.setHostnames("nowhere");
        final String publisherName = "testPublisherHealthCheck";
        int publisherId = PUBLISHER_PROXY_SESSION.addPublisher(admin, publisherName, ldapPublisher);
        final String caName = "testPublisherHealthCheck";
        CaTestCase.createTestCA(caName);
        final CAInfo caInfo = CA_SESSION.getCAInfo(admin, caName);
        caInfo.setCRLPublishers(Collections.singletonList(publisherId));
        CA_SESSION.editCA(admin, caInfo);
        try {
            final HttpURLConnection response = performHealthCheckGetRequestWithFalseFlag("publishers");
            assertEquals("Response code was not 200", 200, response.getResponseCode());
            final String responseStr = Streams.asString(response.getInputStream());
            assertTrue("Response did not contain correct error message, was: " + responseStr, responseStr.contains("ALLOK"));
        } finally {
            PUBLISHER_PROXY_SESSION.removePublisherInternal(admin, publisherName);
            CaTestCase.removeTestCA(caName);
            CONFIG_SESSION.updateProperty(KEY_HEALTHCHECK_PUBLISHERCONNECTIONS, originalValue);
        }
    }
    
    @Test
    public void testAuditLogHealthCheck() throws Exception {
        Assume.assumeTrue("This test does not support Community Edition", ENTERPRISE_EJB_BRIDGE_SESSION.isRunningEnterprise());
        // Create a crypto token to sign with
        final Properties cryptoTokenProperties = new Properties();
        final String cryptoTokenName = "testAuditLogHealthCheck";
        CaTestUtils.removeCa(admin, cryptoTokenName, ""); // delete left overs from previous test runs
        int cryptoTokenId = CRYPTO_TOKEN_MANAGEMENT_SESSION.createCryptoToken(admin, cryptoTokenName, SoftCryptoToken.class.getName(),
                cryptoTokenProperties, null, null);

        // Disable publisher checks just to be sure
        final String originalPublisherValue = CONFIG_SESSION.getProperty(KEY_HEALTHCHECK_PUBLISHERCONNECTIONS);
        CONFIG_SESSION.updateProperty(KEY_HEALTHCHECK_PUBLISHERCONNECTIONS, "false");
        // Make sure that database protection is enabled
        final String shouldProtectAuditLog = CONFIG_SESSION.getCesecoreProperty(KEY_DATABASEPROTECTION_ENABLESIGN_AUDITRECORDDATA);
        if (shouldProtectAuditLog == null || !shouldProtectAuditLog.equals("true")) {
            CONFIG_SESSION.updateCesecoreProperty(KEY_DATABASEPROTECTION_ENABLESIGN_AUDITRECORDDATA, "true");
        }
        final String auditLogKeyId = CONFIG_SESSION.getCesecoreProperty(KEY_DATABASEPROTECTION_KEYID_AUDITRECORDDATA);
        if (auditLogKeyId == null || !auditLogKeyId.equals("true")) {
            CONFIG_SESSION.updateCesecoreProperty(KEY_DATABASEPROTECTION_KEYID_AUDITRECORDDATA, "999");
        }
        try {
            final HttpURLConnection response = performHealthCheckGetRequest();
            assertEquals("Response code was not 500", 500, response.getResponseCode());
            final String responseStr = Streams.asString(response.getErrorStream());
            assertTrue("Response did not contain correct error message, was: " + responseStr,
                    responseStr.contains("Could not perform a test signature on the audit log."));
        } finally {
            // Restore values
            CONFIG_SESSION.updateCesecoreProperty(KEY_DATABASEPROTECTION_ENABLESIGN_AUDITRECORDDATA, shouldProtectAuditLog);
            CONFIG_SESSION.updateCesecoreProperty(KEY_DATABASEPROTECTION_KEYID_AUDITRECORDDATA, auditLogKeyId);
            CONFIG_SESSION.updateProperty(KEY_HEALTHCHECK_PUBLISHERCONNECTIONS, originalPublisherValue);
            CRYPTO_TOKEN_MANAGEMENT_SESSION.deleteCryptoToken(admin, cryptoTokenId);
        }
    }
}
