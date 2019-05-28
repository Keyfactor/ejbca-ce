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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;
import java.util.Properties;

import org.apache.commons.fileupload.util.Streams;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenManagementProxySessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.publisher.PublisherProxySessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.model.ca.publisher.LdapPublisher;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

/**
 * System tests for the health check servlet.
 * 
 * @version $Id$
 */

public class HealthCheckTest {

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("HealthCheckTest"));

    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class,
            EjbRemoteHelper.MODULE_TEST);
    private final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private final CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final PublisherProxySessionRemote publisherProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherProxySessionRemote.class,
            EjbRemoteHelper.MODULE_TEST);

    private final String httpHost = SystemTestsConfiguration
            .getRemoteHost(configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME));
    private final String httpPort = SystemTestsConfiguration
            .getRemotePortHttp(configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP));
    private String httpReqPath = "http://" + httpHost + ":" + httpPort + "/ejbca/publicweb/healthcheck/ejbcahealth";

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    private HttpURLConnection performHealthCheck() throws IOException {
        URL url = new URL(httpReqPath);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
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
        HttpURLConnection response = performHealthCheck();
        assertEquals("Response code was not 200", 200, response.getResponseCode());
        String retStr = Streams.asString(response.getInputStream());
        assertTrue("Response did not contain OK, was: " + retStr, retStr.contains("ALLOK"));
    }

    /**
     * This test creates a CA with a non-auto activated crypto token, sets it offline then verifies that healthcheck tosses its cookies. 
     */
    @Test
    public void testCaHealthCheck() throws IOException, CADoesntExistsException, CAExistsException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException, AuthorizationDeniedException, CryptoTokenNameInUseException {
        final String caName = "testCaHealthCheck";
        CaTestCase.createTestCA(caName);
        CAInfo caInfo = caSession.getCAInfo(admin, caName);

        try {
            // Remove auto activate
            CryptoToken cryptoToken = cryptoTokenManagementProxySession.getCryptoToken(caInfo.getCAToken().getCryptoTokenId());
            Properties prop = cryptoToken.getProperties();
            prop.remove(CryptoToken.AUTOACTIVATE_PIN_PROPERTY);
            cryptoToken.setProperties(prop);
            cryptoTokenManagementProxySession.mergeCryptoToken(cryptoToken);
            //Set CA's crypto token offline
            cryptoTokenManagementSession.deactivate(admin, caInfo.getCAToken().getCryptoTokenId());
            HttpURLConnection response = performHealthCheck();
            assertEquals("Response code was not 500", 500, response.getResponseCode());
            String retStr = Streams.asString(response.getErrorStream());
            assertTrue("Response did not contain correct error message, was: " + retStr, retStr.contains("CA: Error CA Token is disconnected"));

        } finally {
            CaTestCase.removeTestCA(caName);
        }
    }

    @Test
    public void testPublisherHealthCheck() throws PublisherExistsException, AuthorizationDeniedException, IOException, CADoesntExistsException,
            CAExistsException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
        //Make sure that publishers are checked by health check
        String originalValue = configurationSession.getProperty("healthcheck.publisherconnections");
        if (!originalValue.equals("true")) {
            configurationSession.updateProperty("healthcheck.publisherconnections", "true");
        }
        //Create a random publisher that's not connected to anything. 
        LdapPublisher ldapPublisher = new LdapPublisher();
        ldapPublisher.setHostnames("nowhere");
        final String publisherName = "testPublisherHealthCheck";
        int publisherId = publisherProxySession.addPublisher(admin, publisherName, ldapPublisher);
        final String caName = "testPublisherHealthCheck";
        CaTestCase.createTestCA(caName);
        CAInfo caInfo = caSession.getCAInfo(admin, caName);
        caInfo.setCRLPublishers(Arrays.asList(publisherId));
        caSession.editCA(admin, caInfo);
        try {
            HttpURLConnection response = performHealthCheck();
            assertEquals("Response code was not 500", 500, response.getResponseCode());
            String retStr = Streams.asString(response.getErrorStream());
            assertTrue("Response did not contain correct error message, was: " + retStr,
                    retStr.contains("Error when testing the connection with publisher"));
        } finally {
            publisherProxySession.removePublisherInternal(admin, publisherName);
            CaTestCase.removeTestCA(caName);
            configurationSession.updateProperty("healthcheck.publisherconnections", originalValue);
        }
    }

    @Test
    public void testAuditLogHealthCheck() throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException,
            AuthorizationDeniedException, NoSuchSlotException, IOException {
        //Create a crypto token to sign with
        final Properties cryptoTokenProperties = new Properties();
        final String cryptoTokenName = "testAuditLogHealthCheck";
        int cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(admin, cryptoTokenName, SoftCryptoToken.class.getName(),
                cryptoTokenProperties, null, null);

        //Disable publisher checks just to be sure
        String originalPublisherValue = configurationSession.getProperty("healthcheck.publisherconnections");
        configurationSession.updateProperty("healthcheck.publisherconnections", "false");
        //Make sure that database protection is enabled 
        final String shouldProtectAuditLog = configurationSession.getCesecoreProperty("databaseprotection.enablesign.AuditRecordData");
        if (shouldProtectAuditLog == null || !shouldProtectAuditLog.equals("true")) {
            configurationSession.updateCesecoreProperty("databaseprotection.enablesign.AuditRecordData", "true");
        }
        final String auditLogKeyId = configurationSession.getCesecoreProperty("databaseprotection.keyid.AuditRecordData");
        if (auditLogKeyId == null || !auditLogKeyId.equals("true")) {
            configurationSession.updateCesecoreProperty("databaseprotection.keyid.AuditRecordData", "123");
        }
        try {
            HttpURLConnection response = performHealthCheck();
            assertEquals("Response code was not 500", 500, response.getResponseCode());
            String retStr = Streams.asString(response.getErrorStream());
            assertTrue("Response did not contain correct error message, was: " + retStr,
                    retStr.contains("Could not perform a test signature on the audit log."));
        } finally {
            //Restore values
            configurationSession.updateCesecoreProperty("databaseprotection.enablesign.AuditRecordData", shouldProtectAuditLog);
            configurationSession.updateCesecoreProperty("ddatabaseprotection.keyid.AuditRecordData", auditLogKeyId);
            configurationSession.updateProperty("healthcheck.publisherconnections", originalPublisherValue);
            cryptoTokenManagementSession.deleteCryptoToken(admin, cryptoTokenId);
        }

    }

}
