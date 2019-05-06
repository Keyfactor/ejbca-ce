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

import java.net.URL;
import java.security.SecureRandom;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.configuration.GlobalConfigurationSession;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.provider.X509TrustManagerAcceptAll;
import org.ejbca.config.AvailableProtocolsConfiguration;
import org.ejbca.config.EstConfiguration;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeProxySessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

/**
 * 
 * @version $Id: CmpAliasTest.java 22450 2015-12-15 14:06:34Z mikekushner $
 *
 */

public class EstAliasTest extends EstTestCase {

    private static final Logger log = Logger.getLogger(EstAliasTest.class);

    private final GlobalConfigurationSession globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private static final EnterpriseEditionEjbBridgeProxySessionRemote enterpriseEjbBridgeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EnterpriseEditionEjbBridgeProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    @BeforeClass
    public static void beforeClass() {
        assumeTrue(enterpriseEjbBridgeSession.isRunningEnterprise());
        CryptoProviderTools.installBCProvider();
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Sends a EST request with the alias requestAlias in the URL and expects a HTTP error message 
     * if that extractedAlias does not  exist.
     * 
     * @param requestAlias the alias that is specified in the URL
     * @param extractedAlias the alias that EJBCA will use to handle the EST request
     * @throws Exception if connection to server can not be established
     */
    private void sendEstRequest(EstConfiguration config, String operation, String requestAlias, String extractedAlias, int expectedReturnCode) throws Exception {

        try {
            // If the extractedAlias exists, move it away for the test as we expect the test to fail with unknown alias
            if (config.aliasExists(extractedAlias)) {
                config.renameAlias(extractedAlias, "backUpAlias" + extractedAlias + "ForAliasTesting001122334455");
                this.globalConfigurationSession.saveConfiguration(ADMIN, config);
            }
            // If the default alias exists, move it away for the test as we expect the test to fail with unknown alias
            if (StringUtils.isEmpty(requestAlias) && config.aliasExists(extractedAlias)) {
                log.error("MOVING DEFAULT ALIAS");
                config.renameAlias(extractedAlias, "backUpAlias" + extractedAlias + "ForAliasTestingDefault001122334455");
                this.globalConfigurationSession.saveConfiguration(ADMIN, config);
            }

            String urlString = this.httpReqPath;
            if(StringUtils.isNotEmpty(requestAlias)) {
                urlString += requestAlias; 
                urlString += "/" + operation;
            } else {
                urlString += operation;                
            }
            log.info("requestAlias: " + requestAlias);
            log.info("extractedAlias: " + extractedAlias);
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
            if (operation.contains("simple")) {
                // mime-type for simpleenroll and simplereenroll as specified in RFC7030 section 4.2.1
                con.setRequestProperty("Content-type", "application/pkcs10");
            }
            con.connect();
            // An EST alias that does not exist will result in a HTTP bad request error
            // an unknown operation in a 404 not found
            assertEquals("Unexpected HTTP response code.", expectedReturnCode, con.getResponseCode()); 
        } finally {
            // If we moved away the alias in the beginning, move it back
            if (config.aliasExists("backUpAlias" + extractedAlias + "ForAliasTesting001122334455")) {
                config.renameAlias("backUpAlias" + extractedAlias + "ForAliasTesting001122334455", extractedAlias);
                this.globalConfigurationSession.saveConfiguration(ADMIN, config);
            }
            if (config.aliasExists("backUpAlias" + extractedAlias + "ForAliasTestingDefault001122334455")) {
                config.renameAlias("backUpAlias" + extractedAlias + "ForAliasTestingDefault001122334455", extractedAlias);
                this.globalConfigurationSession.saveConfiguration(ADMIN, config);
            }
        }
    }


    /**
     * Tests that the right configuration alias is extracted from the EST URL. 
     * 
     * An EST request for a non-existing alias is sent. Expected a http error code caused by the absence of the expected EST alias 
     * 
     * @throws Exception if connection to server can not be established
     */
    @Test
    public void testAccessAlias() throws Exception {
        log.trace(">test01Access()");

        AvailableProtocolsConfiguration protConf = ((AvailableProtocolsConfiguration) this.globalConfigurationSession
                .getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID));
        final boolean isProtocolEnabled = protConf.getProtocolStatus("EST");

        try {
            if (!isProtocolEnabled) {
                // Enable if not enabled
                protConf.setProtocolStatus("EST", true);
                this.globalConfigurationSession.saveConfiguration(ADMIN, protConf);
            }
            EstConfiguration config = (EstConfiguration) this.globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);

            //
            // Requests with an unknown alias gives a http 400, bad_request
            //
            sendEstRequest(config, "cacerts", "alias123", "alias123", 400); // "alias123" in the request causes EJBCA to use "alias123" as EST alias
            sendEstRequest(config, "cacerts", "123", "123", 400); // "123" in the request causes EJBCA to use "123" as EST alias
            sendEstRequest(config, "cacerts", "", "est", 400); // No alias in the request causes EJBCA to use "est" (the default alias) as EST alias
            sendEstRequest(config, "cacerts", null, "est", 400); // No alias in the request causes EJBCA to use "est" (the default alias) as EST alias
            sendEstRequest(config, "cacerts", "abcdefghijklmnopqrstuvwxyz0123456789", "abcdefghijklmnopqrstuvwxyz0123456789", 400); // too long alias (>32) gives bad request

            //
            // Requests with an unknown operation gives a http 404, not_found
            //
            sendEstRequest(config, "cacerts", "alias??&!!foo", "alias", 404); // Specifying alias with non-alphanumeric characters cause EJBCA to 
            // strip everything after these chars, making the URL broken. As EST alias, a url of 
            // https://localhost:8442/.well-known/est/alias??&!!foo/cacerts will on the server side be processed as
            // https://localhost:8442/.well-known/est/alias hence using 'alias' as operation, which is not a supported operation
            sendEstRequest(config, "cacerts", "??##!!&", "est", 404); // same as above, will result in HTTP request https://localhost:8442/.well-known/est/
            // i.e. with no method            

            //
            // Requests to EST when it is disabled in protocol configuration gives a http 403, forbidden
            //
            // Disable protocol
            protConf.setProtocolStatus("EST", false);
            this.globalConfigurationSession.saveConfiguration(ADMIN, protConf);
            sendEstRequest(config, "cacerts", "", "est", 403); // Not enabled will give forbidden

        } finally {
            // Restore values
            protConf.setProtocolStatus("EST", isProtocolEnabled);            
            this.globalConfigurationSession.saveConfiguration(ADMIN, protConf);
        }
        
        
        log.trace("<test01Access()");
    }

    @Test
    public void testCreateAndCloneAlias() {
        EstConfiguration estConfig = (EstConfiguration) this.globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);

        // Test adding an alias
        String alias = "EstURLTestCmpConfigAlias";
        while(estConfig.aliasExists(alias)) {
            alias += "0";
        }
        estConfig.addAlias(alias);
        assertTrue("Failed to add alias: " + alias, estConfig.aliasExists(alias));
        assertEquals("Alias '" + alias + "' was not initialized correctly", "1", estConfig.getCertProfileID(alias));

        // Test cloning an alias
        String clonealias = alias + "CloneAlias";
        while(estConfig.aliasExists(clonealias)) {
            clonealias += "0";
        }
        estConfig.cloneAlias(alias, clonealias);
        assertTrue(estConfig.aliasExists(alias));
        assertTrue(estConfig.aliasExists(clonealias));
        // run some checks on the cloned alias
        assertEquals("1", estConfig.getCertProfileID(alias));
        assertEquals("1", estConfig.getCertProfileID(clonealias));
        assertEquals(1, estConfig.getEndEntityProfileID(alias));
        assertEquals(1, estConfig.getEndEntityProfileID(clonealias));
        assertEquals("", estConfig.getDefaultCAID(alias));
        assertEquals("", estConfig.getDefaultCAID(clonealias));
        assertTrue(estConfig.getKurAllowSameKey(alias));
        assertTrue(estConfig.getKurAllowSameKey(clonealias));
        estConfig.setCertProfileID(alias, 2);
        estConfig.setDefaultCAID(alias, 3);
        assertEquals("2", estConfig.getCertProfileID(alias));
        assertEquals("1", estConfig.getCertProfileID(clonealias));
        assertEquals("3", estConfig.getDefaultCAID(alias));
        assertEquals("", estConfig.getDefaultCAID(clonealias));
        estConfig.cloneAlias(clonealias, alias);
        assertTrue(estConfig.aliasExists(alias));
        assertTrue(estConfig.aliasExists(clonealias));
        assertEquals("2", estConfig.getCertProfileID(alias));
        assertEquals("1", estConfig.getCertProfileID(clonealias));

        // Test renaming an alias
        String renamealias = alias + "RenameAlias";
        while(estConfig.aliasExists(renamealias)) {
            renamealias += "0";
        }
        estConfig.renameAlias(alias, renamealias);
        assertTrue(estConfig.aliasExists(renamealias));
        assertFalse(estConfig.aliasExists(alias));
        assertEquals("2", estConfig.getCertProfileID(renamealias));
        estConfig.renameAlias(renamealias, clonealias); // not possible to rename to an existing alias
        assertTrue(estConfig.aliasExists(renamealias));
        assertTrue(estConfig.aliasExists(clonealias));
        assertEquals("2", estConfig.getCertProfileID(renamealias));
        assertEquals("1", estConfig.getCertProfileID(clonealias));

        //Test removing alias
        estConfig.removeAlias(alias);
        estConfig.removeAlias(clonealias);
        estConfig.removeAlias(renamealias);
        assertFalse(estConfig.aliasExists(alias));
        assertFalse(estConfig.aliasExists(clonealias));
        assertFalse(estConfig.aliasExists(renamealias));
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

}
