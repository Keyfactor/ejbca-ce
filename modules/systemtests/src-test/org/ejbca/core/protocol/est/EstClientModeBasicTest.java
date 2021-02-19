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

import java.security.cert.X509Certificate;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.configuration.GlobalConfigurationSession;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.AvailableProtocolsConfiguration;
import org.ejbca.config.EstConfiguration;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeProxySessionRemote;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;

/**
 * Tests basic EST client mode. Initial enrollment and re-enrollment to pre-registered end entity using the end entity password for initial authorization.
 * Including basic error cases: malicious request (too large), invalid CSR encoding, no end entity found for initial enrollment or re-enrollment
 */
public class EstClientModeBasicTest extends EstTestCase {

    private static final Logger log = Logger.getLogger(EstClientModeBasicTest.class);

    private static final String TESTCA_NAME = EstClientModeBasicTest.class.getSimpleName();
    private static boolean isESTEnabled = false; // if EST was enabled or not before running test 
    
    private static final GlobalConfigurationSession globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private static final EnterpriseEditionEjbBridgeProxySessionRemote enterpriseEjbBridgeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EnterpriseEditionEjbBridgeProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    @BeforeClass
    public static void beforeClass() throws CADoesntExistsException, CAExistsException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, AuthorizationDeniedException {
        assumeTrue(enterpriseEjbBridgeSession.isRunningEnterprise());
        CryptoProviderTools.installBCProvider();
        createTestCA(TESTCA_NAME); // Create test CA
        
        // Enable EST. EstAliasTest tests responses when disabled so here we only want to test enabled functionality
        AvailableProtocolsConfiguration protConf = ((AvailableProtocolsConfiguration) globalConfigurationSession
                .getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID));
        isESTEnabled = protConf.getProtocolStatus("EST");
        if (!isESTEnabled) {
            // Enable if not enabled
            protConf.setProtocolStatus("EST", true);
            globalConfigurationSession.saveConfiguration(ADMIN, protConf);
        }
    }

    @AfterClass
    public static void afterClass() {
        // Set back enablement to what it was before running tests
        AvailableProtocolsConfiguration protConf = ((AvailableProtocolsConfiguration) globalConfigurationSession
                .getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID));
        protConf.setProtocolStatus("EST", isESTEnabled);            
        try {
            globalConfigurationSession.saveConfiguration(ADMIN, protConf);
        } catch (AuthorizationDeniedException e) {
            log.error(e.getMessage(), e);
        }
        try {
            removeTestCA(TESTCA_NAME);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
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
     * Tests getting CA certificates, when CA exists and when not. {@link EstAliasTest)} already tests cacerts for non existing aliases.
     */
    @Test
    public void testGetCACerts() throws Exception {
        log.trace(">testGetCACerts()");
        final String alias = "ESTGetCACertsTest";
        EstConfiguration config = (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        try {
            config.addAlias(alias);
            config.setRAMode(alias, false); // client mode
            // We don't need much in this alias to just get CA certificate
            config.setDefaultCAID(alias, getTestCAId(TESTCA_NAME));
            globalConfigurationSession.saveConfiguration(ADMIN, config);
            // Make EST cacerts request here
            byte[] resp = sendEstRequest(alias, "cacerts", null, 200);
            // If all was OK we should have gotten a base64 encoded certificates-only CMS message back. RFC7030 section 4.1.3
            assertNotNull("There must be response data to cacerts request", resp);
            final CMSSignedData msg = new CMSSignedData(Base64.decode(resp));
            final Store<X509CertificateHolder> certstore = msg.getCertificates();
            final Collection<X509CertificateHolder> certs = certstore.getMatches(null);
            assertEquals("EST test CA has a single CA certificate", 1, certs.size());
            final X509Certificate testcacert = (X509Certificate)getTestCACert(TESTCA_NAME);
            assertEquals("cacerts response subjectDN must be our EST test CAs subjectDN", testcacert.getSubjectDN().getName(), certs.iterator().next().getSubject().toString());
        } finally {
            // Remove EST alias
            config.removeAlias(alias);
            globalConfigurationSession.saveConfiguration(ADMIN, config);
        }        
        log.trace("<testGetCACerts()");
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

}
