package org.ejbca.core.protocol.config;

import org.apache.http.HttpResponse;
import org.apache.log4j.Logger;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.WebTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.AvailableProtocolsConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.config.AvailableProtocolsConfiguration.AvailableProtocols;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeProxySessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.protocol.ws.EjbcaWSTest;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;

/**
 * Tests the denied state of all configurable protocols and services in  (Modular Protocol Configuration)
 * @version $Id$
 *
 */
public class ProtocolConfigTest {

    private static final Logger log = Logger.getLogger(ProtocolConfigTest.class);
    private static final String EXPECTED_403_REASON = "Forbidden";
    private static final String EXPECTED_WS_MESSAGE = "Web Services not enabled";
    
    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final ConfigurationSessionRemote configurationSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final EnterpriseEditionEjbBridgeProxySessionRemote enterpriseEjbBridgeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EnterpriseEditionEjbBridgeProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ProtocolConfigTest"));
    
    private static String httpReqPath;
    private AvailableProtocolsConfiguration configBackup;
    
    
    @Before
    public void preTest() {
        final String httpHost = SystemTestsConfiguration.getRemoteHost(configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME));
        final String httpPort = SystemTestsConfiguration.getRemotePortHttp(configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP));
        httpReqPath = "http://" + httpHost + ":" + httpPort;
        configBackup = (AvailableProtocolsConfiguration) globalConfigurationSession.getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
    }
    
    @After
    public void postTest() {
        try {
            globalConfigurationSession.saveConfiguration(admin, configBackup);
        } catch (AuthorizationDeniedException e) {
            log.info("AlwaysAllowedToken was denied access while saving global configuration");
            e.printStackTrace();
        }
    }
    
    
    /**
     * Disables OCSP protocol and then runs a simple OCSP access test which will expect status code 403
     * when service is disabled by configuration.
     * @throws AuthorizationDeniedException 
     * @throws IOException 
     */
    @Test
    public void testOcsp() throws AuthorizationDeniedException, IOException {
        AvailableProtocolsConfiguration protocolConfig = (AvailableProtocolsConfiguration)globalConfigurationSession.
                getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
        protocolConfig.setProtocolStatus(AvailableProtocols.OCSP.getName(), false);
        globalConfigurationSession.saveConfiguration(admin, protocolConfig);
        
        HttpResponse resp = WebTestUtils.sendGetRequest(httpReqPath + AvailableProtocols.getContextPathByName(AvailableProtocols.OCSP.getName()));
        assertEquals("Unexpected response after disabling protocol", 403, resp.getStatusLine().getStatusCode());
        assertEquals(EXPECTED_403_REASON, resp.getStatusLine().getReasonPhrase());
    }
    
    /**
     * Disables SCEP protocol and then runs a simple SCEP access test which will expect status 403 when
     * service is disabled by configuration.
     * @throws AuthorizationDeniedException 
     * @throws IOException 
     */
    @Test
    public void testScep() throws AuthorizationDeniedException, IOException {
        AvailableProtocolsConfiguration protocolConfig = (AvailableProtocolsConfiguration)globalConfigurationSession.
                getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
        protocolConfig.setProtocolStatus(AvailableProtocols.SCEP.getName(), false);
        globalConfigurationSession.saveConfiguration(admin, protocolConfig);
       
        HttpResponse resp = WebTestUtils.sendGetRequest(httpReqPath + AvailableProtocols.getContextPathByName(AvailableProtocols.SCEP.getName()));
        assertEquals("Unexpected response after disabling protocol", 403, resp.getStatusLine().getStatusCode());
        assertEquals(EXPECTED_403_REASON, resp.getStatusLine().getReasonPhrase());
    }
    
    /**
     * Disables Public Web and then runs a simple Public Web access test which will expect status 403 when
     * service is disabled by configuration.
     * @throws AuthorizationDeniedException 
     * @throws IOException 
     */
    @Test
    public void testPublicWeb() throws AuthorizationDeniedException, IOException {
        AvailableProtocolsConfiguration protocolConfig = (AvailableProtocolsConfiguration)globalConfigurationSession.
                getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
        protocolConfig.setProtocolStatus(AvailableProtocols.PUBLIC_WEB.getName(), false);
        globalConfigurationSession.saveConfiguration(admin, protocolConfig);
       
        HttpResponse resp = WebTestUtils.sendGetRequest(httpReqPath + AvailableProtocols.getContextPathByName(AvailableProtocols.PUBLIC_WEB.getName()));
        assertEquals("Unexpected response after disabling protocol", 403, resp.getStatusLine().getStatusCode());
        assertEquals(EXPECTED_403_REASON, resp.getStatusLine().getReasonPhrase());
    }
    
    /**
     * Disables RA Web and then runs a simple RA Web access test which will expect status 403 when
     * service is disabled by configuration.
     * @throws AuthorizationDeniedException 
     * @throws IOException 
     */
    @Test
    public void testRaWeb() throws AuthorizationDeniedException, IOException {
        AvailableProtocolsConfiguration protocolConfig = (AvailableProtocolsConfiguration)globalConfigurationSession.
                getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
        protocolConfig.setProtocolStatus(AvailableProtocols.RA_WEB.getName(), false);
        globalConfigurationSession.saveConfiguration(admin, protocolConfig);
       
        HttpResponse resp = WebTestUtils.sendGetRequest(httpReqPath + AvailableProtocols.getContextPathByName(AvailableProtocols.RA_WEB.getName()));
        assertEquals("Unexpected response after disabling protocol", 403, resp.getStatusLine().getStatusCode());
        assertEquals(EXPECTED_403_REASON, resp.getStatusLine().getReasonPhrase());
    }
    
    /**
     * Disables CMP protocol and then runs a simple CMP access test which will expect status 403 when
     * service is disabled by configuration.
     * @throws AuthorizationDeniedException 
     * @throws IOException 
     */
    @Test
    public void testCmp() throws AuthorizationDeniedException, IOException {
        AvailableProtocolsConfiguration protocolConfig = (AvailableProtocolsConfiguration)globalConfigurationSession.
                getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
        protocolConfig.setProtocolStatus(AvailableProtocols.CMP.getName(), false);
        globalConfigurationSession.saveConfiguration(admin, protocolConfig);
       
        HttpResponse resp = WebTestUtils.sendGetRequest(httpReqPath + AvailableProtocols.getContextPathByName(AvailableProtocols.CMP.getName()));
        assertEquals("Unexpected response after disabling protocol", 403, resp.getStatusLine().getStatusCode());
        assertEquals(EXPECTED_403_REASON, resp.getStatusLine().getReasonPhrase());
    }
    
    /**
     * Disables EST protocol and then runs a simple EST access test which will expect status 403 when
     * service is disabled by configuration.
     * @throws AuthorizationDeniedException 
     * @throws IOException 
     */
    @Test
    public void testEst() throws AuthorizationDeniedException, IOException {
        AvailableProtocolsConfiguration protocolConfig = (AvailableProtocolsConfiguration)globalConfigurationSession.
                getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
        protocolConfig.setProtocolStatus(AvailableProtocols.EST.getName(), false);
        globalConfigurationSession.saveConfiguration(admin, protocolConfig);
       
        HttpResponse resp = WebTestUtils.sendGetRequest(httpReqPath + AvailableProtocols.getContextPathByName(AvailableProtocols.EST.getName()));
        
        if (enterpriseEjbBridgeSession.isRunningEnterprise()) {
            assertEquals("Unexpected response after disabling protocol", 403, resp.getStatusLine().getStatusCode());
            assertEquals(EXPECTED_403_REASON, resp.getStatusLine().getReasonPhrase());
        } else {
            assertEquals("EST seems to be available in EJBCA CE", 404, resp.getStatusLine().getStatusCode());
        }
        
    }
    
    /**
     * Disables Web Dist and then runs a simple Web Dist access test which will expect status 403 when
     * service is disabled by configuration.
     * @throws AuthorizationDeniedException 
     * @throws IOException 
     */
    @Test
    public void testWebDist() throws AuthorizationDeniedException, IOException {
        AvailableProtocolsConfiguration protocolConfig = (AvailableProtocolsConfiguration)globalConfigurationSession.
                getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
        protocolConfig.setProtocolStatus(AvailableProtocols.WEB_DIST.getName(), false);
        globalConfigurationSession.saveConfiguration(admin, protocolConfig);
       
        HttpResponse resp = WebTestUtils.sendGetRequest(httpReqPath + AvailableProtocols.getContextPathByName(AvailableProtocols.WEB_DIST.getName()));
        assertEquals("Unexpected response after disabling protocol", 403, resp.getStatusLine().getStatusCode());
        assertEquals(EXPECTED_403_REASON, resp.getStatusLine().getReasonPhrase());
    }
    
    /**
     * Disables Ejbca Web Services and then runs a simple WS operation which will expect an exception to be thrown
     * when service is disabled by configuration
     * @throws Exception
     */
    @Test
    public void testWs() throws Exception {
        EjbcaException_Exception expectedException = null;
        EjbcaWSTest wsTest = new EjbcaWSTest();
        
        AvailableProtocolsConfiguration protocolConfig = (AvailableProtocolsConfiguration)globalConfigurationSession.
                getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
        protocolConfig.setProtocolStatus(AvailableProtocols.WS.getName(), false);
        globalConfigurationSession.saveConfiguration(admin, protocolConfig);
        
        try {
            EjbcaWSTest.beforeClass();
            wsTest.setUpAdmin();
            // Call some random WS method
            wsTest.test01EditUser();
            EjbcaWSTest.afterClass();
        } catch (EjbcaException_Exception e) {
            expectedException = e;
        }
        
        assertNotNull("Unexpected response after disabling protocol", expectedException);
        assertEquals(EXPECTED_WS_MESSAGE, expectedException.getMessage());
    }
}
