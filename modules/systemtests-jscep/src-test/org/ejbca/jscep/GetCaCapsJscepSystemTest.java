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
package org.ejbca.jscep;

import static org.junit.Assert.assertTrue;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;

import javax.security.auth.callback.CallbackHandler;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.config.ScepConfiguration;
import org.jscep.client.Client;
import org.jscep.client.DefaultCallbackHandler;
import org.jscep.client.verification.CertificateVerifier;
import org.jscep.client.verification.ConsoleCertificateVerifier;
import org.jscep.transport.response.Capabilities;
import org.jscep.transport.response.Capability;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.rules.TestRule;

/**
 * Bog standard SCEP tests for testing with jscep
 */

public class GetCaCapsJscepSystemTest extends JscepTestBase{

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("GetCaCapsJscepSystemTest"));

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();
    
    @Rule
    public TestName testName = new TestName();

    private GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);

    private String scepAlias;
    private ScepConfiguration scepConfiguration;
    
    @Before
    public void setup() throws AuthorizationDeniedException {
        scepAlias = testName.getMethodName();
        //Set up a SCEP alias
        scepConfiguration = (ScepConfiguration) globalConfigSession.getCachedConfiguration(ScepConfiguration.SCEP_CONFIGURATION_ID);
        scepConfiguration.addAlias(scepAlias);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);
    }
    
    @After
    public void tearDown() throws AuthorizationDeniedException {
        scepConfiguration.removeAlias(scepAlias);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);
    }
    
    @Test
    public void testGetCaCaps() throws MalformedURLException, URISyntaxException {
      //Set up jscep
        CertificateVerifier verifier = new ConsoleCertificateVerifier();
        CallbackHandler handler = new DefaultCallbackHandler(verifier);
        final URL url = getUrl(scepAlias);
        Client client = new Client(url, handler);
        Capabilities capabilities = client.getCaCapabilities();
        //Assert that EJBCA's standard caps are all there
        assertTrue(capabilities.contains(Capability.POST_PKI_OPERATION));
        assertTrue(capabilities.contains(Capability.RENEWAL));
        assertTrue(capabilities.contains(Capability.SHA_512));
        assertTrue(capabilities.contains(Capability.SHA_256));
        assertTrue(capabilities.contains(Capability.SHA_1));
        assertTrue(capabilities.contains(Capability.TRIPLE_DES));
        assertTrue(capabilities.contains(Capability.AES));
        assertTrue(capabilities.contains(Capability.SCEP_STANDARD));
    }
}
