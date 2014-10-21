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
package org.ejbca.ui.cli.ocsp;

import static org.junit.Assert.assertEquals;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.config.GlobalOcspConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.Before;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class SetDefaultOcspResponderCommandTest {
    
    private SetDefaultOcspResponderCommand command;
    
    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    
    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken("SetDefaultOcspResponderCommandTest");
    
    @Before
    public void setup() {
        command = new SetDefaultOcspResponderCommand();
    }
    
    @Test
    public void testSetDefaultResponder() throws AuthorizationDeniedException {
        final String originalValue = ((GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID)).getOcspDefaultResponderReference();
        final String newValue = "CN=SetDefaultOcspResponderCommandTest";
        try {
            command.execute(newValue);
            GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            assertEquals("Default responder ID was not modified.", newValue, configuration.getOcspDefaultResponderReference());
        } finally {
            GlobalOcspConfiguration configuration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            configuration.setOcspDefaultResponderReference(originalValue);
            globalConfigurationSession.saveConfiguration(authenticationToken, configuration);
        }
        
    }
    
}
