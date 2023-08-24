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

package org.ejbca.core.ejb.ra;

import org.apache.log4j.Logger;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.Test;

/** 
 * This test is meant to be used as "ant test:runone -Dtest.runone=" before all the systemtests run to test redacted log.<br>
 * We need to set "enable.log.redact=true" at systemtest.properties to allow the functionality.<br>
 * This ensures other systemtests especially the ones meant for testing audit log redaction are not affected.
 */
public class EnableGlobalPiiDataRedactionTest {
    
    private static final Logger log = Logger.getLogger(EnableGlobalPiiDataRedactionTest.class);
        
    protected static final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);   
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken("EnableGlobalPiiDataRedactionTest");
    
    @Test
    public void setRedactEnforced() throws Exception {
        if (!SystemTestsConfiguration.getEnableLogRedact()) {
            return;
        }
       GlobalCesecoreConfiguration globalCesecoreConfiguration = (GlobalCesecoreConfiguration)
                globalConfigurationSession.getCachedConfiguration(GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
       globalCesecoreConfiguration.setRedactPiiEnforced(true);
       globalConfigurationSession.saveConfiguration(admin, globalCesecoreConfiguration);
    }
}
