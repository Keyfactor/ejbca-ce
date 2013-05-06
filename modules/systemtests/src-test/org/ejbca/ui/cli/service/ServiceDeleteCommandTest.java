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
package org.ejbca.ui.cli.service;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.TraceLogMethodsRule;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * System test class for ServiceDeleteCommand
 * 
 * @version $Id$
 */
public class ServiceDeleteCommandTest extends ServiceTestCase {
    
    @org.junit.Rule
    public org.junit.rules.TestRule traceLogMethodsRule = new TraceLogMethodsRule();
    
    private ServiceDeleteCommand serviceDeleteCommand;
    private static final String SERVICE_NAME = "TestServiceCLIDelete";
    
    private static final String[] DELETE_ARGS = { "delete", SERVICE_NAME };
    private static final String[] NONEXISTENT_ARGS = { "delete", "TestServiceShouldNotExist" };
    private static final String[] MISSING_NAME_ARGS = { "delete" };
    
    @Before
    public void setUp() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        serviceDeleteCommand = new ServiceDeleteCommand();
        getServiceSession().removeService(getAdmin(), SERVICE_NAME);
        
        ServiceConfiguration sc = new ServiceConfiguration();
        getServiceSession().addService(getAdmin(), SERVICE_NAME, sc);
    }

    @After
    public void tearDown() throws Exception {
        getServiceSession().removeService(getAdmin(), SERVICE_NAME);
    }
    
    @Test
    public void testExecuteDelete() throws ErrorAdminCommandException {
        assertNotNull("service should have been created", getServiceSession().getService(SERVICE_NAME));
        serviceDeleteCommand.execute(DELETE_ARGS);
        assertNull("service should have been deleted", getServiceSession().getService(SERVICE_NAME));
    }
    
    @Test
    public void testExecuteMissingName() throws ErrorAdminCommandException {
        // should log an error
        serviceDeleteCommand.execute(MISSING_NAME_ARGS);
    }
    
    @Test
    public void testExecuteNonExistent() throws ErrorAdminCommandException {
        // should log an error
        serviceDeleteCommand.execute(NONEXISTENT_ARGS);
        assertNotNull("service should still exist", getServiceSession().getService(SERVICE_NAME));
    }
    
}
