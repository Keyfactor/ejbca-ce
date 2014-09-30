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
package org.ejbca.ui.cli.service;

import static org.junit.Assert.assertEquals;

import java.util.Properties;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * System test class for ServiceEditCommand
 * 
 * @version $Id$
 */
public class ServiceEditCommandTest extends ServiceTestCase {
    
    @org.junit.Rule
    public org.junit.rules.TestRule traceLogMethodsRule = new TraceLogMethodsRule();
    
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ServiceEditCommandTest"));
    private ServiceEditCommand serviceEditCommand;
    private static final String SERVICE_NAME = "TestServiceCLIEdit";
    
    private static final String[] EDIT_EMPTY_ARGS = { SERVICE_NAME };
    private static final String[] EDIT_BOOL_ARGS = { SERVICE_NAME, "active=false" };
    private static final String[] EDIT_LIST_ARGS = { SERVICE_NAME, "pinToNodes=10.0.0.1,10.0.0.2" };
    private static final String[] EDIT_CLASSPATH_ARGS = { SERVICE_NAME, "intervalClassPath=org.ejbca.core.model.services.intervals.PeriodicalInterval" };
    private static final String[] EDIT_PROPERTY_ARGS = { SERVICE_NAME, "worker.timebeforeexpiring=2000" };
    private static final String[] NONEXISTENT_ARGS = { "TestServiceShouldNotExist" };
    private static final String[] MISSING_NAME_ARGS = { };
    
    @Before
    public void setUp() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        serviceEditCommand = new ServiceEditCommand();
        getServiceSession().removeService(admin, SERVICE_NAME);
        
        ServiceConfiguration sc = new ServiceConfiguration();
        sc.setWorkerClassPath("org.ejbca.core.model.services.workers.CRLUpdateWorker");
        Properties props = new Properties();
        props.setProperty("worker.caidstocheck", "");
        props.setProperty("worker.certificateprofileidstocheck", "");
        props.setProperty("worker.timebeforeexpiring", "1000"); 
        props.setProperty("worker.timeunit", "DAYS");
        sc.setWorkerProperties(props);
        getServiceSession().addService(admin, SERVICE_NAME, sc);
    }

    @After
    public void tearDown() throws Exception {
        getServiceSession().removeService(admin, SERVICE_NAME);
    }
    
    @Test
    public void testExecuteHappyPathEmpty() {
        assertEquals(CommandResult.SUCCESS, serviceEditCommand.execute(EDIT_EMPTY_ARGS));
    }
    
    @Test
    public void testExecuteHappyPathArgs() {
        assertEquals(CommandResult.SUCCESS, serviceEditCommand.execute(EDIT_BOOL_ARGS));
        assertEquals(CommandResult.SUCCESS, serviceEditCommand.execute(EDIT_LIST_ARGS));
        assertEquals(CommandResult.SUCCESS, serviceEditCommand.execute(EDIT_CLASSPATH_ARGS));
        assertEquals(CommandResult.SUCCESS, serviceEditCommand.execute(EDIT_PROPERTY_ARGS));
        
        ServiceConfiguration sc = getServiceSession().getService(SERVICE_NAME);
        assertEquals("active", false, sc.isActive());
        assertEquals("workerClassPath", "org.ejbca.core.model.services.workers.CRLUpdateWorker", sc.getWorkerClassPath());
        assertEquals("intervalClassPath", "org.ejbca.core.model.services.intervals.PeriodicalInterval", sc.getIntervalClassPath());
        Properties props = sc.getWorkerProperties();
        assertEquals("worker.timebeforeexpiring", "2000", props.getProperty("worker.timebeforeexpiring"));
        String[] pinToNodes = sc.getPinToNodes();
        assertEquals("pinToNodes length", 2, pinToNodes.length);
        assertEquals("pinToNodes[0]", "10.0.0.1", pinToNodes[0]);
        assertEquals("pinToNodes[0]", "10.0.0.2", pinToNodes[1]);
    }
    
    @Test
    public void testExecuteMissingName() {
        // should log an error
        assertEquals(CommandResult.CLI_FAILURE, serviceEditCommand.execute(MISSING_NAME_ARGS));
    }
    
    @Test
    public void testExecuteNonExistent() {
        // should log an error
        assertEquals(CommandResult.FUNCTIONAL_FAILURE, serviceEditCommand.execute(NONEXISTENT_ARGS));
    }

    
}
