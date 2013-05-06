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

import static org.junit.Assert.assertEquals;

import java.util.Properties;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.TraceLogMethodsRule;
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
    
    private static final String[] EDIT_EMPTY_ARGS = { "edit", SERVICE_NAME };
    private static final String[] EDIT_BOOL_ARGS = { "edit", SERVICE_NAME, "active=false" };
    private static final String[] EDIT_LIST_ARGS = { "edit", SERVICE_NAME, "pinToNodes=10.0.0.1,10.0.0.2" };
    private static final String[] EDIT_CLASSPATH_ARGS = { "edit", SERVICE_NAME, "intervalClassPath=org.ejbca.core.model.services.intervals.PeriodicalInterval" };
    private static final String[] EDIT_PROPERTY_ARGS = { "edit", SERVICE_NAME, "worker.timebeforeexpiring=2000" };
    private static final String[] LIST_FIELDS_ARGS = { "edit", SERVICE_NAME, "-listFields" };
    private static final String[] LIST_PROPERTIES_ARGS = { "edit", SERVICE_NAME, "-listProperties" };
    private static final String[] NONEXISTENT_ARGS = { "edit", "TestServiceShouldNotExist" };
    private static final String[] MISSING_NAME_ARGS = { "edit" };
    
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
    public void testExecuteHappyPathEmpty() throws ErrorAdminCommandException {
        serviceEditCommand.execute(EDIT_EMPTY_ARGS);
    }
    
    @Test
    public void testExecuteHappyPathArgs() throws ErrorAdminCommandException {
        serviceEditCommand.execute(EDIT_BOOL_ARGS);
        serviceEditCommand.execute(EDIT_LIST_ARGS);
        serviceEditCommand.execute(EDIT_CLASSPATH_ARGS);
        serviceEditCommand.execute(EDIT_PROPERTY_ARGS);
        
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
    public void testExecuteMissingName() throws ErrorAdminCommandException {
        // should log an error
        serviceEditCommand.execute(MISSING_NAME_ARGS);
    }
    
    @Test
    public void testExecuteNonExistent() throws ErrorAdminCommandException {
        // should log an error
        serviceEditCommand.execute(NONEXISTENT_ARGS);
    }
    
    @Test
    public void testExecuteList() throws ErrorAdminCommandException {
        // should not modify anything, just list the available fields/properties
        serviceEditCommand.execute(LIST_FIELDS_ARGS);
        serviceEditCommand.execute(LIST_PROPERTIES_ARGS);
    }
    
}
