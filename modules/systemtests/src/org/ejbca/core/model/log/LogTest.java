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

package org.ejbca.core.model.log;

import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.core.ejb.log.LogConfigurationSessionRemote;
import org.cesecore.core.ejb.log.LogSessionRemote;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.util.InterfaceCache;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.LogMatch;
import org.ejbca.util.query.Query;

/**
 * Tests the log modules entity and session beans.
 *
 * @version $Id$
 */
public class LogTest extends CaTestCase {
    private static final Logger log = Logger.getLogger(LogTest.class);

    private final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    private LogConfigurationSessionRemote logConfigurationSession = InterfaceCache.getLogConfigurationSession();
    private LogSessionRemote logSession = InterfaceCache.getLogSession();
    private CAAdminSessionRemote caAdminSession = InterfaceCache.getCAAdminSession();
    
    /**
     * Creates a new TestLog object.
     *
     * @param name name
     */
    public LogTest(String name) {
        super(name);
    }

    public void setUp() throws Exception {
    }

    public void tearDown() throws Exception {
    }

    /**
     * tests adding a log configuration and checks if it can be read again.
     *
     * @throws Exception error
     */
    public void test01AddLogConfiguration() throws Exception {
        log.trace(">test01AddLogConfiguration()");
        assertTrue("Could not create TestCA.", createTestCA());
        
        LogConfiguration logconf = new LogConfiguration();
        logconf.setLogEvent(LogConstants.EVENT_INFO_DATABASE, false);
        logconf.setLogEvent(LogConstants.EVENT_ERROR_DATABASE, true);

        logSession.saveLogConfiguration(admin, getTestCAId(), logconf);

        LogConfiguration logconf2 = logConfigurationSession.loadLogConfiguration(getTestCAId());
        assertTrue("Couldn't retrieve correct log confirguration data from database.", !logconf2.getLogEvent(LogConstants.EVENT_INFO_DATABASE).booleanValue());
        assertTrue("Couldn't retrieve correct log confirguration data from database.", logconf2.getLogEvent(LogConstants.EVENT_ERROR_DATABASE).booleanValue());

        log.trace("<test01AddLogConfiguration()");
    }

    /**
     * tests adds some log events and checks that they have been stored
     * correctly.
     *
     * @throws Exception error
     */
    public void test02AddAndCheckLogEvents() throws Exception {
        log.trace(">test02AddAndCheckLogEvents()");
        logSession.log(admin, getTestCAId(), LogConstants.MODULE_LOG, new Date(), null, null, LogConstants.EVENT_ERROR_UNKNOWN, "Test");
        Collection<String> logDeviceNames = logSession.getAvailableLogDevices();
        Iterator<String> iterator = logDeviceNames.iterator();
        Collection<LogEntry> result = null;
        while (iterator.hasNext()) {
        	String logDeviceName = iterator.next();
        	if (logDeviceName.equalsIgnoreCase(Log4jLogDevice.DEFAULT_DEVICE_NAME)) {
        		continue;
        	}
        	Query query = new Query(Query.TYPE_LOGQUERY);
        	query.add(LogMatch.MATCH_WITH_COMMENT,BasicMatch.MATCH_TYPE_EQUALS,"Test");
        	result = logSession.query(logDeviceName, query, "", "caId=" + Integer.toString(getTestCAId()), 500);
        	Iterator<LogEntry> iter = result.iterator();
        	boolean found = false;
        	while (iter.hasNext()) {
        		LogEntry entry = iter.next();
        		if ( (entry.getComment() != null) && (entry.getComment().equals("Test")) ) {
        			found = true;
        		}
        	}
        	assertTrue("Couldn't retrieve correct log data from database.", found);
        }
 	   ILogExporter exporter = new CsvLogExporter();
 	   exporter.setEntries(result);
 	   Map<Class<?>, Object> ejbs = new HashMap<Class<?>, Object>();
 	   ejbs.put(CAAdminSession.class, caAdminSession);
 	   byte[] export = exporter.export(admin, ejbs);
	   assertNotNull("Nothing was exported!", export);
	   String str = new String(export);
	   //assertEquals("foo", str);
	   int ind = str.indexOf("\tTest");
	   assertTrue(ind > 0);
	   log.trace("<test02AddAndCheckLogEvents()");
    }

    /**
     * Test of the cache of LogConfiguration. This test depends on the default cache time of 5 second being used.
     * If you changed this config, logconfiguration.cachetime, this test may fail. 
     */
    public void test03LogConfigurationCache() throws Exception {
    	log.trace(">test03LogConfigurationCache()");
    	// First a check that we have the correct configuration, i.e. default
    	long cachetime = EjbcaConfiguration.getCacheLogConfigurationTime();
    	assertEquals(5000, cachetime);

    	// Load LogConfiguration
    	LogConfiguration config = logConfigurationSession.loadLogConfiguration(getTestCAId());
    	assertNotNull(config);
    	assertTrue("Needs a fresh LogConfiguration for this test to work.", config.useExternalLogDevices()); // default value
        // Flush caches to reset cache timeout
    	logConfigurationSession.flushConfigurationCache();
    	// Save our object to update the cache we just flushed (a load would also work here..)
    	logConfigurationSession.saveLogConfiguration(getTestCAId(), config, true);
    	// Change config, not flushing cache
    	config.setUseExternalLogDevices(false);
    	logConfigurationSession.saveLogConfiguration(getTestCAId(), config, false);
    	// read config again, value should not be changed because it is cached
    	config = logConfigurationSession.loadLogConfiguration(getTestCAId());
    	assertTrue("LogConfiguration cache was updated immediately.", config.useExternalLogDevices()); 
    	
    	// Wait 6 seconds and try again, now the cache should have been updated
    	Thread.sleep(6000);
    	config = logConfigurationSession.loadLogConfiguration(getTestCAId());
    	assertFalse("LogConfiguration cache did not expire as expected.", config.useExternalLogDevices()); 

        // Changing using the regular method however should immediately flush the cache
    	config.setUseExternalLogDevices(true);
    	logSession.saveLogConfiguration(admin, getTestCAId(), config);
    	config = logConfigurationSession.loadLogConfiguration(getTestCAId());
    	assertTrue("LogConfiguration cache was not updated immediately.", config.useExternalLogDevices()); 
    	log.trace("<test03LogConfigurationCache()");
    }
    
    /**
     * Test that log entries for OldLogDevice are persisted even if a the main transaction rolls back.
     * @throws IllegalQueryException 
     */
    public void test04rollback() throws IllegalQueryException {
    	Date now = new Date();
    	try {
    		logSession.testRollback(now.getTime());
    		assertTrue("test of rollback did not throw an exception as expected.", false);
    	} catch (Exception e) {
    		log.debug("Got an exception as expected: " + e.getMessage());
    	}
        Iterator<String> iterator = logSession.getAvailableLogDevices().iterator();
        Collection<LogEntry> result = null;
        while (iterator.hasNext()) {
        	String logDeviceName = iterator.next();
        	if (logDeviceName.equalsIgnoreCase(Log4jLogDevice.DEFAULT_DEVICE_NAME)) {
        		continue;
        	}
        	Query query = new Query(Query.TYPE_LOGQUERY);
        	query.add(LogMatch.MATCH_WITH_COMMENT, BasicMatch.MATCH_TYPE_EQUALS, "Test of rollback resistance of log-system.");
        	result = logSession.query(logDeviceName, query, "", "caId=" + 0, 500);
        	Iterator<LogEntry> iter = result.iterator();
        	boolean found = false;
        	while (iter.hasNext()) {
        		LogEntry entry = iter.next();
        		if ( (entry.getTime() != null) && (entry.getTime().equals(now)) ) {
        			found = true;
        		}
        	}
        	assertTrue("Log entry has been rolled back.", found);
        }
    }

	public void test99RemoveTestCA() throws Exception {
		removeTestCA();
	}
}
