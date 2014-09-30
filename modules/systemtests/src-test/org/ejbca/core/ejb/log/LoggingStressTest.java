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

package org.ejbca.core.ejb.log;

import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionRemote;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Stress test security audit logging. (This will not measure real performance we run over RMI.) 
 * 
 * @version $Id$
 */
public class LoggingStressTest {
	
	private static Logger log = Logger.getLogger(LoggingStressTest.class);
	
	private static final int NUMBER_OF_THREADS = 20; 
	private static final int TIME_TO_RUN = 15*60000; // Run for 15 minutes

	@Before
    public void setUp() throws Exception {
    }

	@After
    public void tearDown() throws Exception {
    }

	@Test
    public void test01LogALot() throws Exception {
		ArrayList<Thread> threads = new ArrayList<Thread>(); // NOPMD, it's not a JEE app
		for (int i=0; i<NUMBER_OF_THREADS; i++) {
	        Thread thread = new Thread(new LogTester(i, TIME_TO_RUN), "LogTester-"+i); // NOPMD, it's not a JEE app
	        thread.start();
	        log.info("Started LogTester-"+i);
	        threads.add(thread);
		}
		for (Thread thread : threads) { // NOPMD, it's not a JEE app
			thread.join();
		}
    }
    
    private class LogTester implements Runnable { // NOPMD, it's not a JEE app
    	
    	private long runTime = 0;
    	private long startTime = 0;
    	private int threadId = 0;
    	
    	private SecurityEventsLoggerSessionRemote securityEventsLoggerSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SecurityEventsLoggerSessionRemote.class);

    	LogTester(int threadId, long runTime) {
    		this.threadId = threadId;
    		this.startTime = new Date().getTime();
    		this.runTime = runTime;
    	}
    	
    	AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("LogTester"));
    	public void run() {
            try {
            	int i = 0;
            	long delta = 0;
            	final Map<String, Object> details = new HashMap<String, Object>();
            	details.put("msg", "This log entry was produced by " + LoggingStressTest.class.getSimpleName());
            	while ((delta = System.currentTimeMillis() - startTime) < runTime) {
            		securityEventsLoggerSession.log(internalAdmin, EjbcaEventTypes.CUSTOMLOG_INFO, EventStatus.VOID, EjbcaModuleTypes.CUSTOM, EjbcaServiceTypes.EJBCA, null, null, null, details);
                	i++;
                	if (((delta * 100) / runTime) % 10 == 0) {
                		log.info(threadId+" has logged "+i+" events.");
                	}
                	Thread.yield();
            	}
                log.info("\nThread "+threadId+" finished in "+((delta)/1000) + "."+((delta)%1000)+" seconds.");
                log.info("Throughput: "+(i/(delta/1000)) + "." + (i%(delta/1000)) + " log-invocations/second.");
			} catch (Exception e) {
				e.printStackTrace();
            	assertTrue(false);
			}    		
    	}
    }
}
