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

package se.anatom.ejbca.log;

import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;
import org.apache.log4j.Logger;
import se.anatom.ejbca.util.query.Query;

/**
 * Tests the log modules entity and session beans.
 *
 * @version $Id: TestLog.java,v 1.2 2005-02-11 13:12:28 anatom Exp $
 */
public class TestLog extends TestCase {
    private static Logger log = Logger.getLogger(TestLog.class);

    private ILogSessionRemote cacheAdmin;

    private static ILogSessionHome cacheHome;

    private Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    /**
     * Creates a new TestLog object.
     *
     * @param name name
     */
    public TestLog(String name) {
        super(name);
    }

    protected void setUp() throws Exception {

        log.debug(">setUp()");

        if (cacheAdmin == null) {
            if (cacheHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup("LogSession");
                cacheHome = (ILogSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ILogSessionHome.class);

            }

            cacheAdmin = cacheHome.create();
        }


        log.debug("<setUp()");
    }

    protected void tearDown() throws Exception {
    }

    private Context getInitialContext() throws NamingException {
        log.debug(">getInitialContext");

        Context ctx = new javax.naming.InitialContext();
        log.debug("<getInitialContext");

        return ctx;
    }


    /**
     * tests adding a log configuration and checks if it can be read again.
     *
     * @throws Exception error
     */
    public void test01AddLogConfiguration() throws Exception {
        log.debug(">test01AddLogConfiguration()");

        LogConfiguration logconf = new LogConfiguration();
        logconf.setLogEvent(LogEntry.EVENT_INFO_DATABASE, false);
        logconf.setLogEvent(LogEntry.EVENT_ERROR_DATABASE, true);

        cacheAdmin.saveLogConfiguration(admin, "CN=TEST".hashCode(), logconf);

        LogConfiguration logconf2 = cacheAdmin.loadLogConfiguration("CN=TEST".hashCode());
        assertTrue("Couldn't retrieve correct log confirguration data from database.", !logconf2.getLogEvent(LogEntry.EVENT_INFO_DATABASE).booleanValue());
        assertTrue("Couldn't retrieve correct log confirguration data from database.", logconf2.getLogEvent(LogEntry.EVENT_ERROR_DATABASE).booleanValue());

        log.debug("<test01AddLogConfiguration()");
    }

    /**
     * tests adds some log events and checks that they have been stored
     * correctly.
     *
     * @throws Exception error
     */
    public void test02AddAndCheckLogEvents() throws Exception {
        log.debug(">test02AddAndCheckLogEvents()");

        cacheAdmin.log(admin, "CN=TEST".hashCode(), LogEntry.MODULE_LOG, new Date(), null, null, LogEntry.EVENT_ERROR_UNKNOWN, "Test");


        Query query = new Query(Query.TYPE_LOGQUERY);
        query.add(new Date(0), new Date());
        Collection result = cacheAdmin.query(query, "", "caid=" + Integer.toString("CN=TEST".hashCode()));
        Iterator iter = result.iterator();
        boolean found = false;
        while (iter.hasNext()) {
            LogEntry entry = (LogEntry) iter.next();
            if (entry.getComment().equals("Test")) {
                found = true;
            }
        }

        assertTrue("Couldn't retrieve correct log data from database.", found);

        log.debug("<test02AddAndCheckLogEvents()");
    }


}
