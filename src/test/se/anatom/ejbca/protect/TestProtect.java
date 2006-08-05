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

package se.anatom.ejbca.protect;

import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;

import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.protect.TableProtectSessionHome;
import org.ejbca.core.ejb.protect.TableProtectSessionRemote;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogEntry;
import org.ejbca.core.model.protect.TableVerifyResult;

/**
 * Tests the log modules entity and session beans.
 *
 * @version $Id: TestProtect.java,v 1.1 2006-08-05 09:59:53 anatom Exp $
 */
public class TestProtect extends TestCase {
    private static Logger log = Logger.getLogger(TestProtect.class);

    private TableProtectSessionRemote cacheAdmin = null;

    private static TableProtectSessionHome cacheHome = null;
    
    private static ArrayList entrys = null;

    private Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    /**
     * Creates a new TestLog object.
     *
     * @param name name
     */
    public TestProtect(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        log.debug(">setUp()");
        if (cacheAdmin == null) {
            if (cacheHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup("TableProtectSession");
                cacheHome = (TableProtectSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, TableProtectSessionHome.class);

            }
            cacheAdmin = cacheHome.create();
        }
        if (entrys == null) createLogEntrys();
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

    private void createLogEntrys() {
    	entrys = new ArrayList();
        Random rand = new Random();
        LogEntry le1 = new LogEntry(rand.nextInt(),Admin.TYPE_INTERNALUSER, "12345", -1, LogEntry.MODULE_CA, new Date(2), "foo", "123456", LogEntry.EVENT_ERROR_ADDEDENDENTITY, "foo comment 1");
        LogEntry le2 = new LogEntry(rand.nextInt(),Admin.TYPE_INTERNALUSER, "12345", -1, LogEntry.MODULE_CA, new Date(3), "foo", "123456", LogEntry.EVENT_ERROR_ADDEDENDENTITY, "foo comment 2");
        LogEntry le3 = new LogEntry(rand.nextInt(),Admin.TYPE_INTERNALUSER, "12345", -1, LogEntry.MODULE_CA, new Date(4), "foo", "123456", LogEntry.EVENT_ERROR_ADDEDENDENTITY, "foo comment 3");
        LogEntry le4 = new LogEntry(rand.nextInt(),Admin.TYPE_INTERNALUSER, "12345", -1, LogEntry.MODULE_CA, new Date(5), "foo", "123456", LogEntry.EVENT_ERROR_ADDEDENDENTITY, "foo comment 4");
        LogEntry le5 = new LogEntry(rand.nextInt(),Admin.TYPE_INTERNALUSER, "12345", -1, LogEntry.MODULE_CA, new Date(6), "foo", "123456", LogEntry.EVENT_ERROR_ADDEDENDENTITY, "foo comment 5");
        entrys.add(le1);
        entrys.add(le2);
        entrys.add(le3);
        entrys.add(le4);
        entrys.add(le5);
    }

    /**
     * tests adding protection to a log event.
     *
     * @throws Exception error
     */
    public void test01Protect() throws Exception {
        log.debug(">test01Protect()");
        Iterator iter = entrys.iterator();
        while (iter.hasNext()) {
        	LogEntry le = (LogEntry)iter.next();
            cacheAdmin.protect(admin, le);        	
        }
        log.debug("<test01Protect()");
    }

    /**
     * tests verify protection for a log event
     *
     * @throws Exception error
     */
    public void test02Verify() throws Exception {
        log.debug(">test02Verify()");
        Iterator iter = entrys.iterator();
        while (iter.hasNext()) {
        	LogEntry le = (LogEntry)iter.next();
            TableVerifyResult res = cacheAdmin.verify(le);
            assertEquals(res.getResultCode(), TableVerifyResult.VERIFY_SUCCESS);
        }
        LogEntry le = (LogEntry)entrys.get(2);
        LogEntry le1 = new LogEntry(le.getId(), le.getAdminType(), le.getAdminData(), le.getCAId(), le.getModule(), le.getTime(), le.getUsername(), le.getCertificateSNR(), le.getEvent(), "modified");
        entrys.set(2, le1);
        iter = entrys.iterator();
        while (iter.hasNext()) {
        	LogEntry le2 = (LogEntry)iter.next();
            TableVerifyResult res = cacheAdmin.verify(le2);
            if (le2.getId() == le.getId()) {
                assertEquals(res.getResultCode(), TableVerifyResult.VERIFY_FAILED);            	
            } else {
                assertEquals(res.getResultCode(), TableVerifyResult.VERIFY_SUCCESS);            	            	
            }
        }
        le1 = new LogEntry(le.getId(), le.getAdminType(), le.getAdminData(), le.getCAId(), le.getModule(), le.getTime(), le.getUsername(), le.getCertificateSNR(), le.getEvent(), le.getComment());
        entrys.set(2, le1);
        le = (LogEntry)entrys.get(3);
        le1 = new LogEntry(le.getId(), le.getAdminType(), le.getAdminData(), le.getCAId(), le.getModule(), le.getTime(), le.getUsername(), le.getCertificateSNR(), LogEntry.EVENT_INFO_CAEDITED, le.getComment());
        entrys.set(3, le1);
        iter = entrys.iterator();
        while (iter.hasNext()) {
        	LogEntry le2 = (LogEntry)iter.next();
            TableVerifyResult res = cacheAdmin.verify(le2);
            if (le2.getId() == le.getId()) {
                assertEquals(res.getResultCode(), TableVerifyResult.VERIFY_FAILED);            	
            } else {
                assertEquals(res.getResultCode(), TableVerifyResult.VERIFY_SUCCESS);            	            	
            }
        }
        le1 = new LogEntry(le.getId(), le.getAdminType(), le.getAdminData(), le.getCAId(), le.getModule(), le.getTime(), le.getUsername(), le.getCertificateSNR(), le.getEvent(), le.getComment());
        entrys.set(3, le1);
        le = (LogEntry)entrys.get(4);
        le1 = new LogEntry(le.getId(), le.getAdminType(), le.getAdminData(), le.getCAId(), le.getModule(), new Date(), le.getUsername(), le.getCertificateSNR(), LogEntry.EVENT_INFO_CAEDITED, le.getComment());
        entrys.set(4, le1);
        iter = entrys.iterator();
        while (iter.hasNext()) {
        	LogEntry le2 = (LogEntry)iter.next();
            TableVerifyResult res = cacheAdmin.verify(le2);
            if (le2.getId() == le.getId()) {
                assertEquals(res.getResultCode(), TableVerifyResult.VERIFY_FAILED);            	
            } else {
                assertEquals(res.getResultCode(), TableVerifyResult.VERIFY_SUCCESS);            	            	
            }
        }
        
        log.debug("<test02Verify()");
    }
}
