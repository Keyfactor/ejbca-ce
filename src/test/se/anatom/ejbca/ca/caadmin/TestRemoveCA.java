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

package se.anatom.ejbca.ca.caadmin;

import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.log.Admin;

/**
 * Tests and removes the ca data entity bean.
 *
 * @version $Id: TestRemoveCA.java,v 1.3 2006-07-20 17:50:52 herrvendil Exp $
 */
public class TestRemoveCA extends TestCase {
    private static Logger log = Logger.getLogger(TestCAs.class);

    private ICAAdminSessionRemote cacheAdmin;


    private static ICAAdminSessionHome cacheHome;

    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    /**
     * Creates a new TestCAs object.
     *
     * @param name name
     */
    public TestRemoveCA(String name) {
        super(name);
    }

    protected void setUp() throws Exception {

        log.debug(">setUp()");

        if (cacheAdmin == null) {
            if (cacheHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup("CAAdminSession");
                cacheHome = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICAAdminSessionHome.class);
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
     * edits ca and checks that it's stored correctly.
     *
     * @throws Exception error
     */
    public void test01renewCA() throws Exception {
        log.debug(">test01renewCA()");

        X509CAInfo info = (X509CAInfo) cacheAdmin.getCAInfo(admin, "TEST");
        X509Certificate orgcert = (X509Certificate) info.getCertificateChain().iterator().next();
        
        cacheAdmin.renewCA(admin,info.getCAId(),null,false);
        X509CAInfo newinfo = (X509CAInfo) cacheAdmin.getCAInfo(admin, "TEST");
        X509Certificate newcertsamekeys = (X509Certificate) newinfo.getCertificateChain().iterator().next();
        assertTrue(!orgcert.getSerialNumber().equals(newcertsamekeys.getSerialNumber()));
        byte[] orgkey = orgcert.getPublicKey().getEncoded();
        byte[] samekey = newcertsamekeys.getPublicKey().getEncoded();
        assertTrue(Arrays.equals(orgkey,samekey));

        cacheAdmin.renewCA(admin,info.getCAId(),null,true);
        X509CAInfo newinfo2 = (X509CAInfo) cacheAdmin.getCAInfo(admin, "TEST");
        X509Certificate newcertnewkeys = (X509Certificate) newinfo2.getCertificateChain().iterator().next();
        assertTrue(!orgcert.getSerialNumber().equals(newcertnewkeys.getSerialNumber()));
        byte[] newkey = newcertnewkeys.getPublicKey().getEncoded();
        assertFalse(Arrays.equals(orgkey,newkey));        
        
        log.debug("<test01renewCA()");
    }

    /**
     * removes CA
     *
     * @throws Exception error
     */
    public void test02removeCA() throws Exception {
        log.debug(">test02removeCA()");
        boolean ret = false;
        try {
            cacheAdmin.removeCA(admin, "CN=TEST".hashCode());
            ret = true;
        } catch (Exception pee) {
        }
        assertTrue("Removing CA failed", ret);

        log.debug("<test02removeCA()");
    }


}
