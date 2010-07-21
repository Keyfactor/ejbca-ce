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

package org.ejbca.core.ejb.ca.caadmin;

import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.log.Admin;

/**
 * Tests and removes the ca data entity bean.
 *
 * @version $Id$
 */
public class RenewCATest extends CaTestCase {
    private static final Logger log = Logger.getLogger(RenewCATest.class);
    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    /**
     * Creates a new TestCAs object.
     *
     * @param name name
     */
    public RenewCATest(String name) {
        super(name);
        assertTrue("Could not create TestCA.", createTestCA());
    }

    public void setUp() throws Exception {
    }

    public void tearDown() throws Exception {
    }

    /**
     * renews CA.
     *
     * @throws Exception error
     */
    public void test01renewCA() throws Exception {
        log.trace(">test01renewCA()");

        X509CAInfo info = (X509CAInfo) caAdminSessionRemote.getCAInfo(admin, "TEST");
        X509Certificate orgcert = (X509Certificate) info.getCertificateChain().iterator().next();
        // Sleep at least for one second so we are not so fast that we create a new cert with the same time
        Thread.sleep(2000);
        caAdminSessionRemote.renewCA(admin,info.getCAId(),null,false);
        X509CAInfo newinfo = (X509CAInfo) caAdminSessionRemote.getCAInfo(admin, "TEST");
        X509Certificate newcertsamekeys = (X509Certificate) newinfo.getCertificateChain().iterator().next();
        assertTrue(!orgcert.getSerialNumber().equals(newcertsamekeys.getSerialNumber()));
        byte[] orgkey = orgcert.getPublicKey().getEncoded();
        byte[] samekey = newcertsamekeys.getPublicKey().getEncoded();
        assertTrue(Arrays.equals(orgkey,samekey));
        // The new certificate must have a validity greater than the old cert
        assertTrue("newcertsamekeys.getNotAfter: " + newcertsamekeys.getNotAfter() + " orgcert.getNotAfter: "+orgcert.getNotAfter(), newcertsamekeys.getNotAfter().after(orgcert.getNotAfter()));

        // This assumes that the default system keystore password is not changed from foo123
        caAdminSessionRemote.renewCA(admin,info.getCAId(),"foo123",true);
        X509CAInfo newinfo2 = (X509CAInfo) caAdminSessionRemote.getCAInfo(admin, "TEST");
        X509Certificate newcertnewkeys = (X509Certificate) newinfo2.getCertificateChain().iterator().next();
        assertTrue(!orgcert.getSerialNumber().equals(newcertnewkeys.getSerialNumber()));
        byte[] newkey = newcertnewkeys.getPublicKey().getEncoded();
        assertFalse(Arrays.equals(orgkey,newkey));        
        
        log.trace("<test01renewCA()");
    }

	public void test99RemoveTestCA() throws Exception {
		removeTestCA();
	}
}
