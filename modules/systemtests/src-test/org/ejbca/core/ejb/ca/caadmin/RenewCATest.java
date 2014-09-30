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

package org.ejbca.core.ejb.ca.caadmin;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * @version $Id$
 */
public class RenewCATest extends CaTestCase {
    private static final Logger log = Logger.getLogger(RenewCATest.class);
    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("RenewCATest"));

    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);

    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }
    
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

    /** Test renewal of a CA. */
    @Test
    public void test01renewCA() throws Exception {
        log.trace(">test01renewCA()");
        X509CAInfo info = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TEST");
        X509Certificate orgcert = (X509Certificate) info.getCertificateChain().iterator().next();
        // Sleep at least for one second so we are not so fast that we create a new cert with the same time
        Thread.sleep(2000);
        caAdminSession.renewCA(internalAdmin, info.getCAId(), false, null, false);
        X509CAInfo newinfo = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TEST");
        X509Certificate newcertsamekeys = (X509Certificate) newinfo.getCertificateChain().iterator().next();
        assertTrue(!orgcert.getSerialNumber().equals(newcertsamekeys.getSerialNumber()));
        byte[] orgkey = orgcert.getPublicKey().getEncoded();
        byte[] samekey = newcertsamekeys.getPublicKey().getEncoded();
        assertTrue(Arrays.equals(orgkey, samekey));
        // The new certificate must have a validity greater than the old cert
        assertTrue("newcertsamekeys.getNotAfter: " + newcertsamekeys.getNotAfter() + " orgcert.getNotAfter: " + orgcert.getNotAfter(),
                newcertsamekeys.getNotAfter().after(orgcert.getNotAfter()));
        caAdminSession.renewCA(internalAdmin, info.getCAId(), true, null, false);
        X509CAInfo newinfo2 = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TEST");
        X509Certificate newcertnewkeys = (X509Certificate) newinfo2.getCertificateChain().iterator().next();
        assertTrue(!orgcert.getSerialNumber().equals(newcertnewkeys.getSerialNumber()));
        byte[] newkey = newcertnewkeys.getPublicKey().getEncoded();
        assertFalse(Arrays.equals(orgkey, newkey));
        log.trace("<test01renewCA()");
    }
}
