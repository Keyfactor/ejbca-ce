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
import static org.junit.Assume.assumeTrue;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests and removes the CA entity and its CryptoToken.
 * 
 * @version $Id$
 */
public class RemoveCATest extends CaTestCase {
    private static final Logger log = Logger.getLogger(RemoveCATest.class);
    private static final AuthenticationToken alwaysAllowAuthenticationToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(RemoveCATest.class.getSimpleName()));

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }
    
    @Test
    public void test02removeRSACA() throws Exception {
        log.trace(">test02removeRSACA()");
        removeTestCA("TEST");
        log.trace("<test02removeRSACA()");
    }

    @Test
    public void test03removeECDSACA() throws Exception {
        removeCa("CN=TESTECDSA");
    }

    @Test
    public void test03removeECDSAImplicitlyCA() throws Exception {
        removeCa("CN=TESTECDSAImplicitlyCA");
    }

    @Test
    public void test03primRemoveECGOST3410CA() throws Exception {
        assumeTrue(AlgorithmTools.isGost3410Enabled());
        removeCa("CN=TESTECGOST3410");
    }
    
    @Test
    public void test03bisRemoveDSTU4145CA() throws Exception {
        assumeTrue(AlgorithmTools.isDstu4145Enabled());
        removeCa("CN=TESTDSTU4145");
    }

    @Test
    public void test04removeRSASha256WithMGF1CA() throws Exception {
        removeCa("CN=TESTSha256WithMGF1");
    }

    @Test
    public void test05removeRSACA4096() throws Exception {
        removeCa("CN=TESTRSA4096,OU=FooBaaaaaar veeeeeeeery long ou,OU=Another very long very very long ou,"
                + "O=FoorBar Very looong O,L=Lets ad a loooooooooooooooooong Locality as well,C=SE");
    }

    @Test
    public void test06removeRSACAReverse() throws Exception {
        removeCa("CN=TESTRSAReverse,O=FooBar,OU=BarFoo,C=SE");
    }

    @Test
    public void test07removeCVCCA01() throws Exception {
        removeCa("CN=TESTCVCA,C=SE");
    }

    @Test
    public void test07removeCVCCA02() throws Exception {
        removeCa("CN=TESTDV-D,C=SE");
    }

    @Test
    public void test07removeCVCCA03() throws Exception {
        removeCa("CN=TESTDV-F,C=FI");
    }

    @Test
    public void test07removeCVCCA04() throws Exception {
        removeCa("CN=TCVCAEC,C=SE");
    }

    @Test
    public void test07removeCVCCA05() throws Exception {
        removeCa("CN=TDVEC-D,C=SE");
    }

    @Test
    public void test07removeCVCCA06() throws Exception {
        removeCa("CN=TDVEC-F,C=FI");
    }

    @Test
    public void test07removeCVCCA07() throws Exception {
        log.trace(">" + Thread.currentThread().getStackTrace()[1].getMethodName());
        try {
            certificateProfileSession.removeCertificateProfile(alwaysAllowAuthenticationToken, "TESTCVCDV");
        } catch (Exception e) {
            log.info("Remove profile failed: ", e);
        }
        log.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
    }

    @Test
    public void test09removeRSASignedByExternal() throws Exception {
        removeCa("CN=TESTSIGNEDBYEXTERNAL");
    }

    @Test
    public void test10removeDSACA() throws Exception {
        removeCa("CN=TESTDSA");
    }

    @Test
    public void test11removeRevokeCA() throws Exception {
        removeCa("CN=TestRevokeCA");
    }

    private void removeCa(String dn) {
        // Log trace with calling methods name
        log.trace(">" + Thread.currentThread().getStackTrace()[2].getMethodName());
        final int caid = CertTools.stringToBCDNString(dn).hashCode();
        try {
            removeTestCA(caid);
        } catch (AuthorizationDeniedException e) {
            throw new RuntimeException(e);
        }
        assertFalse("Removal of CA failed. " + caid + " still reported as existing.", caSession.getAllCaIds().contains(Integer.valueOf(caid)));
        // Log trace with calling methods name
        log.trace("<" + Thread.currentThread().getStackTrace()[2].getMethodName());
    }
}
