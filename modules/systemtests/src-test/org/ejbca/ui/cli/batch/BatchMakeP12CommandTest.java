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

package org.ejbca.ui.cli.batch;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.NotFoundException;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/** Tests the batch making of soft cards.
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class BatchMakeP12CommandTest extends CaTestCase {
    private static final Logger log = Logger.getLogger(BatchMakeP12CommandTest.class);
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("BatchMakeP12Test"));
    private int caid = getTestCAId();

    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityAccessSessionRemote.class);

    private final String username1 = BatchMakeP12CommandTest.class.getSimpleName() + "1";
    private final String username2 = BatchMakeP12CommandTest.class.getSimpleName() + "2";

    @Before
    public void setUp() throws Exception {
        super.setUp();
        log.trace(">test01CreateNewUser()");
  
        endEntityManagementSession.addUser(admin, username1, "foo123", "C=SE, O=AnaTom, CN=" + username1, "", username1 + "@anatom.se", false,
                SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(),
                SecConst.TOKEN_SOFT_P12, 0, caid);
        endEntityManagementSession.setClearTextPassword(admin, username1, "foo123");

        log.debug("created " + username1 + ", pwd=foo123");
        assertEquals("end entity password wasn't set", "foo123", findPassword(username1));

        endEntityManagementSession.addUser(admin, username2, "foo123", "C=SE, O=AnaTom, CN=" + username2, "", username2 + "@anatom.se", false,
                SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(),
                SecConst.TOKEN_SOFT_P12, 0, caid);
        endEntityManagementSession.setClearTextPassword(admin, username2, "foo123");

        log.debug("created " + username2 + ", pwd=foo123");
        assertEquals("end entity password wasn't set", "foo123", findPassword(username2));
        log.trace("<test01CreateNewUsers()");
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        if (endEntityAccessSession.findUser(admin, username1) != null) {
            endEntityManagementSession.deleteUser(admin, username1);
        }
        if (endEntityAccessSession.findUser(admin, username2) != null) {
            endEntityManagementSession.deleteUser(admin, username2);
        }
    }


    /**
     * Tests creation of P12 file
     *
     * @throws Exception error
     */
    @Test
    public void testMakeP12All() throws Exception {
        BatchMakeP12Command makep12 = new BatchMakeP12Command();
        File tmpfile = File.createTempFile("ejbca", "p12");
        makep12.execute("-dir", tmpfile.getParent());
        assertTrue("No file was created.", tmpfile.exists());
        EndEntityInformation user1 = endEntityAccessSession.findUser(admin, username1);
        EndEntityInformation user2 = endEntityAccessSession.findUser(admin, username1);
        assertEquals("User1 was not generated.", EndEntityConstants.STATUS_GENERATED, user1.getStatus()); 
        assertEquals("User2 was not generated.", EndEntityConstants.STATUS_GENERATED, user2.getStatus()); 
    }

    @Test
    public void testMakeP12ForSingleUser() throws Exception {
        BatchMakeP12Command makep12 = new BatchMakeP12Command();
        File tmpfile = File.createTempFile("ejbca", "p12");
        makep12.execute("-dir", tmpfile.getParent(), "--username", username1);
        assertTrue("No file was created.", tmpfile.exists());
        EndEntityInformation user1 = endEntityAccessSession.findUser(admin, username1);
        assertEquals("User1 was not generated.", EndEntityConstants.STATUS_GENERATED, user1.getStatus()); 
    }

    
    /**
     * Gets the clear text password of a user.
     */
    private String findPassword(String user) throws Exception {
        EndEntityInformation ei = endEntityAccessSession.findUser(admin, user);
        if (ei == null) {
            throw new NotFoundException("coundn't find user \"" + user + "\"");
        }
        return ei.getPassword();
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }
}
