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
package org.ejbca.ui.cli.ra;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import javax.ejb.RemoveException;

import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * System test class for RA renameendentity command
 * 
 * @version $Id$
 */
public class RenameEndEntityCommandTest {

    private static final String USER_NAME1 = "RenameEndEntityCommandTest_username1";
    private static final String USER_NAME2 = "RenameEndEntityCommandTest_username2";
    private static final String CA_NAME = "TestCA";
    private static final String[] HAPPY_PATH_RENAME_ARGS = { "--current", USER_NAME1, "--new", USER_NAME2 };

    private RenameEndEntityCommand renameEndEntityCommand;
    private CA testx509ca;
    private AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("RaSetPwdCommandTest"));

    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);

    @Before
    public void setUp() throws Exception {
        final int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        testx509ca = CaTestUtils.createTestX509CA("CN=" + CA_NAME, null, false, keyusage);
        caSession.addCA(admin, testx509ca);
        renameEndEntityCommand = new RenameEndEntityCommand();
    }
    
    @After
    public void tearDown() throws Exception {
        CryptoTokenTestUtils.removeCryptoToken(null, testx509ca.getCAToken().getCryptoTokenId());
        caSession.removeCA(admin, testx509ca.getCAId());
    }

    @Test
    public void testExecuteHappyPath() throws AuthorizationDeniedException, RemoveException, CADoesntExistsException, EndEntityExistsException,
            EndEntityProfileValidationException, WaitingForApprovalException, IllegalNameException, CertificateSerialNumberException, CustomFieldException, ApprovalException {
        endEntityManagementSession.addUser(admin, USER_NAME1, "foo123", "CN=" + USER_NAME1, null, null, true, SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0, testx509ca.getCAId());
        try {
            assertEquals(CommandResult.SUCCESS, renameEndEntityCommand.execute(HAPPY_PATH_RENAME_ARGS));
            final EndEntityInformation endEntityInformation1 = endEntityAccessSession.findUser(admin, USER_NAME1);
            assertNull("Renamed user should no longer exist under old username.", endEntityInformation1);
            final EndEntityInformation endEntityInformation2 = endEntityAccessSession.findUser(admin, USER_NAME2);
            assertNotNull("End entity should still exist after rename under the new username.", endEntityInformation2);
        } finally {
            try {
                endEntityManagementSession.deleteUser(admin, USER_NAME1);
            } catch (NoSuchEndEntityException e) {} // NOPMD: user does not exist, some error failed above           
            try {
                endEntityManagementSession.deleteUser(admin, USER_NAME2);
            } catch (NoSuchEndEntityException e) {} // NOPMD: user does not exist, some error failed above           
        }  
    }
}
