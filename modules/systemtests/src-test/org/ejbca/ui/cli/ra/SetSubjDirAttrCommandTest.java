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

import java.util.Collections;
import java.util.Date;

import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;

import static org.junit.Assert.assertEquals;

/**
 * @version $Id$
 *
 */
public class SetSubjDirAttrCommandTest {

    private static final String TESTCLASS_NAME = KeyRecoveryNewestCommandTest.class.getSimpleName();
    private static final String END_ENTITY_SUBJECT_DN = "C=SE, O=PrimeKey, CN=" + TESTCLASS_NAME;
    private static final String TEST_EEPROFILE = "SetSubjDirAttrCommandTest_EEP";
    private static final String TEST_CERTPROFILE = "SetSubjDirAttrCommandTest_CP";

    private SetSubjDirAttrCommand command = new SetSubjDirAttrCommand();

    private final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);

    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(TESTCLASS_NAME));

    private static X509CA x509ca = null;
    private int certificateProfileId;
    private int endEntityProfileId;

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProvider();
        x509ca = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(authenticationToken, "C=SE,CN=" + TESTCLASS_NAME);
    }

    @AfterClass
    public static void afterClass() throws Exception {
        if (x509ca != null) {
            CaTestUtils.removeCa(authenticationToken, x509ca.getCAInfo());
        }
    }

    @Before
    public void setup() throws Exception {
        cleanup();
        createProfiles();
        final EndEntityInformation userdata = new EndEntityInformation(TESTCLASS_NAME, END_ENTITY_SUBJECT_DN, x509ca.getCAId(), null, null,
                EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, new Date(), new Date(), SecConst.TOKEN_SOFT_P12, null);
        userdata.setPassword("foo123");
        userdata.setCertificateProfileId(certificateProfileId);
        userdata.setEndEntityProfileId(endEntityProfileId);
        endEntityManagementSession.addUser(authenticationToken, userdata, true);
        if (null == endEntityAccessSession.findUser(authenticationToken, TESTCLASS_NAME)) {
            throw new RuntimeException("Could not create end entity.");
        }
    }

    @After
    public void tearDown() throws Exception {
        cleanup();
    }

    private void createProfiles() throws Exception {
        final CertificateProfile certProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certProfile.setUseSubjectDirAttributes(true);
        certificateProfileId = certificateProfileSession.addCertificateProfile(authenticationToken, TEST_CERTPROFILE, certProfile);
        final EndEntityProfile eeProfile = new EndEntityProfile(true);
        eeProfile.setAvailableCertificateProfileIds(Collections.singletonList(certificateProfileId));
        eeProfile.setAvailableCAs(Collections.singletonList(x509ca.getCAId()));
        endEntityProfileId = endEntityProfileSession.addEndEntityProfile(authenticationToken, TEST_EEPROFILE, eeProfile );
    }
    
    private void cleanup() throws Exception {
        if (null != endEntityAccessSession.findUser(authenticationToken, TESTCLASS_NAME)) {
            endEntityManagementSession.deleteUser(authenticationToken, TESTCLASS_NAME);
        }
        endEntityProfileSession.removeEndEntityProfile(authenticationToken, TEST_EEPROFILE);
        certificateProfileSession.removeCertificateProfile(authenticationToken, TEST_CERTPROFILE);
    }

    @Test
    public void testSetSubjDirAttr() throws AuthorizationDeniedException {
        final String attributes = "placeOfBirth=FooTown";
        final String args[] = new String[] { TESTCLASS_NAME, attributes };
        command.execute(args);
        assertEquals("SubjDirAttributes were not set.", attributes, endEntityAccessSession.findUser(authenticationToken, TESTCLASS_NAME)
                .getExtendedInformation().getSubjectDirectoryAttributes());
    }
}
