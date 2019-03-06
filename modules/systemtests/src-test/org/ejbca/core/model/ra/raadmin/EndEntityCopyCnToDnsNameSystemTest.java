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
package org.ejbca.core.model.ra.raadmin;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Verify DNSname copied from CN for field with copy set to true
 * @version $Id$
 */
public class EndEntityCopyCnToDnsNameSystemTest extends CaTestCase {


    private static final Logger log = Logger.getLogger(EndEntityCopyCnToDnsNameSystemTest.class);


    private static final String TEST_CERTIFICATEPROFILE = "EndEntityCopyCnToDnsNameSystemTest_CP";
    private static final String TEST_ENDENTITYPROFILE = "EndEntityCopyCnToDnsNameSystemTest_EEP";
    private static final String TEST_ENDENTITY = "EndEntityCopyCnToDnsNameSystemTest_EE";
    private static final String TEST_PASSWORD = "foo123";
    private static final String EXPECTED_SAN = "DNSNAME=EndEntityCopyCnToDnsNameSystemTest_EE";
    private static final String USER_DOMAINNAME = "my.dns";
    private static final String USER_SAN = "DNSNAME="+USER_DOMAINNAME;

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EndEntityCopyCnToDnsNameSystemTest"));
    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);

    private InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class);
    private int certificateProfileId;
    private int endEntityProfileId;
    private KeyPair keys;

    @Override
    public String getRoleName() {
        return "EndEntityCopyCnToDnsNameSystemTest";
    }

    @Override
    @Before
    public void setUp() throws Exception {
        log.trace(">setUp");
        super.setUp();
        initialize();
        log.trace("<setUp");
    }

    @Override
    @After
    public void tearDown() throws Exception {
        log.trace(">tearDown");
        cleanup();
        super.tearDown();
        log.trace("<tearDown");
    }

    private void initialize() throws Exception {
        log.trace(">initialize");
        final int caId = getTestCAId();

        // Create Certificate Profile
        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_SERVER);
        certificateProfile.setAvailableCAs(new ArrayList<>(Collections.singletonList(caId)));
        certificateProfileId = certificateProfileSession.addCertificateProfile(admin, TEST_CERTIFICATEPROFILE, certificateProfile);
        // Create End Entity Profile
        final EndEntityProfile endEntityProfile = new EndEntityProfile();
        endEntityProfile.setDefaultCA(caId);
        endEntityProfile.setAvailableCAs(new ArrayList<>(Collections.singletonList(caId)));
        endEntityProfile.setDefaultCertificateProfile(certificateProfileId);
        endEntityProfile.setAvailableCertificateProfileIds(new ArrayList<>(Collections.singletonList(certificateProfileId)));
        endEntityProfile.addField(DnComponents.COMMONNAME);
        endEntityProfile.addField(DnComponents.DNSNAME);
        endEntityProfile.setCopy(DnComponents.DNSNAME, 0, true);
        endEntityProfile.addField(DnComponents.DNSNAME);
        endEntityProfileId = endEntityProfileSession.addEndEntityProfile(admin, TEST_ENDENTITYPROFILE, endEntityProfile);
        keys = KeyTools.genKeys("2048", "RSA");
        log.trace("<initialize");
    }

    private void cleanup() throws AuthorizationDeniedException {
        log.trace(">cleanup");
        endEntityProfileSession.removeEndEntityProfile(admin, TEST_ENDENTITYPROFILE);
        certificateProfileSession.removeCertificateProfile(admin, TEST_CERTIFICATEPROFILE);
        internalCertStoreSession.removeCertificatesByUsername(TEST_ENDENTITY);
        try {
            endEntityManagementSession.deleteUser(admin, TEST_ENDENTITY);
        } catch (CouldNotRemoveEndEntityException e) {
            log.info("Could not clean up end entity", e);
        } catch (NoSuchEndEntityException e) {
            // NOPMD Ignored
        }
        log.trace("<cleanup");
    }

    @Test
    public void addEndEntityOneDnsNameCopiedSecondIsEmpty() throws Exception {
        log.trace(">validationInApprovalPhase");
        // given
        final EndEntityInformation endEntity = new EndEntityInformation();
        endEntity.setUsername(TEST_ENDENTITY);
        endEntity.setPassword(TEST_PASSWORD);
        endEntity.setCAId(getTestCAId());
        endEntity.setCertificateProfileId(certificateProfileId);
        endEntity.setEndEntityProfileId(endEntityProfileId);
        endEntity.setTokenType(EndEntityConstants.TOKEN_SOFT_P12);
        endEntity.setDN("CN=" + TEST_ENDENTITY);
        endEntity.setType(EndEntityTypes.ENDUSER.toEndEntityType());
        // when
        endEntityManagementSession.addUserFromWS(admin, endEntity, false);
        EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(admin, TEST_ENDENTITY);
        signSession.createCertificate(admin, TEST_ENDENTITY, TEST_PASSWORD, new PublicKeyWrapper(keys.getPublic()));
        X509Certificate certificate = (X509Certificate) EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(TEST_ENDENTITY)).iterator().next();
        // then
        assertNotNull("End Entity Subject Alt name should not be empty", endEntityInformation.getSubjectAltName());
        assertEquals("Wrong Subject Alt Name for End Entity", EXPECTED_SAN, endEntityInformation.getSubjectAltName());

        assertNotNull("End Entity Certificate should not be empty", certificate);
        assertTrue("Subject alternative name should contain CN", certificate.getSubjectAlternativeNames().iterator().next().contains(TEST_ENDENTITY));
    }


    @Test
    public void addEndEntityOneDnsNameCopiedSecondUserValue() throws Exception {
        log.trace(">validationInApprovalPhase");
        // given
        final EndEntityInformation endEntity = new EndEntityInformation();
        endEntity.setUsername(TEST_ENDENTITY);
        endEntity.setPassword(TEST_PASSWORD);
        endEntity.setCAId(getTestCAId());
        endEntity.setCertificateProfileId(certificateProfileId);
        endEntity.setEndEntityProfileId(endEntityProfileId);
        endEntity.setTokenType(EndEntityConstants.TOKEN_SOFT_P12);
        endEntity.setDN("CN=" + TEST_ENDENTITY);
        endEntity.setSubjectAltName(USER_SAN);
        endEntity.setType(EndEntityTypes.ENDUSER.toEndEntityType());
        // when
        endEntityManagementSession.addUserFromWS(admin, endEntity, false);
        EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(admin, TEST_ENDENTITY);
        signSession.createCertificate(admin, TEST_ENDENTITY, TEST_PASSWORD, new PublicKeyWrapper(keys.getPublic()));
        X509Certificate certificate = (X509Certificate) EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(TEST_ENDENTITY)).iterator().next();
        // then
        assertNotNull("End Entity Subject Alt name should not be empty", endEntityInformation.getSubjectAltName());
        assertEquals("Wrong Subject Alt Name for End Entity", USER_SAN + ", " + EXPECTED_SAN, endEntityInformation.getSubjectAltName());

        assertNotNull("End Entity Certificate should not be empty", certificate);
        Iterator<List<?>> iterator = certificate.getSubjectAlternativeNames().iterator();
        assertTrue("Subject alternative name should contain User inserted Dns Name", iterator.next().contains(USER_DOMAINNAME));
        assertTrue("Subject alternative name should contain CN", iterator.next().contains(TEST_ENDENTITY));
    }
}
