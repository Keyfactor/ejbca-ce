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

package org.ejbca.core.ejb.ra;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.ErrorCode;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.NoConflictCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.mock.authentication.tokens.UsernameBasedAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherProxySessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueProxySessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherTestSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileInformation;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.mock.publisher.MockedThrowAwayRevocationPublisher;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * Tests the EndEntityInformation entity bean and some parts of EndEntityManagementSession.
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EndEntityManagementSessionTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(EndEntityManagementSessionTest.class);
    
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken("EndEntityManagementSessionTest");
    private static final BigInteger THROWAWAY_CERT_SERIAL = new BigInteger("123456788A43197E", 16);
    private static final String THROWAWAY_CERT_PROFILE = EndEntityManagementSessionTest.class.getName()+"-ThrowAwayRevocationProfile";
    private static final String THROWAWAY_PUBLISHER = EndEntityManagementSessionTest.class.getName()+"-ThrowAwayRevocationPublisher";
    
    private int caid = getTestCAId();

    private static String username;
    private static String pwd;
    private static ArrayList<String> usernames = new ArrayList<>();
    private static String serialnumber;

    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);;
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private NoConflictCertificateStoreSessionRemote noConflictCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(NoConflictCertificateStoreSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private SimpleAuthenticationProviderSessionRemote simpleAuthenticationProvider = EjbRemoteHelper.INSTANCE.getRemoteSession(SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
    private GlobalConfigurationSessionRemote globalConfSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private PublisherSessionRemote publisherSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class);
    private PublisherProxySessionRemote publisherProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private PublisherTestSessionRemote publisherTestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private PublisherQueueProxySessionRemote publisherQueueSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherQueueProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        // Make user that we know later...
        username = genRandomUserName();
        pwd = genRandomPwd();
    }

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        for (final String username : usernames) {
            try {
                endEntityManagementSession.deleteUser(admin, username);
            } catch (Exception e) {
                // NOPMD, ignore errors so we don't stop deleting users because one of them does not exist.
            }
        }
        try {
            endEntityProfileSession.removeEndEntityProfile(admin, "TESTMERGEWITHWS");
        } catch (Exception e) {} // NOPMD, ignore errors
    }
    
    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

    private void genRandomSerialnumber() throws Exception {
        // Gen random number
        Random rand = new Random(new Date().getTime() + 4913);
        serialnumber = "";
        for (int i = 0; i < 8; i++) {
            int randint = rand.nextInt(9);
            serialnumber += (Integer.valueOf(randint)).toString();
        }
        log.debug("Generated random serialnumber: serialnumber =" + serialnumber);

    } // genRandomSerialnumber

    /**
     * tests creation of new user and duplicate user
     * 
     * @throws Exception error
     */
    private void addUser() throws Exception {
        log.trace(">addUser()");

        String email = username + "@anatom.se";
        endEntityManagementSession.addUser(admin, username, pwd, "C=SE, O=AnaTom, CN=" + username, "rfc822name=" + email, email, true,
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0, caid);
        usernames.add(username);
        log.debug("created user: " + username + ", " + pwd + ", C=SE, O=AnaTom, CN=" + username);
        // Add the same user again
        boolean userexists = false;
        try {
            endEntityManagementSession.addUser(admin, username, pwd, "C=SE, O=AnaTom, CN=" + username, "rfc822name=" + email, email, true,
                    EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0, caid);
        } catch (EndEntityExistsException e) {
            userexists = true; // This is what we want
        }
        assertTrue("Trying to create the same user twice didn't throw EndEntityExistsException", userexists);

        // try to add user with non-existing CA-id
        String username2 = genRandomUserName();
        int fakecaid = -1;
        boolean thrown = false;
        try {
            endEntityManagementSession.addUser(admin, username2, pwd, "C=SE, O=AnaTom, CN=" + username2, null, null, true, EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                    CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0, fakecaid);
            assertTrue(false);
        } catch (CADoesntExistsException e) {
            thrown = true;
        }
        assertTrue(thrown);

        log.trace("<addUser()");
    }
    
    private boolean setEnableEndEntityProfileLimitations(final boolean newValue) throws AuthorizationDeniedException {
        final GlobalConfiguration gc = (GlobalConfiguration) globalConfSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        final boolean previousValue = gc.getEnableEndEntityProfileLimitations();
        gc.setEnableEndEntityProfileLimitations(newValue);
        globalConfSession.saveConfiguration(admin, gc);
        return previousValue;
    }

    /**
     * tests creation of new user testing behavior of empty passwords
     * 
     * @throws Exception error
     */
    @Test
    public void testAddUserWithEmptyPwd() throws Exception {
        // First make sure we have end entity profile limitations enabled
        final boolean eelimitation = setEnableEndEntityProfileLimitations(true);
        final String eeprofileName = "TESTADDUSER";
        try {            
            // Add a new end entity profile, by default password is required and we should not be able to add a user with empty or null password.
            EndEntityProfile profile = new EndEntityProfile();
            profile.addField(DnComponents.COMMONNAME);
            profile.addField(DnComponents.COUNTRY);
            profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
            profile.setAllowMergeDnWebServices(true);
            // Profile will be removed in finally clause
            endEntityProfileSession.addEndEntityProfile(admin, eeprofileName, profile);
            int profileId = endEntityProfileSession.getEndEntityProfileId(eeprofileName);
            String thisusername = genRandomUserName();
            String email = thisusername + "@anatom.se";
            try {
                endEntityManagementSession.addUser(admin, thisusername, "", "C=SE, CN=" + thisusername, null, email, false,
                        profileId, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0, caid);
                usernames.add(thisusername);
                fail("User " + thisusername + " was added to the database although it should not have been.");
            } catch (EndEntityProfileValidationException e) {
                assertTrue("Error message should be about password", e.getMessage().contains("Password cannot be empty or null"));
            }
            try {
                endEntityManagementSession.addUser(admin, thisusername, null, "C=SE, CN=" + thisusername, null, email, false,
                        profileId, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0, caid);
                usernames.add(thisusername);
                fail("User " + thisusername + " was added to the database although it should not have been.");
            } catch (EndEntityProfileValidationException e) {
                assertTrue("Error message should be about password", e.getMessage().contains("Password cannot be empty or null"));
            }
            // Set required = false for password, then an empty password should be allowed
            profile.setRequired(EndEntityProfile.PASSWORD,0,false);
            endEntityProfileSession.changeEndEntityProfile(admin, eeprofileName, profile);
            try {
                endEntityManagementSession.addUser(admin, thisusername, "", "C=SE, CN=" + thisusername, null, email, false,
                        profileId, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0, caid);
                usernames.add(thisusername);
            } catch (EndEntityProfileValidationException e) {
                fail("User " + thisusername + " was not added to the database although it should have been.");
            }
            thisusername = genRandomUserName();
            email = thisusername + "@anatom.se";
            try {
                endEntityManagementSession.addUser(admin, thisusername, null, "C=SE, CN=" + thisusername, null, email, false,
                        profileId, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0, caid);
                usernames.add(thisusername);
            } catch (EndEntityProfileValidationException e) {
                fail("User " + thisusername + " was not added to the database although it should have been.");
            }
        } finally {
            setEnableEndEntityProfileLimitations(eelimitation);
            endEntityProfileSession.removeEndEntityProfile(admin, eeprofileName);
        }
    }
    
    /**
     * tests creation of new user with unique serialnumber
     * 
     * @throws Exception error
     */
    @Test
    public void test02AddUserWithUniqueDNSerialnumberAndChange() throws Exception {
        log.trace(">test02AddUserWithUniqueDNSerialnumber()");

        // Make user that we know later...
        String thisusername = genRandomUserName();
        String email = thisusername + "@anatom.se";
        genRandomSerialnumber();
        endEntityManagementSession.addUser(admin, thisusername, pwd, "C=SE, CN=" + thisusername + ", SN=" + serialnumber, "rfc822name=" + email, email, false,
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0, caid);
        assertTrue("User " + thisusername + " was not added to the database.", endEntityManagementSession.existsUser(thisusername));
        usernames.add(thisusername);

        // Set the CA to enforce unique subjectDN serialnumber
        CAInfo cainfo = caSession.getCAInfo(admin, caid);
        boolean requiredUniqueSerialnumber = cainfo.isDoEnforceUniqueSubjectDNSerialnumber();
        cainfo.setDoEnforceUniqueSubjectDNSerialnumber(true);
        caAdminSession.editCA(admin, cainfo);

        // Add another user with the same serialnumber
        thisusername = genRandomUserName();
        try {
            endEntityManagementSession.addUser(admin, thisusername, pwd, "C=SE, CN=" + thisusername + ", SN=" + serialnumber, "rfc822name=" + email, email,
                    false, EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0,
                    caid);
            usernames.add(thisusername);
        } catch (CertificateSerialNumberException e) {
            assertEquals(ErrorCode.SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS, e.getErrorCode());
        }
        assertFalse("Succeeded in adding another end entity with the same serialnumber", endEntityManagementSession.existsUser(thisusername));

        // Set the CA to NOT enforcing unique subjectDN serialnumber
        cainfo.setDoEnforceUniqueSubjectDNSerialnumber(false);
        caAdminSession.editCA(admin, cainfo);
        endEntityManagementSession.addUser(admin, thisusername, pwd, "C=SE, CN=" + thisusername + ", SN=" + serialnumber, "rfc822name=" + email, email, false,
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0, caid);
        assertTrue(endEntityManagementSession.existsUser(thisusername));
        usernames.add(thisusername);

        // Set the CA back to its original settings of enforcing unique
        // subjectDN serialnumber.
        cainfo.setDoEnforceUniqueSubjectDNSerialnumber(requiredUniqueSerialnumber);
        caAdminSession.editCA(admin, cainfo);

        log.trace("<test02AddUserWithUniqueDNSerialnumber()");
    

        // Make user that we know later...
        String secondUserName;
        if (usernames.size() > 1) {
            secondUserName = usernames.get(1);
        } else {
            secondUserName = username;
        }
        String secondEmail = secondUserName + username + "@anatomanatom.se";

        CAInfo secondCainfo = caSession.getCAInfo(admin, caid);
        boolean secondRequiredUniqueSerialnumber = secondCainfo.isDoEnforceUniqueSubjectDNSerialnumber();

        // Set the CA to enforce unique serialnumber
        cainfo.setDoEnforceUniqueSubjectDNSerialnumber(true);
        caAdminSession.editCA(admin, cainfo);    
        try {
            EndEntityInformation user = new EndEntityInformation(secondUserName, "C=SE, CN=" + secondUserName + ", SN=" + serialnumber, caid, "rfc822name=" + secondEmail, secondEmail,
                    new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);    
            endEntityManagementSession.changeUser(admin, user, false);
        } catch (CertificateSerialNumberException e) {
            assertEquals(ErrorCode.SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS, e.getErrorCode());
        }
        assertTrue("The user '" + secondUserName + "' was changed even though the serialnumber already exists.",
                endEntityAccessSession.findUserByEmail(admin, secondEmail).size() == 0);

        // Set the CA to NOT enforcing unique subjectDN serialnumber
        cainfo.setDoEnforceUniqueSubjectDNSerialnumber(false);
        caAdminSession.editCA(admin, cainfo);
        EndEntityInformation user = new EndEntityInformation(secondUserName, "C=SE, CN=" + secondUserName + ", SN=" + serialnumber, caid, "rfc822name=" + secondEmail, secondEmail,
                new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);    
        endEntityManagementSession.changeUser(admin, user, false);
        assertTrue("The user '" + thisusername + "' was not changed even though unique serialnumber is not enforced", endEntityAccessSession
                .findUserByEmail(admin, secondEmail).size() > 0);

        // Set the CA back to its original settings of enforcing unique
        // subjectDN serialnumber.
        cainfo.setDoEnforceUniqueSubjectDNSerialnumber(secondRequiredUniqueSerialnumber);
        caAdminSession.editCA(admin, secondCainfo);

        log.trace("<test03ChangeUserWithUniqueDNSerialnumber()");

    }

    /**
     * tests findUser and existsUser
     * 
     * @throws Exception error
     */
    @Test
    public void test03FindUser() throws Exception {
        addUser();

        log.trace(">test03FindUser()");
        EndEntityInformation data = endEntityAccessSession.findUser(admin, username);
        assertNotNull(data);
        assertEquals(username, data.getUsername());
        boolean exists = endEntityManagementSession.existsUser(username);
        assertTrue(exists);

        String notexistusername = genRandomUserName();
        exists = endEntityManagementSession.existsUser(notexistusername);
        assertFalse(exists);
        data = endEntityAccessSession.findUser(admin, notexistusername);
        assertNull(data);
        log.trace("<test03FindUser()");

    }

    /**
     * tests changeUser
     * 
     * @throws Exception error
     */
    @Test
    public void test04ChangeUser() throws Exception {
        addUser();

        log.trace(">test04ChangeUser()");
        EndEntityInformation data = endEntityAccessSession.findUser(admin, username);
        assertNotNull(data);
        assertEquals(username, data.getUsername());
        assertNull(data.getCardNumber());
        assertEquals(pwd, data.getPassword()); // Note that changing the user
                                               // sets the password to null!!!
        assertEquals("CN=" + username + ",O=AnaTom,C=SE", data.getDN());
        String email = username + "@anatom.se";
        assertEquals("rfc822name=" + email, data.getSubjectAltName());
        data.setCardNumber("123456");
        data.setPassword("bar123");
        data.setDN("C=SE, O=AnaTom1, CN=" + username);
        data.setSubjectAltName("dnsName=a.b.se, rfc822name=" + email);

        endEntityManagementSession.changeUser(admin, data, true);
        EndEntityInformation data1 = endEntityAccessSession.findUser(admin, username);
        assertNotNull(data1);
        assertEquals(username, data1.getUsername());
        assertEquals("123456", data1.getCardNumber());
        assertEquals("bar123", data1.getPassword());
        assertEquals("CN=" + username + ",O=AnaTom1,C=SE", data1.getDN());
        assertEquals("dnsName=a.b.se, rfc822name=" + email, data1.getSubjectAltName());
        log.trace("<test04ChangeUser()");
    }

    @Test
    public void test05RevokeCert() throws Exception {
        addUser();

        KeyPair keypair = KeyTools.genKeys("512", "RSA");

        EndEntityInformation data1 = endEntityAccessSession.findUser(admin, username);
        assertNotNull(data1);
        data1.setPassword("foo123");
        endEntityManagementSession.changeUser(admin, data1, true);

        Certificate cert = signSession.createCertificate(admin, username, "foo123", new PublicKeyWrapper(keypair.getPublic()));
        CertificateStatus status = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.NOT_REVOKED, status.revocationReason);
        // Revoke the certificate, put on hold
        endEntityManagementSession.revokeCert(admin, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert),
                RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
        status = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, status.revocationReason);

        // Unrevoke the certificate
        endEntityManagementSession.revokeCert(admin, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert), RevokedCertInfo.NOT_REVOKED);
        status = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.NOT_REVOKED, status.revocationReason);

        // Revoke again certificate
        endEntityManagementSession.revokeCert(admin, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert),
                RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
        status = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, status.revocationReason);

        // Unrevoke the certificate, but with different code
        endEntityManagementSession.revokeCert(admin, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert),
                RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL);
        status = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.NOT_REVOKED, status.revocationReason);

        // Revoke again certificate permanently
        endEntityManagementSession.revokeCert(admin, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert),
                RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE);
        status = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE, status.revocationReason);

        // Unrevoke the certificate, should not work
        try {
            endEntityManagementSession.revokeCert(admin, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert),
                    RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL);
            assertTrue(false); // should not reach this
        } catch (AlreadyRevokedException e) {
        }
        status = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE, status.revocationReason);
    }
    
    @Test
    public void test05RevokeOrDeleteUser() throws Exception {
        addUser();

        KeyPair keypair = KeyTools.genKeys("512", "RSA");
        EndEntityInformation data1 = endEntityAccessSession.findUser(admin, username);
        assertNotNull(data1);
        data1.setPassword("foo123");
        endEntityManagementSession.changeUser(admin, data1, true);

        final int revocationReason = RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;
        
        Certificate cert = signSession.createCertificate(admin, username, "foo123", new PublicKeyWrapper(keypair.getPublic()));
        CertificateStatus status = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.NOT_REVOKED, status.revocationReason);
                
        // 1.1 Revoke user.
        endEntityManagementSession.revokeUser(admin, username, revocationReason, false);
        status = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(revocationReason, status.revocationReason);
        // Check user still exists.
        assertTrue(endEntityManagementSession.existsUser(username));
        
        // 1.2 Revoke and delete user.
        data1.setStatus(EndEntityConstants.STATUS_NEW);
        endEntityManagementSession.changeUser(admin, data1, true);
        cert = signSession.createCertificate(admin, username, "foo123", new PublicKeyWrapper(keypair.getPublic()));
        status = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.NOT_REVOKED, status.revocationReason);        
        // Check certificate was revoked.
        endEntityManagementSession.revokeUser(admin, username, revocationReason, true);
        status = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(revocationReason, status.revocationReason);
        // Check user was deleted.
        assertTrue(!endEntityManagementSession.existsUser(username));
                
        // 2.1 Test user was not found (throw new NoSuchEndEntityException("User '" + username + "' not found.")).
        Exception exception = null;
        try {
            endEntityManagementSession.revokeUser(admin, username, revocationReason, false);
        } catch(Exception e) {
            exception = e;
        }
        assertTrue(exception instanceof NoSuchEndEntityException);
        assertTrue(("User '" + username + "' not found.").equals( exception.getMessage()));
        
        // 2.2 Test CA was not found (throw new CADoesntExistsException("CA with id " + caid + " does not exist.")).
        // Create new user again.
        addUser();
        data1 = endEntityAccessSession.findUser(admin, username);
        assertNotNull(data1);
        data1.setPassword("foo123");
        endEntityManagementSession.changeUser(admin, data1, true);
        // Test cannot be performed because NPE is thrown because of non existing CA ID in 
        // EndEntityManagementSessionBean line 884.
//        // Set CA ID which should not exist in DB.
//        final int oldCaId = data1.getCAId();
//        final int notExistingCa = 1234567890;
//        data1.setCAId(notExistingCa); 
//        endEntityManagementSession.changeUser(admin, data1, true);
//        // Revoke user with non exiting CA.
//        exception = null;
//        try {
//            endEntityManagementSession.revokeUser(admin, username, revocationReason, false);
//        } catch(Exception e) {
//            exception = e;
//        }
//        assertTrue(exception instanceof CADoesntExistsException);
//        assertTrue(("CA with id " + notExistingCa + " does not exist.").equals( exception.getMessage()));
        
        // 2.3 Authorization denied (throw new AuthorizationDeniedException(intres.getLocalizedMessage("authorization.notauthorizedtoresource", StandardRules.CAACCESS.resource() + caId, null))).
        exception = null;
        // Create missing authorization for CA access (can fail because of no accesno authorization to access end entity profile as well !!!)
        final AuthenticationToken adminNoAuthToAccessCa = new UsernameBasedAuthenticationToken(new UsernamePrincipal("EndEntityManagementSessionTest-NoAuth"));
        try {
            endEntityManagementSession.revokeUser(adminNoAuthToAccessCa, username, revocationReason, false);
        } catch(Exception e) {
            exception = e;
        }
        assertTrue(exception instanceof AuthorizationDeniedException);
        // ECA-6685: Improve test with auth. to end entity profile
        // not authorized to [end entity profile 1 that existing user 678071 was created with. Admin: 678071
        // assertEquals(intres.getLocalizedMessage("authorization.notauthorizedtoresource", StandardRules.CAACCESS.resource() + data1.getCAId()), exception.getMessage());
        
        // 2.4 Could not delete user (throw new CouldNotRemoveEndEntityException(intres.getLocalizedMessage("ra.errorremoveentity", username))).
        // ECA-6685: Improve test with end entity which can not be removed.
    }
    
    /**
     * tests deletion of user, and user that does not exist
     * 
     * @throws Exception error
     */
    @Test
    public void test06DeleteUser() throws Exception {
        addUser();

        log.trace(">test06DeleteUser()");
        endEntityManagementSession.deleteUser(admin, username);
        log.debug("deleted user: " + username);
        // Delete the the same user again
        boolean removed = false;
        try {
            endEntityManagementSession.deleteUser(admin, username);
        } catch (NoSuchEndEntityException e) {
            removed = true;
        }
        assertTrue("User does not exist does not throw NotFoundException", removed);
        log.trace("<test06DeleteUser()");
    }

    /**
     * Test adding a user, merging the DN request in the End Entity with the default DN fields in the end entity profile.
     * 
     * @throws Exception error
     */
    @Test
    public void test07MergeWithWS() throws Exception {
        // First make sure we have end entity profile limitations enabled
        final boolean eelimitation = setEnableEndEntityProfileLimitations(true);
        try {
            // An end entity profile that has CN,DNEMAIL,OU=FooOrgUnit,O,C
            EndEntityProfile profile = new EndEntityProfile();
            profile.addField(DnComponents.COMMONNAME);
            profile.addField(DnComponents.DNEMAILADDRESS);
            profile.addField(DnComponents.ORGANIZATIONALUNIT);
            profile.setUse(DnComponents.ORGANIZATIONALUNIT, 0, true);
            profile.setValue(DnComponents.ORGANIZATIONALUNIT, 0, "FooOrgUnit");
            // The merge only handles 1 default value for each DN component, i.e. one OU one O etc. You can not have two default OUs to merge.
            // You can not even define two OUs to be used in the profile, it will be merged with the value of the first duplicated, i.e. FooOrgUnit twice
            //profile.addField(DnComponents.ORGANIZATIONALUNIT);
            profile.addField(DnComponents.ORGANIZATION);
            profile.addField(DnComponents.COUNTRY);
            profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
            profile.setAllowMergeDnWebServices(true);

            endEntityProfileSession.addEndEntityProfile(admin, "TESTMERGEWITHWS", profile);
            int profileId = endEntityProfileSession.getEndEntityProfileId("TESTMERGEWITHWS");

            // An end entity with CN=username,O=AnaTom,C=SE
            // Merged with the EE profile default it should become CN=username,OU=FooOrgUnit,OU=BarOrgUnit,O=AnaTom,C=SE
            EndEntityInformation addUser = new EndEntityInformation(username, "C=SE, O=AnaTom, CN=" + username, caid, null, null,
                    EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), profileId, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, new Date(), new Date(),
                    SecConst.TOKEN_SOFT_P12, 0, null);
            addUser.setPassword("foo123");
            endEntityManagementSession.addUserFromWS(admin, addUser, false);
            EndEntityInformation data = endEntityAccessSession.findUser(admin, username);
            assertEquals("CN=" + username + ",OU=FooOrgUnit,O=AnaTom,C=SE", data.getDN());

            addUser.setDN("EMAIL=foo@bar.com, OU=hoho");
            // Changing the user feeding in EMAIL=foo@bar.com,OU=hohoit will actuallybe merged with the existing end entity user DN into
            // EMAIL:foo@bar.com,CN=username,OU=hoho,O=AnaTom,C=SE
            // Since there is an order EMAIL and OU gets in their proper order. Since we pass in OU=hoho, it override the profile default OU=FooOrgUnit
            endEntityManagementSession.changeUser(admin, addUser, false, true);
            data = endEntityAccessSession.findUser(admin, username);
            // E=foo@bar.com,CN=430208,OU=FooOrgUnit,O=hoho,C=NO
            assertEquals("E=foo@bar.com,CN=" + username + ",OU=hoho,O=AnaTom,C=SE", data.getDN());

            //Skip this test on Community
            if (DnComponents.enterpriseMappingsExist()) {
                endEntityManagementSession.deleteUser(admin, username);
                // A real use case. Add EV SSL items as default values and merge those into the End Entity
                profile.addField(DnComponents.JURISDICTIONCOUNTRY);
                profile.setUse(DnComponents.JURISDICTIONCOUNTRY, 0, true);
                profile.setValue(DnComponents.JURISDICTIONCOUNTRY, 0, "NO");
                profile.addField(DnComponents.JURISDICTIONSTATE);
                profile.setUse(DnComponents.JURISDICTIONSTATE, 0, true);
                profile.setValue(DnComponents.JURISDICTIONSTATE, 0, "California");
                profile.addField(DnComponents.JURISDICTIONLOCALITY);
                profile.setUse(DnComponents.JURISDICTIONLOCALITY, 0, true);
                profile.setValue(DnComponents.JURISDICTIONLOCALITY, 0, "Stockholm");
                endEntityProfileSession.changeEndEntityProfile(admin, "TESTMERGEWITHWS", profile);
                final String subjectDN = "CN=foo subject,O=Bar";
                addUser = new EndEntityInformation(username, subjectDN, caid, "dnsName=foo.bar.com,dnsName=foo1.bar.com,rfc822Name=foo@bar.com", null,
                        EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), profileId,
                        CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, new Date(), new Date(), SecConst.TOKEN_SOFT_P12, 0, null);
                addUser.setPassword("foo123");
                try {
                    endEntityManagementSession.addUserFromWS(admin, addUser, false);
                    fail("Should not be allowed since we have altNames that are not allowed in the profile.");
                } catch (EndEntityProfileValidationException e) {
                } // NOPMD
                // Add the required end entity profile fields
                profile.addField(DnComponents.DNSNAME);
                profile.addField(DnComponents.DNSNAME);
                profile.addField(DnComponents.DNSNAME);
                profile.addField(DnComponents.RFC822NAME);
                endEntityProfileSession.changeEndEntityProfile(admin, "TESTMERGEWITHWS", profile);
                endEntityManagementSession.addUserFromWS(admin, addUser, false);
                data = endEntityAccessSession.findUser(admin, username);
                assertEquals("JurisdictionCountry=NO,JurisdictionState=California,JurisdictionLocality=Stockholm,CN=foo subject,OU=FooOrgUnit,O=Bar",
                        data.getDN());
                // Make sure altNames are not stripped, they shall actually be merged as well
                // This returns slightly different between JDK 7 and JDK 8
                String[] javaVersionElements = System.getProperty("java.version").split("\\.");
                int major = Integer.parseInt(javaVersionElements[1]);
                if (major > 7) {
                    assertEquals("rfc822Name=foo@bar.com,dnsName=foo.bar.com,dnsName=foo1.bar.com", data.getSubjectAltName());
                } else {
                    assertEquals("dnsName=foo.bar.com,dnsName=foo1.bar.com,rfc822Name=foo@bar.com", data.getSubjectAltName());
                }        
                // Try with some altName value to merge
                endEntityManagementSession.deleteUser(admin, username);
                profile.setValue(DnComponents.DNSNAME, 0, "server.bad.com");
                profile.setValue(DnComponents.DNSNAME, 1, "server.superbad.com");
                // The merge only handles consecutive default value for each DN component, i.e. defaultname for 0 and 1, not for 0 and 2
                // The resulting altName will have 4 dnsNames, so we must allow this amount
                profile.addField(DnComponents.DNSNAME);
                endEntityProfileSession.changeEndEntityProfile(admin, "TESTMERGEWITHWS", profile);
                endEntityManagementSession.addUserFromWS(admin, addUser, false);
                data = endEntityAccessSession.findUser(admin, username);
                assertEquals("JurisdictionCountry=NO,JurisdictionState=California,JurisdictionLocality=Stockholm,CN=foo subject,OU=FooOrgUnit,O=Bar",
                        data.getDN());
                // Make sure altNames are not stripped, they shall actually be merged as well. Ok cases are different but that does not matter.
                // This returns slightly different between JDK 7 and JDK 8
                if (major > 7) {
                    assertEquals("DNSNAME=server.superbad.com,DNSNAME=server.bad.com,rfc822Name=foo@bar.com,dnsName=foo.bar.com,dnsName=foo1.bar.com", data.getSubjectAltName());
                } else {
                    assertEquals("DNSNAME=server.superbad.com,DNSNAME=server.bad.com,dnsName=foo.bar.com,dnsName=foo1.bar.com,rfc822Name=foo@bar.com",
                            data.getSubjectAltName());
                }        
            } else {
                log.debug("Skipped test related to Enterprise DN properties.");
            }
        } finally {
            setEnableEndEntityProfileLimitations(eelimitation);
        }
    }
    
    /** Tests that CA and End Entity profile authorization methods in EndEntityManagementSessionBean works.
     * When called with a user that does not have access to the CA (that you try to add a user for), or the
     * end entity profile specified for the user, an AuthorizationDeniedException should be thrown.
     * For end entity profile authorization to be effective, this must be configured in global configuration.
     */
    @Test
    public void test08Authorization() throws Exception {
        
        Set<Principal> principals = new HashSet<>();
        principals.add(new X500Principal("C=SE,O=Test,CN=Test EndEntityManagementSessionNoAuth"));
        
        TestX509CertificateAuthenticationToken adminTokenNoAuth  = (TestX509CertificateAuthenticationToken) simpleAuthenticationProvider.authenticate(new AuthenticationSubject(principals, null));
        final X509Certificate adminCert = adminTokenNoAuth.getCertificate();

        final String testRole = "EndEntityManagementSessionTestAuthRole";
        Boolean eelimitation = null;

        final String authUsername = genRandomUserName();
        String email = authUsername + "@anatom.se";
        EndEntityInformation userdata = new EndEntityInformation(authUsername, "C=SE, O=AnaTom, CN=" + username, caid, null, email, new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
        userdata.setPassword("foo123");
        // Test CA authorization
        usernames.add(authUsername+"_renamed");
        try {
            try {
                endEntityManagementSession.addUser(adminTokenNoAuth, userdata, false);
                fail("should throw");
            } catch (AuthorizationDeniedException e) {
                assertTrue("Wrong auth denied message: "+e.getMessage(), StringUtils.startsWith(e.getMessage(), "Administrator not authorized to CA"));
            }
            try {
                endEntityManagementSession.changeUser(adminTokenNoAuth, userdata, true);
                fail("should throw");
            } catch (AuthorizationDeniedException e) {
                assertTrue("Wrong auth denied message: "+e.getMessage(), StringUtils.startsWith(e.getMessage(), "Administrator not authorized to CA"));
            }
            endEntityManagementSession.addUser(admin, userdata, false);
            try {
                boolean result = endEntityManagementSession.renameEndEntity(adminTokenNoAuth, authUsername, authUsername+"_renamed");
                log.debug("Rename result: " + result);
                fail("should throw");
            } catch (AuthorizationDeniedException e) {
                assertTrue("Wrong auth denied message: "+e.getMessage(), StringUtils.startsWith(e.getMessage(), "Administrator not authorized to CA"));
            }
            try {
                endEntityManagementSession.deleteUser(adminTokenNoAuth, authUsername);
                fail("should throw");
            } catch (AuthorizationDeniedException e) {
                assertTrue("Wrong auth denied message: "+e.getMessage(), StringUtils.startsWith(e.getMessage(), "Administrator not authorized to CA"));
            }
            // Now add the administrator to a role that has access to /ca/* but not ee profiles
            final Role oldRole = roleSession.getRole(admin, null, testRole);
            if (oldRole!=null) {
                roleSession.deleteRoleIdempotent(admin, oldRole.getRoleId());
            }
            final Role role = roleSession.persistRole(admin, new Role(null, testRole, Arrays.asList(StandardRules.CAACCESSBASE.resource()), null));
            roleMemberSession.persist(admin, new RoleMember(X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                    CertTools.getIssuerDN(adminCert).hashCode(),
                    X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(),
                    AccessMatchType.TYPE_EQUALCASE.getNumericValue(),
                    CertTools.getPartFromDN(CertTools.getSubjectDN(adminCert), "CN"),
                    role.getRoleId(),
                    null));
            // We must enforce end entity profile limitations for this, with false it should be ok now
            eelimitation = setEnableEndEntityProfileLimitations(false);
            // Do the same test, now it should work since we are authorized to CA and we don't enforce EE profile authorization
            endEntityManagementSession.changeUser(adminTokenNoAuth, userdata, false);
            endEntityManagementSession.renameEndEntity(adminTokenNoAuth, authUsername, authUsername+"_renamed");
            endEntityManagementSession.renameEndEntity(adminTokenNoAuth, authUsername+"_renamed", authUsername);
            // Enforce EE profile limitations
            setEnableEndEntityProfileLimitations(true);
            // Do the same test, now we should get auth denied on EE profiles instead
            try {
                endEntityManagementSession.changeUser(adminTokenNoAuth, userdata, false);
                fail("should throw");
            } catch (AuthorizationDeniedException e) {
                assertTrue("Wrong auth denied message: "+e.getMessage(), StringUtils.startsWith(e.getMessage(), "Administrator not authorized to end entity profile"));
            }
            try {
                endEntityManagementSession.renameEndEntity(adminTokenNoAuth, authUsername, authUsername+"_renamed");
                fail("should throw");
            } catch (AuthorizationDeniedException e) {
                assertTrue("Wrong auth denied message: "+e.getMessage(), StringUtils.startsWith(e.getMessage(), "Administrator not authorized to end entity profile"));
            }
        } finally {
        	if (eelimitation!=null) {
                setEnableEndEntityProfileLimitations(eelimitation);
        	}
            try {
                endEntityManagementSession.deleteUser(admin, authUsername);
            } catch (Exception e) { // NOPMD
                log.info("Error in finally: ", e);
            }
            final Role oldRole = roleSession.getRole(admin, null, testRole);
            if (oldRole!=null) {
                roleSession.deleteRoleIdempotent(admin, oldRole.getRoleId());
            }
        }
    }

    /** Test rename of an end entity. */
    @Test
    public void testRenameEndEntity() throws Exception {
        final String username1 = "testRenameEndEntityA";
        final String username2 = "testRenameEndEntityB";
        final String username3 = "testRenameEndEntityC";
        endEntityManagementSession.addUser(admin, username1, pwd, "C=SE, O=PrimeKey, CN=" + username1, null, null, true,
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0, caid);
        endEntityManagementSession.addUser(admin, username2, pwd, "C=SE, O=PrimeKey, CN=" + username2, null, null, true,
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0, caid);
        usernames.add(username1);
        usernames.add(username2);
        usernames.add(username3);
        try {
            endEntityManagementSession.renameEndEntity(admin, username1, username2);
            fail("Was able to rename an end entity using an already occupied username.");
        } catch (EndEntityExistsException e) {
            // Expected
            final EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(admin, username1);
            assertNotNull("End entity should still exist after a failed rename.", endEntityInformation);
        }
        endEntityManagementSession.renameEndEntity(admin, username1, username3);
        final EndEntityInformation endEntityInformation1 = endEntityAccessSession.findUser(admin, username1);
        assertNull("Renamed user should no longer exist under old username.", endEntityInformation1);
        final EndEntityInformation endEntityInformation2 = endEntityAccessSession.findUser(admin, username3);
        assertNotNull("End entity should still exist after a failed rename to its username.", endEntityInformation2);
        final EndEntityInformation endEntityInformation3 = endEntityAccessSession.findUser(admin, username3);
        assertNotNull("Renamed user should exist under new username.", endEntityInformation3);
    }

    /** Test rename of an end entity with issued certificates and publishing queue. */
    @Test
    public void testRenameEndEntityWithCerts() throws Exception {
        final String username1 = "testRenameEndEntityWithCertsA";
        final String username2 = "testRenameEndEntityWithCertsB";
        final String username3 = "testRenameEndEntityWithCertsC";
        usernames.add(username1);
        usernames.add(username2);
        usernames.add(username3);
        // Add users
        endEntityManagementSession.addUser(admin, username1, pwd, "C=SE, O=PrimeKey, CN=" + username1, null, null, true,
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0, caid);
        endEntityManagementSession.addUser(admin, username2, pwd, "C=SE, O=PrimeKey, CN=" + username2, null, null, true,
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0, caid);
        // Issue certificates
        final KeyPair keyPair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        String fingerprint = null;
        try {
            final X509Certificate x509Certificate = (X509Certificate) signSession.createCertificate(admin, username1, pwd, new PublicKeyWrapper(keyPair.getPublic()));
            assertNotNull("Failed to issue certificate", x509Certificate);
            fingerprint = CertTools.getFingerprintAsString(x509Certificate);
            // Create publisher queue data
            final PublisherQueueVolatileInformation publisherQueueInfo1 = new PublisherQueueVolatileInformation();
            publisherQueueInfo1.setUsername(username1);
            publisherQueueSession.addQueueData(4217, PublisherConst.PUBLISH_TYPE_CERT, fingerprint, publisherQueueInfo1, PublisherConst.STATUS_PENDING);
            // Try to rename a user to an existing username
            try {
                endEntityManagementSession.renameEndEntity(admin, username1, username2);
                fail("Was able to rename an end entity using an already occupied username.");
            } catch (EndEntityExistsException e) {
                // Expected
                final EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(admin, username1);
                assertNotNull("End entity should still exist after a failed rename.", endEntityInformation);
                assertEquals("Publisher queue data should have retained username after failed rename", username1,
                        publisherQueueSession.getEntriesByFingerprint(fingerprint).iterator().next().getVolatileData().getUsername());
                assertEquals("Certificate data should have retained username after failed rename", username1,
                        certificateStoreSession.getCertificateInfo(fingerprint).getUsername());
            }
            endEntityManagementSession.renameEndEntity(admin, username1, username3);
            final EndEntityInformation endEntityInformation1 = endEntityAccessSession.findUser(admin, username1);
            assertNull("Renamed user should no longer exist under old username.", endEntityInformation1);
            final EndEntityInformation endEntityInformation2 = endEntityAccessSession.findUser(admin, username3);
            assertNotNull("End entity should still exist after a failed rename to its username.", endEntityInformation2);
            final EndEntityInformation endEntityInformation3 = endEntityAccessSession.findUser(admin, username3);
            assertNotNull("Renamed user should exist under new username.", endEntityInformation3);
            assertEquals("Publisher queue data should use new username.", username3,
                    publisherQueueSession.getEntriesByFingerprint(fingerprint).iterator().next().getVolatileData().getUsername());
            assertEquals("Certificate data should use new username.", username3,
                    certificateStoreSession.getCertificateInfo(fingerprint).getUsername());
        } finally {
            if (fingerprint!=null) {
                internalCertStoreSession.removeCertificate(fingerprint);
            }
        }
    }

    /** Test revocation of an end entity. */
    @Test
    public void testRevokeEndEntity() throws Exception {
        final String TEST_NAME = Thread.currentThread().getStackTrace()[1].getMethodName();
        final String USERNAME = TEST_NAME + "A";
        endEntityManagementSession.addUser(admin, USERNAME, pwd, "C=SE, O=PrimeKey, CN=" + USERNAME, null, null, true,
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0, caid);
        usernames.add(USERNAME);
        final long now = System.currentTimeMillis();
        final Date date10sAgo = new Date(now-10000L);
        final Date date2sAgo = new Date(now-2000L);
        final Date date1hFromNow = new Date(now+3600000L);
        final KeyPair keyPair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        // Generate self signed certificates
        // This is really a bit strange with no "real" certificates. We can however revoke them anyhow even though they don't belong to a CA in the system
        // This may be useful in order to be able to create "dummy" certificates for specific compromised cases where you want to answer specifically for strange things.
        final X509Certificate x509Certificate1 = CertTools.genSelfCertForPurpose("CN="+USERNAME, date10sAgo, date1hFromNow, null, keyPair.getPrivate(), keyPair.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_RSA, false, X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, null, null, BouncyCastleProvider.PROVIDER_NAME, true, null);
        final String fingerprint1 = CertTools.getFingerprintAsString(x509Certificate1);
        final X509Certificate x509Certificate2 = CertTools.genSelfCertForPurpose("CN="+USERNAME, date10sAgo, date2sAgo, null, keyPair.getPrivate(), keyPair.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_RSA, false, X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, null, null, BouncyCastleProvider.PROVIDER_NAME, true, null);
        final String fingerprint2 = CertTools.getFingerprintAsString(x509Certificate2);
        final X509Certificate x509Certificate3 = CertTools.genSelfCertForPurpose("CN="+USERNAME, date10sAgo, date1hFromNow, null, keyPair.getPrivate(), keyPair.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_RSA, false, X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, null, null, BouncyCastleProvider.PROVIDER_NAME, true, null);
        final String fingerprint3 = CertTools.getFingerprintAsString(x509Certificate3);
        final X509Certificate x509Certificate4 = CertTools.genSelfCertForPurpose("CN="+USERNAME, date10sAgo, date1hFromNow, null, keyPair.getPrivate(), keyPair.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_RSA, false, X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, null, null, BouncyCastleProvider.PROVIDER_NAME, true, null);
        final String fingerprint4 = CertTools.getFingerprintAsString(x509Certificate4);
        final X509Certificate x509Certificate5 = CertTools.genSelfCertForPurpose("CN="+USERNAME, date10sAgo, date2sAgo, null, keyPair.getPrivate(), keyPair.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_RSA, false, X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, null, null, BouncyCastleProvider.PROVIDER_NAME, true, null);
        final String fingerprint5 = CertTools.getFingerprintAsString(x509Certificate5);
        final X509Certificate x509Certificate6 = CertTools.genSelfCertForPurpose("CN="+USERNAME, date10sAgo, date1hFromNow, null, keyPair.getPrivate(), keyPair.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_RSA, false, X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, null, null, BouncyCastleProvider.PROVIDER_NAME, true, null);
        final String fingerprint6 = CertTools.getFingerprintAsString(x509Certificate6);
        try {
            // Persists self signed certificates
            internalCertStoreSession.storeCertificateNoAuth(admin, x509Certificate1, USERNAME, fingerprint1, CertificateConstants.CERT_ACTIVE,
                    CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_NO_PROFILE, EndEntityConstants.NO_END_ENTITY_PROFILE, null, now);
            internalCertStoreSession.storeCertificateNoAuth(admin, x509Certificate2, USERNAME, fingerprint2, CertificateConstants.CERT_ARCHIVED,
                    CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_NO_PROFILE, EndEntityConstants.NO_END_ENTITY_PROFILE, null, now);
            internalCertStoreSession.storeCertificateNoAuth(admin, x509Certificate3, USERNAME, fingerprint3, CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION,
                    CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_NO_PROFILE, EndEntityConstants.NO_END_ENTITY_PROFILE, null, now);
            internalCertStoreSession.storeCertificateNoAuth(admin, x509Certificate4, USERNAME, fingerprint4, CertificateConstants.CERT_REVOKED,
                    CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_NO_PROFILE, EndEntityConstants.NO_END_ENTITY_PROFILE, null, now);
            // A certificate that has expired, but status has not been changed to ARCHIVED by the CRL worker
            internalCertStoreSession.storeCertificateNoAuth(admin, x509Certificate5, USERNAME, fingerprint5, CertificateConstants.CERT_ACTIVE,
                    CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_NO_PROFILE, EndEntityConstants.NO_END_ENTITY_PROFILE, null, now);
            // Artificial test vector where certificate has not expired, but the status is still set to archived
            internalCertStoreSession.storeCertificateNoAuth(admin, x509Certificate6, USERNAME, fingerprint5, CertificateConstants.CERT_ARCHIVED,
                    CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_NO_PROFILE, EndEntityConstants.NO_END_ENTITY_PROFILE, null, now);
            // Revoke user
            endEntityManagementSession.revokeUser(admin, USERNAME, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
            // Get all certificate except the revoked ones
            final List<CertificateDataWrapper> cdws = certificateStoreSession.getCertificateDataByUsername(USERNAME, false, Arrays.asList(CertificateConstants.CERT_REVOKED));
            assertEquals("Expected that revokeUser call would not touch ARCHIVED or expired certificates.", 3, cdws.size());
            final List<String> remainingFingerprints = Arrays.asList(cdws.get(0).getCertificateData().getFingerprint(), cdws.get(1).getCertificateData().getFingerprint(),
                    cdws.get(2).getCertificateData().getFingerprint());
            assertTrue("Expected archived and expired certificate to not be revoked.", remainingFingerprints.contains(fingerprint2));
            assertTrue("Expected active and expired certificate to not be revoked.", remainingFingerprints.contains(fingerprint5));
            assertTrue("Expected archived and non-expired certificate to not be revoked.", remainingFingerprints.contains(fingerprint6));
        } finally {
            // Clean up
            final List<CertificateDataWrapper> cdws = certificateStoreSession.getCertificateDataByUsername(USERNAME, false, null);
            for (final CertificateDataWrapper cdw : cdws) {
                internalCertStoreSession.removeCertificate(cdw.getCertificateData().getFingerprint());
            }
        }
    }
    
    
    /**
     * Test revocation of a throw away certificate with publishing enabled.
     * This test does not use the publisher queue.
     */
    @Test
    public void testRevokeThrowAwayCertAndPublish() throws Exception {
        try {
            final CAInfo cainfo = setUpThrowAwayPublishingTest(false, false); // don't use publisher queue
            publisherTestSession.setLastMockedThrowAwayRevocationReason(-123);
            endEntityManagementSession.revokeCert(admin, THROWAWAY_CERT_SERIAL, cainfo.getSubjectDN(), RevocationReasons.CERTIFICATEHOLD.getDatabaseValue());
            assertEquals("Publisher should have been called with 'on hold' revocation reason.",
                    RevocationReasons.CERTIFICATEHOLD.getDatabaseValue(), publisherTestSession.getLastMockedThrowAwayRevocationReason());
            endEntityManagementSession.revokeCert(admin, THROWAWAY_CERT_SERIAL, cainfo.getSubjectDN(), RevocationReasons.NOT_REVOKED.getDatabaseValue());
            assertEquals("Publisher should have been called with 'not revoked' revocation reason.",
                    RevocationReasons.NOT_REVOKED.getDatabaseValue(), publisherTestSession.getLastMockedThrowAwayRevocationReason());
            endEntityManagementSession.revokeCert(admin, THROWAWAY_CERT_SERIAL, cainfo.getSubjectDN(), RevocationReasons.SUPERSEDED.getDatabaseValue());
            assertEquals("Publisher should have been called with 'superseeded' revocation reason.",
                    RevocationReasons.SUPERSEDED.getDatabaseValue(), publisherTestSession.getLastMockedThrowAwayRevocationReason());
        } finally {
            cleanUpThrowAwayPublishingTest();
        }
    }
    
    /**
     * Test revocation of a throw away certificate with publishing enabled.
     * This test does not use the publisher queue. Data is stored in the NoConflictCertificateData table.
     */
    @Test
    public void testRevokeThrowAwayCertAndPublishWithNoConflictTable() throws Exception {
        try {
            final CAInfo cainfo = setUpThrowAwayPublishingTest(false, true); // don't use publisher queue. use no conflict table
            publisherTestSession.setLastMockedThrowAwayRevocationReason(-123);
            endEntityManagementSession.revokeCert(admin, THROWAWAY_CERT_SERIAL, cainfo.getSubjectDN(), RevocationReasons.CERTIFICATEHOLD.getDatabaseValue());
            assertEquals("Publisher should have been called with 'on hold' revocation reason.",
                    RevocationReasons.CERTIFICATEHOLD.getDatabaseValue(), publisherTestSession.getLastMockedThrowAwayRevocationReason());
            endEntityManagementSession.revokeCert(admin, THROWAWAY_CERT_SERIAL, cainfo.getSubjectDN(), RevocationReasons.NOT_REVOKED.getDatabaseValue());
            assertEquals("Publisher should have been called with 'not revoked' revocation reason.",
                    RevocationReasons.NOT_REVOKED.getDatabaseValue(), publisherTestSession.getLastMockedThrowAwayRevocationReason());
            endEntityManagementSession.revokeCert(admin, THROWAWAY_CERT_SERIAL, cainfo.getSubjectDN(), RevocationReasons.SUPERSEDED.getDatabaseValue());
            assertEquals("Publisher should have been called with 'superseeded' revocation reason.",
                    RevocationReasons.SUPERSEDED.getDatabaseValue(), publisherTestSession.getLastMockedThrowAwayRevocationReason());
        } finally {
            cleanUpThrowAwayPublishingTest();
        }
    }
    
    /**
     * Test revocation of a throw away certificate with publishing enabled.
     * This test uses the publisher queue. Data is stored in the NoConflictCertificateData table.
     */
    @Test
    public void testRevokeThrowAwayCertAndPublishViaQueue() throws Exception {
        try {
            final CAInfo cainfo = setUpThrowAwayPublishingTest(true, true); // use publisher queue. use no conflict table.
            final BasePublisher publisher = publisherSession.getPublisher(THROWAWAY_PUBLISHER);
            // Place on hold
            publisherTestSession.setLastMockedThrowAwayRevocationReason(-123);
            endEntityManagementSession.revokeCert(admin, THROWAWAY_CERT_SERIAL, cainfo.getSubjectDN(), RevocationReasons.CERTIFICATEHOLD.getDatabaseValue());
            assertEquals("Publisher should not have been called.", -123, publisherTestSession.getLastMockedThrowAwayRevocationReason());
            publisherQueueSession.plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(admin, publisher.getPublisherId(), publisher);
            assertEquals("Publisher should have been called with 'on hold' revocation reason.",
                    RevocationReasons.CERTIFICATEHOLD.getDatabaseValue(), publisherTestSession.getLastMockedThrowAwayRevocationReason());
            // Activate again
            publisherTestSession.setLastMockedThrowAwayRevocationReason(-123);
            assertEquals("Publisher should not have been called.", -123, publisherTestSession.getLastMockedThrowAwayRevocationReason());
            endEntityManagementSession.revokeCert(admin, THROWAWAY_CERT_SERIAL, cainfo.getSubjectDN(), RevocationReasons.NOT_REVOKED.getDatabaseValue());
            publisherQueueSession.plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(admin, publisher.getPublisherId(), publisher);
            assertEquals("Publisher should have been called THROW_AWAY_CERT_SERIAL 'not revoked' revocation reason.",
                    RevocationReasons.NOT_REVOKED.getDatabaseValue(), publisherTestSession.getLastMockedThrowAwayRevocationReason());
            // Revoke permanently
            publisherTestSession.setLastMockedThrowAwayRevocationReason(-123);
            assertEquals("Publisher should not have been called.", -123, publisherTestSession.getLastMockedThrowAwayRevocationReason());
            endEntityManagementSession.revokeCert(admin, THROWAWAY_CERT_SERIAL, cainfo.getSubjectDN(), RevocationReasons.SUPERSEDED.getDatabaseValue());
            publisherQueueSession.plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(admin, publisher.getPublisherId(), publisher);
            assertEquals("Publisher should have been called with 'superseeded' revocation reason.",
                    RevocationReasons.SUPERSEDED.getDatabaseValue(), publisherTestSession.getLastMockedThrowAwayRevocationReason());
        } finally {
            cleanUpThrowAwayPublishingTest();
            final String fingerprint = noConflictCertificateStoreSession.generateDummyFingerprint("CN="+getTestCAName(), THROWAWAY_CERT_SERIAL);
            for (final PublisherQueueData entry : publisherQueueSession.getEntriesByFingerprint(fingerprint)) {
                log.debug("Removing publisher queue entry");
                publisherQueueSession.removeQueueData(entry.getPk());
            }
        }
    }
    
    private CAInfo setUpThrowAwayPublishingTest(final boolean useQueue, final boolean useNoConflictCertificateData) throws PublisherExistsException, AuthorizationDeniedException, CertificateProfileExistsException {
        // Set up publishing
        final CustomPublisherContainer publisher = new CustomPublisherContainer();
        publisher.setClassPath(MockedThrowAwayRevocationPublisher.class.getName());
        publisher.setDescription("Used in Junit Test, Remove this one");
        publisher.setOnlyUseQueue(useQueue);
        final int publisherId = publisherSession.addPublisher(admin, THROWAWAY_PUBLISHER, publisher);
        final CertificateProfile certProf = new CertificateProfile(CertificateConstants.CERTTYPE_ENDENTITY);
        certProf.setPublisherList(Arrays.asList(publisherId));
        int certProfId = certificateProfileSession.addCertificateProfile(admin, THROWAWAY_CERT_PROFILE, certProf);
        // Set throw away flag on test CA
        final CAInfo cainfo = caSession.getCAInfo(admin, caid);
        cainfo.setUseCertificateStorage(false);
        cainfo.setUseUserStorage(false);
        cainfo.setAcceptRevocationNonExistingEntry(true);
        cainfo.setUseNoConflictCertificateData(useNoConflictCertificateData);
        cainfo.setDefaultCertificateProfileId(certProfId);
        caAdminSession.editCA(admin, cainfo);
        return cainfo;
    }
    
    private void cleanUpThrowAwayPublishingTest() throws AuthorizationDeniedException {
        final CAInfo cainfo = caSession.getCAInfo(admin, caid);
        cainfo.setUseCertificateStorage(true);
        cainfo.setUseUserStorage(true);
        cainfo.setAcceptRevocationNonExistingEntry(false);
        cainfo.setUseNoConflictCertificateData(false);
        caAdminSession.editCA(admin, cainfo);
        certificateProfileSession.removeCertificateProfile(admin, THROWAWAY_CERT_PROFILE);
        publisherProxySession.removePublisherInternal(admin, THROWAWAY_PUBLISHER);
        internalCertStoreSession.removeCertificate(THROWAWAY_CERT_SERIAL);
    }
}
