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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Random;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
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
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.NoConflictCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.BasicCertificateExtension;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.mock.authentication.tokens.UsernameBasedAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
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
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileInformation;
import org.ejbca.core.model.era.TestRaMasterApiProxySessionRemote;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.model.services.workers.PublishQueueProcessWorker;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.core.protocol.ws.objects.UserDataVOWS;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import com.keyfactor.ErrorCode;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;
import com.novell.ldap.util.Base64;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

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
    private static final String EE_PROFILE_NAME_COPY_UPN = "EE_PROFILE_NAME_COPY_UPN";
    
    private final int caId = getTestCAId();

    private static String username;
    private static String pwd;
    private static final ArrayList<String> usernames = new ArrayList<>();
    private static String serialnumber;

    private final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private final NoConflictCertificateStoreSessionRemote noConflictCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(NoConflictCertificateStoreSessionRemote.class);
    private final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private final SimpleAuthenticationProviderSessionRemote simpleAuthenticationProvider = EjbRemoteHelper.INSTANCE.getRemoteSession(SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private final RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
    private final GlobalConfigurationSessionRemote globalConfSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final PublisherSessionRemote publisherSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class);
    private final PublisherProxySessionRemote publisherProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final PublisherTestSessionRemote publisherTestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final PublisherQueueProxySessionRemote publisherQueueSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherQueueProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private TestRaMasterApiProxySessionRemote testRaMasterApiProxySession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(TestRaMasterApiProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
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
        } catch (Exception e) {
            // NOPMD, ignore errors
        }
        try {
            endEntityProfileSession.removeEndEntityProfile(admin, EE_PROFILE_NAME_COPY_UPN);
        } catch (Exception e) {
            // NOPMD, ignore errors
        }
        
    }
    
    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

    private void genRandomSerialnumber() {
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
        EndEntityInformation endEntityInformation = new EndEntityInformation(username,  "C=SE, O=AnaTom, CN=" + username, caId,  "rfc822name=" + email, email, 
                EndEntityTypes.ENDUSER.toEndEntityType(), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, null);
        endEntityInformation.setPassword(pwd);
        
        endEntityManagementSession.addUser(admin, endEntityInformation, true);
        usernames.add(username);
        log.debug("created user: " + username + ", " + pwd + ", C=SE, O=AnaTom, CN=" + username);
        // Add the same user again
        boolean userexists = false;
        try {
            endEntityManagementSession.addUser(admin, endEntityInformation, false);
        } catch (EndEntityExistsException e) {
            userexists = true; // This is what we want
        }
        assertTrue("Trying to create the same user twice didn't throw EndEntityExistsException", userexists);

        // try to add user with non-existing CA-id
        String username2 = genRandomUserName();
        int fakecaid = -1;
        boolean thrown = false;
        try {
            EndEntityInformation secondEndEntity = new EndEntityInformation(username2, "C=SE, O=AnaTom, CN=" + username2, fakecaid, null, null,
                    EndEntityTypes.ENDUSER.toEndEntityType(), EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                    CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, null);
            secondEndEntity.setPassword(pwd);
            endEntityManagementSession.addUser(admin, secondEndEntity, true);
            fail();
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
    
    @Test
    public void testCreateCertMsae() throws Exception {
        String SAMPLE_REQUEST = "308208a906092a864886f70d010702a082089a30820896020103310b300906052b0e0"
                + "3021a0500308203e506082b06010505070c02a08203d7048203d3308203cf3081a030819d020102060a2b0601040182370a0a013"
                + "1818b3081880201003003020101317e302306092b0601040182371515311604147746e7e66bb597a67d08bf6e059c79e16dd66b8"
                + "3305706092b0601040182371514314a30480201090c237669636833642e6a646f6d6373632e6e74746573742e6d6963726f736f6"
                + "6742e636f6d0c154a444f4d4353435c61646d696e6973747261746f720c076365727472657130820324a08203200201013082031"
                + "9308202820201003023310f300d0603550403130654657374434e3110300e060355040a1307546573744f726730819f300d06092"
                + "a864886f70d010101050003818d0030818902818100dab2cc813700c9c8a0903da0f6b7a76880bf43441962fd9b713249c0b0a34"
                + "554d1e524c1cde3e6458a2de53fefcd7eebbc68de7488117661f37765c69c54ee546df9e59bc7ec8215bd6b15889793ec0d0aefa"
                + "85ede0ce794e07de73d44a4771dbdd803dfbfb489a1883c8572e336967ce07fe4ac848a696e02690be453fb2c950203010001a08"
                + "201b4301a060a2b0601040182370d0203310c160a362e302e353336312e323042060a2b0601040182370d0201313430321e26004"
                + "3006500720074006900660069006300610074006500540065006d0070006c0061007400651e080055007300650072305706092b0"
                + "601040182371514314a30480201090c237669636833642e6a646f6d6373632e6e74746573742e6d6963726f736f66742e636f6d0"
                + "c154a444f4d4353435c61646d696e6973747261746f720c07636572747265713074060a2b0601040182370d02023166306402010"
                + "11e5c004d006900630072006f0073006f0066007400200045006e00680061006e006300650064002000430072007900700074006"
                + "f0067007200610070006800690063002000500072006f00760069006400650072002000760031002e003003010030818206092a8"
                + "64886f70d01090e31753073301706092b0601040182371402040a1e08005500730065007230290603551d2504223020060a2b060"
                + "1040182370a030406082b0601050507030406082b06010505070302300e0603551d0f0101ff0404030205a0301d0603551d0e041"
                + "6041415bbba05358d0b21fb5db0f4a38fe3bf0f2ce0c5300d06092a864886f70d0101050500038181006ac9bc0cf7675e9161c78"
                + "ce7df37dc5fcc59cb38c071e61748cbf1d615f28161a330a8242f5d661094d3813445dffa3963ffc617a84ae545f9e814e2aaf4e"
                + "50cde845cf279c5e4419180b975d50c0df708c2adc790be8ff51f9d47e4b750ffaf40b6e21a9986d864dce2d4e41d82c66eab458"
                + "c7be3b5dcd8feaf9978cb1b7086300030003182049930820495020103801415bbba05358d0b21fb5db0f4a38fe3bf0f2ce0c5300"
                + "906052b0e03021a0500a03e301706092a864886f70d010903310a06082b06010505070c02302306092a864886f70d01090431160"
                + "414e088afba3f9bde527ff0887fced97debfa363f72300d06092a864886f70d01010105000481804505b61926013cc202172d9e1"
                + "d194df8ff4358e5544a24525b93e636005bbaaebfbc70d9c7f5d149e9e36ebdb7ac33c9147a81b59eb1a97c2287588b9028874f8"
                + "65b016ecb6fde4a6689e6e5bcaed259b5882381a552a071f0b0d457b8ac64fca03b7bbd8a5e571a711c4705708f27bc7a25beda7"
                + "910d083e08ac3f8d1ff513aa182039b3082039706092b060104018237150d318203883082038406092a864886f70d010703a0820"
                + "375308203710201003181ea3081e70201003050304231123010060355040a13094d6963726f736f6674312c302a0603550403132"
                + "34a444f4d435343204c6f6e67686f726e20456e746572707269736520526f6f74204341020a488a9b22000000000a39300d06092"
                + "a864886f70d0101010500048180960b583191d1fdd1ee45ccfa7a368ca09fb52df2a07def463b1a33a3bf861f00fb3b237cdb504"
                + "e5303e9c147a0186e4bba4a63df419395e6d56b03b117363adba12870f814c45d9e5e4414ae4947e22f357c9e8d9245c9fbe0bc3"
                + "8c9d674cdd93eaf70664476b9943c980b717a5a363ba72d45aa3d816eaf42a89631b1a76d263082027d06092a864886f70d01070"
                + "1301406082a864886f70d030704086cd44389e15a7fc380820258fae61aa513fcae9caefc78fe0b8f0698dcc5f3fd71e29a17488"
                + "65f30edcc4631a90ebead68ff6cfe7ecf6bfdeb647cde6eafe1a9956782388e0c9011f0fb976489701fdd38b3fddf73bf90e39f2"
                + "b11d664798ec3571264fea37c47958860c2193f454cbb48273f1db3b45c800161a4b677b27e22039418181b38e86ef01379c219f"
                + "54e43f5131ea035a9a9fdf2cf14ab2ab41618c0b6fd43d8a9672ee1a7d587a27d8460ecfe441c74cc2c7a9c2272a5d944d154185"
                + "bfc6bfef08bfd09dbe76100fe2abb421c549099df83f1915d22076fcc908445206fc3ed97b243adae5eabdcab69f857aefbb37b4"
                + "e1381b134a0171774e921d1a76870d6f69639924fe26f88ca6d318db267043e39234d1eefcbc8ef34ded1a02a95c3aec792ee136"
                + "cdeeb72e02cbb7b721d03df60c5bfae61bbf7742a0f1855c1c83652cfbf2c5b7704d7615524b85ce13851dd909d6bfd55644d7bf"
                + "045b660f998f1026a74841b4f9016945924988c84c0459f9bea120ebff3ac629f254e1281f5b5f9a0fb3add3883b87753672104b"
                + "6b2bf580cdf64b9da6cd51391a1e4dc007a527e9e6be1ee8ab4eb6349babc605a5de21f62949ee1e7773e12c607d0cb5bd4e33b6"
                + "5ac0ce0cd413af1072f3b8dea07fbe9bdcde0ba1f93767cac5276f48224eaddf8b4cff3a8cdbfe8d7fa9281bc549486533edd218"
                + "5344660ddc0af797887e2a322e52d6cb250211482260b369a0bd0897c93f763671e72ea2470916c68902fb6e687f4e7f0d1eec87"
                + "c1b15a5a978d24d10362ad4e67494c267d02f987815e735ac1e723101baae7e6e7c5154693c5cbd023289392fffdb58644971dfc"
                + "7f8fb";
        
        UserDataVOWS user1 = new UserDataVOWS();
        user1.setUsername("TestCN");
        user1.setSubjectDN("CN=TestCN,O=TestOrg");
        user1.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        user1.setCertificateProfileName("ENDUSER");
        user1.setEndEntityProfileName("EMPTY");
        user1.setStatus(EndEntityConstants.STATUS_NEW);
        user1.setPassword("somepass");

        // The CA Name is user-configurable.
        user1.setCaName("ManagementCA");

        byte[] res = testRaMasterApiProxySession.createCertificateWS(admin, user1, Base64.encode(Hex.decode(SAMPLE_REQUEST)),
               CertificateConstants.CERT_REQ_TYPE_MS_KEY_ARCHIVAL, CertificateHelper.RESPONSETYPE_PKCS7WITHCHAIN);
        assertNotNull(res);
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
            profile.setAvailableCAs(Arrays.asList(SecConst.ALLCAS));
            profile.setAllowMergeDn(true);
            // Profile will be removed in finally clause
            endEntityProfileSession.addEndEntityProfile(admin, eeprofileName, profile);
            int profileId = endEntityProfileSession.getEndEntityProfileId(eeprofileName);
            String thisusername = genRandomUserName();
            String email = thisusername + "@anatom.se";
            try {
                EndEntityInformation endEntityInformation = new EndEntityInformation(thisusername,  "C=SE, CN=" + thisusername, caId, null, email, 
                        EndEntityTypes.ENDUSER.toEndEntityType(), profileId, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, null);
                endEntityInformation.setPassword("");
                endEntityManagementSession.addUser(admin, endEntityInformation, false);
                usernames.add(thisusername);
                fail("User " + thisusername + " was added to the database although it should not have been.");
            } catch (EndEntityProfileValidationException e) {
                assertTrue("Error message should be about password, was " + e.getMessage(), e.getMessage().contains("Password cannot be empty or null"));
            }
            try {
                EndEntityInformation endEntityInformation = new EndEntityInformation(thisusername,  "C=SE, CN=" + thisusername, caId, null, email, 
                        EndEntityTypes.ENDUSER.toEndEntityType(), profileId, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, null);
                endEntityInformation.setPassword(null);
                endEntityManagementSession.addUser(admin, endEntityInformation, false);              
                usernames.add(thisusername);
                fail("User " + thisusername + " was added to the database although it should not have been.");
            } catch (EndEntityProfileValidationException e) {
                assertTrue("Error message should be about password", e.getMessage().contains("Password cannot be empty or null"));
            }
            // Set required = false for password, then an empty password should be allowed
            profile.setPasswordRequired(false);
            endEntityProfileSession.changeEndEntityProfile(admin, eeprofileName, profile);
            try {
                EndEntityInformation endEntityInformation = new EndEntityInformation(thisusername,  "C=SE, CN=" + thisusername, caId, null, email, 
                        EndEntityTypes.ENDUSER.toEndEntityType(), profileId, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, null);
                endEntityInformation.setPassword("");
                endEntityManagementSession.addUser(admin, endEntityInformation, false);              
                usernames.add(thisusername);
            } catch (EndEntityProfileValidationException e) {
                fail("User " + thisusername + " was not added to the database although it should have been. " + e.getMessage());
            }
            thisusername = genRandomUserName();
            email = thisusername + "@anatom.se";
            try {
                EndEntityInformation endEntityInformation = new EndEntityInformation(thisusername,  "C=SE, CN=" + thisusername, caId, null, email, 
                        EndEntityTypes.ENDUSER.toEndEntityType(), profileId, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, null);
                endEntityInformation.setPassword(null);
                endEntityManagementSession.addUser(admin, endEntityInformation, false);              
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
     * Test adding and accessing end entities with leading and trailing whitespace 
     */
    @Test
    public void testAddEndEntityWithWhitespace() throws EndEntityExistsException, CADoesntExistsException, IllegalNameException, CustomFieldException,
            ApprovalException, CertificateSerialNumberException, AuthorizationDeniedException, EndEntityProfileValidationException,
            WaitingForApprovalException, CouldNotRemoveEndEntityException {
        //For legacy support, allow whitespace within the username (as this has been previously allowed)
        final String whitespaceUsername = "john doe";
        //Add trailing and leading whitespace. 
        EndEntityInformation leadingWhitespace = new EndEntityInformation(" " + whitespaceUsername + " ", "CN=" + whitespaceUsername, caId, null,
                null, EndEntityTypes.ENDUSER.toEndEntityType(), EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, null);
        leadingWhitespace.setPassword(pwd);

        endEntityManagementSession.addUser(admin, leadingWhitespace, false);
        try {
            //Verify that the user has been added sans whitespace
            assertNotNull("End entity was added without eliminating leading and trailing whitespace.", endEntityAccessSession.findUser(admin, whitespaceUsername));
            //Verify that we can still find the user with trailing and leading whitespace. 
            assertNotNull("Whitespace was not eliminated when searching for the username.", endEntityAccessSession.findUser(admin, " " + whitespaceUsername + " "));
            //Verify that we can delete the user with whitespace 
            try {
                endEntityManagementSession.deleteUser(admin, " " + whitespaceUsername + " ");
            } catch (NoSuchEndEntityException e) {
                fail("End Entity should have been removed in spite of leading and trailing whitespace in the username.");
            } 
        } finally {
            try {
                endEntityManagementSession.deleteUser(admin, whitespaceUsername);
            } catch (NoSuchEndEntityException e) {
                //Ignore, this is fine
            }
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
        
        EndEntityInformation endEntityInformation = new EndEntityInformation(thisusername, "C=SE, CN=" + thisusername + ", SN=" + serialnumber, caId, "rfc822name=" + email, email, 
                EndEntityTypes.ENDUSER.toEndEntityType(), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, null);
        endEntityInformation.setPassword(pwd);
        endEntityManagementSession.addUser(admin, endEntityInformation, false);
       
        assertTrue("User " + thisusername + " was not added to the database.", endEntityManagementSession.existsUser(thisusername));
        usernames.add(thisusername);

        // Set the CA to enforce unique subjectDN serialnumber
        CAInfo cainfo = caSession.getCAInfo(admin, caId);
        boolean requiredUniqueSerialnumber = cainfo.isDoEnforceUniqueSubjectDNSerialnumber();
        cainfo.setDoEnforceUniqueSubjectDNSerialnumber(true);
        caAdminSession.editCA(admin, cainfo);

        // Add another user with the same serialnumber
        thisusername = genRandomUserName();
        try {
            EndEntityInformation anotherEndEntityInformation = new EndEntityInformation(thisusername, "C=SE, CN=" + thisusername + ", SN=" + serialnumber, caId, "rfc822name=" + email, email, 
                    EndEntityTypes.ENDUSER.toEndEntityType(), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, null);
            anotherEndEntityInformation.setPassword(pwd);
            endEntityManagementSession.addUser(admin, anotherEndEntityInformation, false);
            usernames.add(thisusername);
            fail("Should throw");
        } catch (CertificateSerialNumberException e) {
            assertEquals(ErrorCode.SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS, e.getErrorCode());
        }
        assertFalse("Succeeded in adding another end entity with the same serialnumber", endEntityManagementSession.existsUser(thisusername));

        // Set the CA to NOT enforcing unique subjectDN serialnumber
        cainfo.setDoEnforceUniqueSubjectDNSerialnumber(false);
        caAdminSession.editCA(admin, cainfo);

        EndEntityInformation doNotRequireUniqueSN = new EndEntityInformation(thisusername, "C=SE, CN=" + thisusername + ", SN=" + serialnumber, caId, "rfc822name=" + email, email, 
                EndEntityTypes.ENDUSER.toEndEntityType(), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, null);
        doNotRequireUniqueSN.setPassword(pwd);
        endEntityManagementSession.addUser(admin, doNotRequireUniqueSN, false);
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

        CAInfo secondCainfo = caSession.getCAInfo(admin, caId);
        boolean secondRequiredUniqueSerialnumber = secondCainfo.isDoEnforceUniqueSubjectDNSerialnumber();

        // Set the CA to enforce unique serialnumber
        cainfo.setDoEnforceUniqueSubjectDNSerialnumber(true);
        caAdminSession.editCA(admin, cainfo);    
        try {
            EndEntityInformation user = new EndEntityInformation(secondUserName, "C=SE, CN=" + secondUserName + ", SN=" + serialnumber, caId, "rfc822name=" + secondEmail, secondEmail,
                    new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, null);    
            endEntityManagementSession.changeUser(admin, user, false);
            fail("Should throw");
        } catch (CertificateSerialNumberException e) {
            assertEquals(ErrorCode.SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS, e.getErrorCode());
        }
        assertEquals("The user '" + secondUserName + "' was changed even though the serialnumber already exists.", 0, endEntityAccessSession.findUserByEmail(admin, secondEmail).size());

        // Set the CA to NOT enforcing unique subjectDN serialnumber
        cainfo.setDoEnforceUniqueSubjectDNSerialnumber(false);
        caAdminSession.editCA(admin, cainfo);
        EndEntityInformation user = new EndEntityInformation(secondUserName, "C=SE, CN=" + secondUserName + ", SN=" + serialnumber, caId, "rfc822name=" + secondEmail, secondEmail,
                new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, null);    
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
        
        // Test to change with a EE profile ID that does not exist, this should throw an error
        data.setEndEntityProfileId(new Random().nextInt(100000) + 123456);
        try {
            endEntityManagementSession.changeUser(admin, data, true);
            fail("Trying to edit a user to a non existing end entity profile should not work");
        } catch (EndEntityProfileValidationException e) {
            // NOPMD:
        }
        
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
            fail(); // should not reach this
        } catch (AlreadyRevokedException e) {
            // NOPMD
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
        assertFalse(endEntityManagementSession.existsUser(username));
                
        // 2.1 Test user was not found (throw new NoSuchEndEntityException("User '" + username + "' not found.")).
        Exception exception = null;
        try {
            endEntityManagementSession.revokeUser(admin, username, revocationReason, false);
        } catch(Exception e) {
            exception = e;
        }
        assertTrue(exception instanceof NoSuchEndEntityException);
        assertEquals(("User '" + username + "' not found."), exception.getMessage());
        
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
    
    @Test
    public void test07MergeDN() throws Exception {
        // First make sure we have end entity profile limitations enabled
        final boolean eelimitation = setEnableEndEntityProfileLimitations(true);
        try {
            // An end entity profile that has CN,DNEMAIL,OU=FooOrgUnit,O,C
            EndEntityProfile profile = new EndEntityProfile();
            //profile.addField(DnComponents.COMMONNAME); default EndEntityProfile constructor adds a CN field
            profile.addField(DnComponents.DNEMAILADDRESS);
            profile.addField(DnComponents.ORGANIZATIONALUNIT);
            profile.setUse(DnComponents.ORGANIZATIONALUNIT, 0, true);
            profile.setValue(DnComponents.ORGANIZATIONALUNIT, 0, "FooOrgUnit");
            // The merge handles several default values for each DN component, i.e. OU=OrgU1,OU=OrgU2,O=Org etc.
            profile.addField(DnComponents.ORGANIZATION);
            profile.addField(DnComponents.COUNTRY);
            profile.setAvailableCAs(Arrays.asList(SecConst.ALLCAS));
            profile.setAllowMergeDn(true);

            endEntityProfileSession.addEndEntityProfile(admin, "TESTMERGEWITHWS", profile);
            int profileId = endEntityProfileSession.getEndEntityProfileId("TESTMERGEWITHWS");
            // An end entity with CN=username,O=AnaTom,C=SE
            // Merged with the EE profile default it should become CN=username,OU=FooOrgUnit,OU=BarOrgUnit,O=AnaTom,C=SE
            EndEntityInformation addUser = new EndEntityInformation(username, "C=SE, O=AnaTom, CN=" + username, caId, null, null,
                    EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), profileId, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, new Date(), new Date(),
                    SecConst.TOKEN_SOFT_P12, null);
            addUser.setPassword("foo123");
            endEntityManagementSession.addUser(admin, addUser, false);
            EndEntityInformation data = endEntityAccessSession.findUser(admin, username);
            assertEquals("CN=" + username + ",OU=FooOrgUnit,O=AnaTom,C=SE", data.getDN());
            addUser.setDN("EMAIL=foo@bar.com, OU=hoho");
            // Changing the user feeding in EMAIL=foo@bar.com,OU=hoho it will actually be merged with the existing end entity user DN into
            // EMAIL:foo@bar.com,CN=username,OU=hoho,O=AnaTom,C=SE
            // Since there is an order EMAIL and OU gets in their proper order. Since we pass in OU=hoho, it override the profile default OU=FooOrgUnit
            // It is merged with the existing userDN "CN=" + username + ",OU=FooOrgUnit,O=AnaTom,C=SE", resulting in
            // E=foo@bar.com,CN=" + username + ",OU=hoho,O=AnaTom,C=SE
            endEntityManagementSession.changeUser(admin, addUser, false, true);
            data = endEntityAccessSession.findUser(admin, username);
            // E=foo@bar.com,CN=430208,OU=FooOrgUnit,O=hoho,C=NO
            assertEquals("E=foo@bar.com,CN=" + username + ",OU=hoho,O=AnaTom,C=SE", data.getDN());
            // Since ECA-8942 (EJBCA 7.4.0) we support multiple fields in the profile
            // Add additional tests with multiple fields, typically organizations want to use multiple OU fields, but other fields should behave the same
            profile.addField(DnComponents.ORGANIZATIONALUNIT);
            profile.setUse(DnComponents.ORGANIZATIONALUNIT, 1, true);
            profile.setValue(DnComponents.ORGANIZATIONALUNIT, 1, "OrgUnit2");
            endEntityProfileSession.changeEndEntityProfile(admin, "TESTMERGEWITHWS", profile);
            String usernameMulti = genRandomUserName();
            usernames.add(usernameMulti);
            EndEntityInformation addUserMulti = new EndEntityInformation(usernameMulti, "CN=" + usernameMulti+",O=AnaTom, C=SE", caId, null, null,
                    EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), profileId, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, new Date(), new Date(),
                    SecConst.TOKEN_SOFT_P12, null);
            addUserMulti.setPassword("foo123");
            endEntityManagementSession.addUser(admin, addUserMulti, false);
            EndEntityInformation dataMulti = endEntityAccessSession.findUser(admin, usernameMulti);
            assertEquals("CN=" + usernameMulti + ",OU=FooOrgUnit,OU=OrgUnit2,O=AnaTom,C=SE", dataMulti.getDN());
            // OU overrides from the back in priority order, i.e. when there are two OUs with values, the hoho below overrides the first one
            addUserMulti.setDN("CN=" + usernameMulti + ",OU=hoho");
            // Changing the user feed in CN=usernameMulti,OU=hoho it will actually be merged with the existing end entity user DN into
            // CN=usernameMulti,OU=hoho,OU=OrgUnit2,O=AnaTom,C=SE
            // It is merged with the existing userDN "CN=" + username + ",OU=FooOrgUnit,OU=OrgUnit2,O=AnaTom,C=SE", resulting in
            // CN=" + usernameMulti + ",OU=hoho,OU=OrgUnit2,O=AnaTom,C=SE
            // Since we pass in OU=hoho, it override the profile default OU=FooOrgUnit, but not the second one OU=OrgUnit2
            endEntityManagementSession.changeUser(admin, addUserMulti, false, true);
            dataMulti = endEntityAccessSession.findUser(admin, usernameMulti);
            assertEquals("CN=" + usernameMulti + ",OU=hoho,OU=OrgUnit2,O=AnaTom,C=SE", dataMulti.getDN());
            // Do the same again, nothing should change now
            endEntityManagementSession.changeUser(admin, addUserMulti, false, true);
            dataMulti = endEntityAccessSession.findUser(admin, usernameMulti);
            assertEquals("CN=" + usernameMulti + ",OU=hoho,OU=OrgUnit2,O=AnaTom,C=SE", dataMulti.getDN());
            // Remove the default value for OU=OrgUnit2, now it should override the first still
            profile.setValue(DnComponents.ORGANIZATIONALUNIT, 1, null);
            // Add a DN serial number
            profile.addField(DnComponents.DNSERIALNUMBER);
            endEntityProfileSession.changeEndEntityProfile(admin, "TESTMERGEWITHWS", profile);
            addUserMulti.setDN("SERIALNUMBER=12345,CN=" + usernameMulti + ",OU=hoho1");
            // Now merging:
            // CN=" + username + ",OU=hoho,OU=OrgUnit2,O=AnaTom,C=SE
            // with: SERIALNUMBER=12345,OU=hoho1 will result in the first OU value being overridden
            // CN=" + username + ",SN=12345,OU=hoho1,OU=OrgUnit2,O=AnaTom,C=SE
            endEntityManagementSession.changeUser(admin, addUserMulti, false, true);
            dataMulti = endEntityAccessSession.findUser(admin, usernameMulti);
            assertEquals("CN=" + usernameMulti + ",SN=12345,OU=hoho1,OU=OrgUnit2,O=AnaTom,C=SE", dataMulti.getDN());
            
            addUserMulti.setDN("SERIALNUMBER=12345,CN=" + usernameMulti + ",OU=ahoho2");
            endEntityManagementSession.changeUser(admin, addUserMulti, false, true);
            dataMulti = endEntityAccessSession.findUser(admin, usernameMulti);
            assertEquals("CN=" + usernameMulti + ",SN=12345,OU=ahoho2,OU=OrgUnit2,O=AnaTom,C=SE", dataMulti.getDN());
            
            addUserMulti.setDN("SERIALNUMBER=12345,CN=" + usernameMulti + ",OU=zhoho2");
            endEntityManagementSession.changeUser(admin, addUserMulti, false, true);
            dataMulti = endEntityAccessSession.findUser(admin, usernameMulti);
            assertEquals("CN=" + usernameMulti + ",SN=12345,OU=zhoho2,OU=OrgUnit2,O=AnaTom,C=SE", dataMulti.getDN());
            
            profile.addField(DnComponents.ORGANIZATIONALUNIT);
            profile.addField(DnComponents.ORGANIZATIONALUNIT);
            profile.setValue(DnComponents.ORGANIZATIONALUNIT, 2, "OrgUnit22");
            profile.addField(DnComponents.ORGANIZATIONALUNIT);
            profile.setValue(DnComponents.ORGANIZATIONALUNIT, 4, "OrgUnit23");
            endEntityProfileSession.changeEndEntityProfile(admin, "TESTMERGEWITHWS", profile);
            // changeEndEntity will only merge with previously created DN but not the current end entity profile
            
            addUserMulti.setDN("SERIALNUMBER=12345,CN=" + usernameMulti + ",OU=hoho2,OU=hoho3");
            endEntityManagementSession.changeUser(admin, addUserMulti, false, true);
            dataMulti = endEntityAccessSession.findUser(admin, usernameMulti);
            assertEquals("CN=" + usernameMulti + ",SN=12345,OU=hoho2,OU=hoho3,O=AnaTom,C=SE", dataMulti.getDN());
            
            addUserMulti.setDN("SERIALNUMBER=12345,CN=" + usernameMulti + ",OU=hoho2,OU=hoho3,OU=hoho4");
            endEntityManagementSession.changeUser(admin, addUserMulti, false, true);
            dataMulti = endEntityAccessSession.findUser(admin, usernameMulti);
            assertEquals("CN=" + usernameMulti + ",SN=12345,OU=hoho2,OU=hoho3,OU=hoho4,O=AnaTom,C=SE", dataMulti.getDN());
            
            addUserMulti.setDN("SERIALNUMBER=12345,CN=" + usernameMulti + ",OU=hoho2,OU=hoho5");
            endEntityManagementSession.changeUser(admin, addUserMulti, false, true);
            dataMulti = endEntityAccessSession.findUser(admin, usernameMulti);
            assertEquals("CN=" + usernameMulti + ",SN=12345,OU=hoho2,OU=hoho5,OU=hoho4,O=AnaTom,C=SE", dataMulti.getDN());
            
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
                addUser = new EndEntityInformation(username, subjectDN, caId, "dnsName=foo.bar.com,dnsName=foo1.bar.com,rfc822Name=foo@bar.com", null,
                        EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), profileId,
                        CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, new Date(), new Date(), SecConst.TOKEN_SOFT_P12, null);
                addUser.setPassword("foo123");
                try {
                    endEntityManagementSession.addUser(admin, addUser, false);
                    fail("Should not be allowed since we have altNames that are not allowed in the profile.");
                } catch (EndEntityProfileValidationException e) {
                    // NOPMD
                }
                // Add the required end entity profile fields
                profile.addField(DnComponents.DNSNAME);
                profile.addField(DnComponents.DNSNAME);
                profile.addField(DnComponents.DNSNAME);
                profile.addField(DnComponents.RFC822NAME);
                endEntityProfileSession.changeEndEntityProfile(admin, "TESTMERGEWITHWS", profile);
                endEntityManagementSession.addUser(admin, addUser, false);
                data = endEntityAccessSession.findUser(admin, username);
                assertEquals("JurisdictionCountry=NO,JurisdictionState=California,"
                        + "JurisdictionLocality=Stockholm,CN=foo subject,"
                        + "OU=FooOrgUnit,OU=OrgUnit22,OU=OrgUnit23,O=Bar",
                        data.getDN());
                // This returns slightly different between JDK 7 and JDK 8, but we only support >= JDK 8 so
                assertEquals("dnsName=foo.bar.com,dnsName=foo1.bar.com,rfc822Name=foo@bar.com", data.getSubjectAltName());
                // Try with some altName value to merge
                endEntityManagementSession.deleteUser(admin, username);
                profile.setValue(DnComponents.DNSNAME, 0, "server.bad.com");
                profile.setValue(DnComponents.DNSNAME, 1, "server.superbad.com");
                // The merge only handles consecutive default value for each DN component, i.e. defaultname for 0 and 1, not for 0 and 2
                // The resulting altName will have 4 dnsNames, so we must allow this amount
                profile.addField(DnComponents.DNSNAME);
                endEntityProfileSession.changeEndEntityProfile(admin, "TESTMERGEWITHWS", profile);
                endEntityManagementSession.addUser(admin, addUser, false);
                data = endEntityAccessSession.findUser(admin, username);
                assertEquals("JurisdictionCountry=NO,JurisdictionState=California,"
                        + "JurisdictionLocality=Stockholm,CN=foo subject,"
                        + "OU=FooOrgUnit,OU=OrgUnit22,OU=OrgUnit23,O=Bar",
                        data.getDN());
                // This returns slightly different between JDK 7 and JDK 8, but we only support >= JDK 8 so
                assertEquals("DNSNAME=server.bad.com,DNSNAME=server.superbad.com,"
                        + "dnsName=foo.bar.com,dnsName=foo1.bar.com,rfc822Name=foo@bar.com", data.getSubjectAltName());
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
        EndEntityInformation userdata = new EndEntityInformation(authUsername, "C=SE, O=AnaTom, CN=" + username, caId, null, email, new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, null);
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
            final Role role = roleSession.persistRole(admin, new Role(null, testRole, Collections.singletonList(StandardRules.CAACCESSBASE.resource()), null));
            roleMemberSession.persist(admin, new RoleMember(X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                    CertTools.getIssuerDN(adminCert).hashCode(), RoleMember.NO_PROVIDER,
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
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, caId);
        endEntityManagementSession.addUser(admin, username2, pwd, "C=SE, O=PrimeKey, CN=" + username2, null, null, true,
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, caId);
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
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, caId);
        endEntityManagementSession.addUser(admin, username2, pwd, "C=SE, O=PrimeKey, CN=" + username2, null, null, true,
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, caId);
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
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, caId);
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
                    CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_NO_PROFILE, EndEntityConstants.NO_END_ENTITY_PROFILE,
                    CertificateConstants.NO_CRL_PARTITION, null, now);
            internalCertStoreSession.storeCertificateNoAuth(admin, x509Certificate2, USERNAME, fingerprint2, CertificateConstants.CERT_ARCHIVED,
                    CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_NO_PROFILE, EndEntityConstants.NO_END_ENTITY_PROFILE,
                    CertificateConstants.NO_CRL_PARTITION, null, now);
            internalCertStoreSession.storeCertificateNoAuth(admin, x509Certificate3, USERNAME, fingerprint3, CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION,
                    CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_NO_PROFILE, EndEntityConstants.NO_END_ENTITY_PROFILE,
                    CertificateConstants.NO_CRL_PARTITION, null, now);
            internalCertStoreSession.storeCertificateNoAuth(admin, x509Certificate4, USERNAME, fingerprint4, CertificateConstants.CERT_REVOKED,
                    CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_NO_PROFILE, EndEntityConstants.NO_END_ENTITY_PROFILE,
                    CertificateConstants.NO_CRL_PARTITION, null, now);
            // A certificate that has expired, but status has not been changed to ARCHIVED by the CRL worker
            internalCertStoreSession.storeCertificateNoAuth(admin, x509Certificate5, USERNAME, fingerprint5, CertificateConstants.CERT_ACTIVE,
                    CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_NO_PROFILE, EndEntityConstants.NO_END_ENTITY_PROFILE,
                    CertificateConstants.NO_CRL_PARTITION, null, now);
            // Artificial test vector where certificate has not expired, but the status is still set to archived
            internalCertStoreSession.storeCertificateNoAuth(admin, x509Certificate6, USERNAME, fingerprint5, CertificateConstants.CERT_ARCHIVED,
                    CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_NO_PROFILE, EndEntityConstants.NO_END_ENTITY_PROFILE,
                    CertificateConstants.NO_CRL_PARTITION, null, now);
            // Revoke user
            endEntityManagementSession.revokeUser(admin, USERNAME, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
            // Get all certificate except the revoked ones
            final List<CertificateDataWrapper> cdws = certificateStoreSession.getCertificateDataByUsername(USERNAME, false, Collections.singletonList(CertificateConstants.CERT_REVOKED));
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
    
    /** Test to ensure added ObjectSid standard certificate extension does not interfere with 
     * custom extension with same OID. Only relevant for enrollment in Microsoft environemnts.*/
    @Test
    public void testCustomExtensionMicrosoftObjectSid() throws Exception {
        
        AvailableCustomCertificateExtensionsConfiguration cceConfig = new AvailableCustomCertificateExtensionsConfiguration();
        
        Properties props = new Properties();
        props.put("translatable", "FALSE");
        props.put("encoding", "DEROCTETSTRING");
        cceConfig.addCustomCertExtension(1000, CertTools.OID_MS_SZ_OID_NTDS_CA_SEC_EXT, 
                "ObjectSid", BasicCertificateExtension.class.getName(), false, false, props);
        globalConfSession.saveConfiguration(admin, cceConfig);
	
        // ee cert profile
        CertificateProfile endEntityCertprofile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        List<Integer> usedExtensions = new ArrayList<>();
        usedExtensions.add(1000);
        endEntityCertprofile.setUsedCertificateExtensions(usedExtensions);
        int endEntityCertificateProfileId = certificateProfileSession.addCertificateProfile(admin, "CertProfileObjectSid", endEntityCertprofile);
        log.info("created end entity certificate profile id: " + endEntityCertificateProfileId);

        // end entity profile
        EndEntityProfile endEntityProfile = new EndEntityProfile();
        List<Integer> availableCertProfiles = endEntityProfile.getAvailableCertificateProfileIds();
        availableCertProfiles.add(endEntityCertificateProfileId);
        endEntityProfile.setAvailableCertificateProfileIds(availableCertProfiles);
        endEntityProfile.setAvailableCAs(Arrays.asList(SecConst.ALLCAS));

        int endEntityProfileId = endEntityProfileSession.addEndEntityProfile(admin, "EEProfileObjectSid", endEntityProfile);
        log.info("Created end entity profile id: " + endEntityProfileId);
        
        String username =  genRandomUserName();
        ExtendedInformation ei = new ExtendedInformation();
        ei.setExtensionData(CertTools.OID_MS_SZ_OID_NTDS_CA_SEC_EXT, "0123456789abcdef");
        EndEntityInformation endEntityInformation = new EndEntityInformation(username, "CN=" + username, caId, null, null, 
                EndEntityTypes.ENDUSER.toEndEntityType(), endEntityProfileId, 
                endEntityCertificateProfileId, SecConst.TOKEN_SOFT_P12, ei);
        endEntityInformation.setPassword(username);
        endEntityManagementSession.addUser(admin, endEntityInformation, false);
       
        EndEntityInformation data = endEntityAccessSession.findUser(admin, username);
        assertNotNull(data);
        assertEquals(username, data.getUsername());  
        assertNotNull(data.getExtendedInformation().getExtensionDataOids());
        assertEquals(data.getExtendedInformation().getExtensionData(
                                CertTools.OID_MS_SZ_OID_NTDS_CA_SEC_EXT),"0123456789abcdef");  
        
        endEntityManagementSession.deleteUser(admin, username);
        endEntityProfileSession.removeEndEntityProfile(admin, "EEProfileObjectSid");
        certificateProfileSession.removeCertificateProfile(admin, "CertProfileObjectSid");
        
        cceConfig = new AvailableCustomCertificateExtensionsConfiguration();
        cceConfig.removeCustomCertExtension(1000);
        globalConfSession.saveConfiguration(admin, cceConfig);
        
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
            publisherQueueSession.plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(admin, publisher, PublishQueueProcessWorker.DEFAULT_QUEUE_WORKER_JOBS);
            assertEquals("Publisher should have been called with 'on hold' revocation reason.",
                    RevocationReasons.CERTIFICATEHOLD.getDatabaseValue(), publisherTestSession.getLastMockedThrowAwayRevocationReason());
            // Activate again
            publisherTestSession.setLastMockedThrowAwayRevocationReason(-123);
            assertEquals("Publisher should not have been called.", -123, publisherTestSession.getLastMockedThrowAwayRevocationReason());
            endEntityManagementSession.revokeCert(admin, THROWAWAY_CERT_SERIAL, cainfo.getSubjectDN(), RevocationReasons.NOT_REVOKED.getDatabaseValue());
            publisherQueueSession.plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(admin, publisher, PublishQueueProcessWorker.DEFAULT_QUEUE_WORKER_JOBS);
            assertEquals("Publisher should have been called THROW_AWAY_CERT_SERIAL 'not revoked' revocation reason.",
                    RevocationReasons.NOT_REVOKED.getDatabaseValue(), publisherTestSession.getLastMockedThrowAwayRevocationReason());
            // Revoke permanently
            publisherTestSession.setLastMockedThrowAwayRevocationReason(-123);
            assertEquals("Publisher should not have been called.", -123, publisherTestSession.getLastMockedThrowAwayRevocationReason());
            endEntityManagementSession.revokeCert(admin, THROWAWAY_CERT_SERIAL, cainfo.getSubjectDN(), RevocationReasons.SUPERSEDED.getDatabaseValue());
            publisherQueueSession.plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(admin, publisher, PublishQueueProcessWorker.DEFAULT_QUEUE_WORKER_JOBS);
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
    
    @Test
    public void testCnCopyToMsUpn() throws Exception {
                
        EndEntityProfile profile = new EndEntityProfile();
        profile.addField(DnComponents.UNIFORMRESOURCEID);
        profile.setAvailableCAs(Arrays.asList(SecConst.ALLCAS));

        int eeProfileId = endEntityProfileSession.addEndEntityProfile(admin, EE_PROFILE_NAME_COPY_UPN, profile);
        
        // add EE(username = "prefix_user" + random, CN = "prefix_cn" + random)
        // change EE with copied stuff as applicable
        // change EE without copied stuff
        // all cases assert SAN
        // wrap in try final, final -> add EE name to list
        
        // create EEP with MS UPN - no copy
        profile.addField(DnComponents.UPN);
        profile.setCopy(DnComponents.UPN, 0, false);
        profile.setValue(DnComponents.UPN, 0, "abcd.com");
        endEntityProfileSession.changeEndEntityProfile(admin, EE_PROFILE_NAME_COPY_UPN, profile);
        doAndVerifyUserOperation(eeProfileId, "uniformResourceId=asdf.ghj", "uniformResourceId=asdf.ghj", "uniformResourceId=asdf.poi", "uniformResourceId=asdf.poi", null, null);
        doAndVerifyUserOperation(eeProfileId, "uniformResourceId=asdf.ghj,upn=abcd@wef.com", "uniformResourceId=asdf.ghj,upn=abcd@wef.com", 
                "uniformResourceId=asdf.poi,upn=abcd@wef.jkl", "uniformResourceId=asdf.poi,upn=abcd@wef.jkl", null, null);
        
        // create EEP with MS UPN - no copy, drop down
        profile.setValue(DnComponents.UPN, 0, "abcd.com;wxyz.com");
        endEntityProfileSession.changeEndEntityProfile(admin, EE_PROFILE_NAME_COPY_UPN, profile);
        doAndVerifyUserOperation(eeProfileId, "upn=abcd@wxyz.com", "upn=abcd@wxyz.com", "upn=abcd@abcd.com", "upn=abcd@abcd.com", 
                            "uniformResourceId=asdf.poi,upn=abcd@wxyz.com", "uniformResourceId=asdf.poi,upn=abcd@wxyz.com");
        
        // modify EEP with MS UPN - copy -value
        profile.setCopy(DnComponents.UPN, 0, true);
        profile.setValue(DnComponents.UPN, 0, "abcd.com");
        endEntityProfileSession.changeEndEntityProfile(admin, EE_PROFILE_NAME_COPY_UPN, profile);
        doAndVerifyUserOperation(eeProfileId, "", "UPN=USER_CN@abcd.com", "", "UPN=USER_CN@abcd.com", 
                "uniformResourceId=asdf.poi,UPN=USER_CN@abcd.com", "uniformResourceId=asdf.poi,UPN=USER_CN@abcd.com");

        // modify EEP with MS UPN - no copy + required + value
        profile.setCopy(DnComponents.UPN, 0, false);
        profile.setRequired(DnComponents.UPN, 0, true);
        profile.setValue(DnComponents.UPN, 0, "abcd.com");
        endEntityProfileSession.changeEndEntityProfile(admin, EE_PROFILE_NAME_COPY_UPN, profile);
        doAndVerifyUserOperation(eeProfileId, "upn=some@abcd.com", "upn=some@abcd.com", 
                            "upn=thing@abcd.com", "upn=thing@abcd.com", null, null);
        
        // modify EEP with MS UPN - copy + required + value
        profile.setCopy(DnComponents.UPN, 0, true);
        endEntityProfileSession.changeEndEntityProfile(admin, EE_PROFILE_NAME_COPY_UPN, profile);
        doAndVerifyUserOperation(eeProfileId, "", "UPN=USER_CN@abcd.com", "", "UPN=USER_CN@abcd.com", 
                "uniformResourceId=asdf.poi,UPN=USER_CN@abcd.com", "uniformResourceId=asdf.poi,UPN=USER_CN@abcd.com");
        doAndVerifyUserOperation(eeProfileId, "UPN=USER_CN@abcd.com", "UPN=USER_CN@abcd.com", 
                "UPN=USER_CN@abcd.com", "UPN=USER_CN@abcd.com", 
                "uniformResourceId=asdf.poi", "uniformResourceId=asdf.poi, UPN=USER_CN@abcd.com");
        
        // modify EEP with 2x MS UPN - (copy + required + value) + (copy + value)
        profile.addField(DnComponents.UPN);
        profile.setCopy(DnComponents.UPN, 1, true);
        profile.setValue(DnComponents.UPN, 1, "pqrs.net");
        endEntityProfileSession.changeEndEntityProfile(admin, EE_PROFILE_NAME_COPY_UPN, profile);
        doAndVerifyUserOperation(eeProfileId, "", "UPN=USER_CN@abcd.com, UPN=USER_CN@pqrs.net", 
                "uniformResourceId=asdf.poi", 
                "uniformResourceId=asdf.poi, UPN=USER_CN@abcd.com, UPN=USER_CN@pqrs.net", null, null);
        // either both or none of the copy UPN fields
        doAndVerifyUserOperation(eeProfileId, "UPN=USER_CN@abcd.com, UPN=USER_CN@pqrs.net", 
                "UPN=USER_CN@abcd.com, UPN=USER_CN@pqrs.net", 
                "uniformResourceId=asdf.poi", 
                "uniformResourceId=asdf.poi, UPN=USER_CN@abcd.com, UPN=USER_CN@pqrs.net", null, null);
        
        // modify EEP with 2x MS UPN - (copy + required + value) + (copy + required + value)
        profile.setRequired(DnComponents.UPN, 1, true);
        endEntityProfileSession.changeEndEntityProfile(admin, EE_PROFILE_NAME_COPY_UPN, profile);
        doAndVerifyUserOperation(eeProfileId, "", "UPN=USER_CN@abcd.com, UPN=USER_CN@pqrs.net", 
                "uniformResourceId=asdf.poi", 
                "uniformResourceId=asdf.poi, UPN=USER_CN@abcd.com, UPN=USER_CN@pqrs.net", null, null);
        
        // modify EEP with 2x MS UPN - (copy + required + value) + (no copy + value)
        profile.setRequired(DnComponents.UPN, 1, false);
        profile.setCopy(DnComponents.UPN, 1, false);
        endEntityProfileSession.changeEndEntityProfile(admin, EE_PROFILE_NAME_COPY_UPN, profile);
        doAndVerifyUserOperation(eeProfileId, "", "UPN=USER_CN@abcd.com", 
                "uniformResourceId=asdf.poi", 
                "uniformResourceId=asdf.poi, UPN=USER_CN@abcd.com", null, null);
        doAndVerifyUserOperation(eeProfileId, "UPN=USER_CN@pqrs.net", "UPN=USER_CN@pqrs.net, UPN=USER_CN@abcd.com", 
                "uniformResourceId=asdf.poi", 
                "uniformResourceId=asdf.poi, UPN=USER_CN@abcd.com", null, null);        
        doAndVerifyUserOperation(eeProfileId, "UPN=USER_CN@pqrs.net", "UPN=USER_CN@pqrs.net, UPN=USER_CN@abcd.com", 
                "uniformResourceId=asdf.poi,UPN=USER_CN@pqrs.net", 
                "uniformResourceId=asdf.poi,UPN=USER_CN@pqrs.net, UPN=USER_CN@abcd.com", null, null);
        
        // modify EEP with 2x MS UPN - (copy + value) + (copy + value)
        profile.setRequired(DnComponents.UPN, 0, false);
        profile.setCopy(DnComponents.UPN, 1, true);
        endEntityProfileSession.changeEndEntityProfile(admin, EE_PROFILE_NAME_COPY_UPN, profile);
        doAndVerifyUserOperation(eeProfileId, "", "UPN=USER_CN@abcd.com, UPN=USER_CN@pqrs.net", 
                "uniformResourceId=asdf.poi", 
                "uniformResourceId=asdf.poi, UPN=USER_CN@abcd.com, UPN=USER_CN@pqrs.net", null, null);
        doAndVerifyUserOperation(eeProfileId, "", "UPN=USER_CN@abcd.com, UPN=USER_CN@pqrs.net", 
                "", "UPN=USER_CN@abcd.com, UPN=USER_CN@pqrs.net", null, null);
        
        // modify EEP with UPN(copy), DNSName(copy)
        profile.removeField(DnComponents.UPN, 1);
        profile.addField(DnComponents.DNSNAME);
        profile.setCopy(DnComponents.DNSNAME, 0, true);
        endEntityProfileSession.changeEndEntityProfile(admin, EE_PROFILE_NAME_COPY_UPN, profile);
        doAndVerifyUserOperation(eeProfileId, "", "DNSNAME=USER_CN, UPN=USER_CN@abcd.com", 
                "", "DNSNAME=USER_CN, UPN=USER_CN@abcd.com", null, null);
        
        // modify EEP with UPN(no copy), DNSName(no copy)
        profile.setCopy(DnComponents.UPN, 0, false);
        profile.setCopy(DnComponents.DNSNAME, 0, false);
        profile.addField(DnComponents.RFC822NAME);
        endEntityProfileSession.changeEndEntityProfile(admin, EE_PROFILE_NAME_COPY_UPN, profile);
        doAndVerifyUserOperation(eeProfileId, "uniformResourceId=asdf.poi", "uniformResourceId=asdf.poi", 
                "uniformResourceId=asdf.poi,upn=xxUSER_CN@abcd.com,dnsName=xxUSER_CN,rfc822Name=xxUSER_EMAIL", 
                "uniformResourceId=asdf.poi,upn=xxUSER_CN@abcd.com,dnsName=xxUSER_CN,rfc822Name=xxUSER_EMAIL", null, null);
        
        // allow merge dn
        profile.setAllowMergeDn(true);
        profile.setValue(DnComponents.UPN, 0, "abcd.com");
        profile.setCopy(DnComponents.UPN, 0, true);
        profile.setCopy(DnComponents.DNSNAME, 0, true);
        profile.addField(DnComponents.DNSNAME);
        profile.setValue(DnComponents.DNSNAME, 1, "abcd.pqrs.wxyz");
        profile.setUse(DnComponents.RFC822NAME, 0, true);
        endEntityProfileSession.changeEndEntityProfile(admin, EE_PROFILE_NAME_COPY_UPN, profile);
        doAndVerifyUserOperation(eeProfileId, "uniformResourceId=asdf.poi", 
                "UPN=USER_CN@abcd.com,DNSNAME=USER_CN,DNSNAME=abcd.pqrs.wxyz,RFC822NAME=USER_EMAIL,uniformResourceId=asdf.poi", 
                "", "UPN=USER_CN@abcd.com,DNSNAME=USER_CN,DNSNAME=abcd.pqrs.wxyz,RFC822NAME=USER_EMAIL,uniformResourceId=asdf.poi", null, null);
        
        doAndVerifyUserOperation(eeProfileId, "uniformResourceId=asdf.poi", 
                "UPN=USER_CN@abcd.com,DNSNAME=USER_CN,DNSNAME=abcd.pqrs.wxyz,RFC822NAME=USER_EMAIL,uniformResourceId=asdf.poi", 
                "UPN=USER_CN@abcd.com,DNSNAME=USER_CN,DNSNAME=abcd.pqrs.wxyz,RFC822NAME=USER_EMAIL,uniformResourceId=asdf.poi",
                "UPN=USER_CN@abcd.com,DNSNAME=USER_CN,DNSNAME=abcd.pqrs.wxyz,RFC822NAME=USER_EMAIL,uniformResourceId=asdf.poi", null, null);
        
    }
    
    private String prepareAltNamesFromTemplate(String tempate, String cn, String email) {
         return tempate.replaceAll("USER_CN", cn).replaceAll("USER_EMAIL", email);
    }
    
    private String doAndVerifyUserOperation(int eeProfileId, 
            String requestAltNameAdd, String expectedAltNameAdd, 
            String requestAltNameChange1, String expectedAltNameChange1,
            String requestAltNameChange2, String expectedAltNameChange2) {
        final String prefixUsername = "userMsUpnCopy";
        final String prefixCn = "cnMsUpnCopy";
        final Random random = new Random();
        final String userName = prefixUsername + random.nextLong();
        final String commonName = prefixCn + random.nextLong();
        final String email = userName + "@somedomain.com";
        
        requestAltNameAdd = prepareAltNamesFromTemplate(requestAltNameAdd, commonName ,email);
        expectedAltNameAdd = prepareAltNamesFromTemplate(expectedAltNameAdd, commonName ,email);
        final String commonNameFirstUpdate = requestAltNameChange1.isEmpty() ? commonName : prefixCn + random.nextLong();
        requestAltNameChange1 = prepareAltNamesFromTemplate(requestAltNameChange1, commonNameFirstUpdate ,email);
        expectedAltNameChange1 = prepareAltNamesFromTemplate(expectedAltNameChange1, commonNameFirstUpdate ,email);
        final String commonNameSecondUpdate = StringUtils.isEmpty(requestAltNameChange2) ? commonName : prefixCn + random.nextLong();
        if (requestAltNameChange2!=null) {
            requestAltNameChange2 = prepareAltNamesFromTemplate(requestAltNameChange2, commonNameSecondUpdate ,email);
            expectedAltNameChange2 = prepareAltNamesFromTemplate(expectedAltNameChange2, commonNameSecondUpdate ,email);
        }
        
        EndEntityInformation userData = new EndEntityInformation(userName, "CN="+commonName, caId, null, 
                email, EndEntityTypes.ENDUSER.toEndEntityType(), 
                eeProfileId, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, null);
        
        try {
            userData = doAndVerifyAddUser(userData, requestAltNameAdd, expectedAltNameAdd);
            userData.setDN("CN="+commonNameFirstUpdate);
            userData = doAndVerifyChangeUser(userData, requestAltNameChange1, expectedAltNameChange1);
            if(requestAltNameChange2!=null) {
                userData.setDN("CN="+commonNameSecondUpdate);
                userData = doAndVerifyChangeUser(userData, requestAltNameChange2, expectedAltNameChange2);
            }
        } finally {
            try {
               endEntityManagementSession.deleteUser(admin, userName); 
            } catch (Exception e) {}
        }
        
        return userName;
    }
    
    private EndEntityInformation doAndVerifyAddUser(EndEntityInformation userData,
            String requestAltName, String expectedAltName) {
        userData.setSubjectAltName(requestAltName);
        userData.setPassword("hardcoded");
        EndEntityInformation createdUser = null;
        try {
             createdUser = endEntityManagementSession.addUser(admin, userData, false);
        } catch (Exception e) {
            fail("Failed to create user with SAN: " + requestAltName + ", expected: " + expectedAltName);
        }
        assertEquals("Added user SAN mismatch", createdUser.getSubjectAltName(), expectedAltName);
        return userData;
    }
    
    private EndEntityInformation doAndVerifyChangeUser(EndEntityInformation currentUserData, 
            String requestAltName, String expectedAltName) {
        EndEntityInformation userData = new EndEntityInformation(currentUserData);
        userData.setSubjectAltName(requestAltName);
        userData.setPassword("hardcoded");
        EndEntityInformation updatedUser = null;
        try {
            endEntityManagementSession.changeUser(admin, userData, false);
            updatedUser = endEntityAccessSession.findUser(admin, currentUserData.getUsername());
        } catch (Exception e) {
            fail("Failed to update user with SAN: " + requestAltName + ", expected: " + expectedAltName);
        }
        assertEquals("Updated user SAN mismatch", updatedUser.getSubjectAltName(), expectedAltName);
        return userData;
    }
    
    protected CAInfo setUpThrowAwayPublishingTest(final boolean useQueue, final boolean useNoConflictCertificateData) throws Exception {
        return super.setUpThrowAwayPublishingTest(useQueue, useNoConflictCertificateData, false, caId, THROWAWAY_CERT_PROFILE, THROWAWAY_PUBLISHER);
    }
    
    protected void cleanUpThrowAwayPublishingTest() throws Exception {
        super.cleanUpThrowAwayPublishingTest(caId, THROWAWAY_CERT_PROFILE, THROWAWAY_PUBLISHER, THROWAWAY_CERT_SERIAL);
    }
}
