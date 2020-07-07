package org.ejbca.core.model.ra;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/** Tests variables for user notifications
 * @version $Id$
 */
public class UserNotificationParamGenSystemTest {
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);    
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private static AuthenticationToken TOKEN = new TestAlwaysAllowLocalAuthenticationToken(UserNotificationParamGenSystemTest.class.getSimpleName());
    private static String USERNAME = "UserNotificationCertExpirationEmailTestUser";
    private static String CA_NAME = "CaUserNotificationParamTest";
    private static String CA_DN = "CN=" + CA_NAME;
    private static String CA_TOKEN_PIN = "foo123";
    private static X509Certificate X_509_CERTIFICATE;
    private X509CA ca;
      
    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    } 
    
    @Before
    public void setup() throws Exception {
        ca = CaTestUtils.createTestX509CA(CA_DN, CA_TOKEN_PIN.toCharArray(), false);
        ca.setStatus(CAConstants.CA_ACTIVE);
        caSession.addCA(TOKEN, ca);
    }
       
    @After
    public void tearDown() throws Exception {
        if(X_509_CERTIFICATE != null) {
            internalCertificateStoreSession.removeCertificate(X_509_CERTIFICATE);
        }
        if (endEntityManagementSession.existsUser(USERNAME)) {
            endEntityManagementSession.deleteUser(TOKEN, USERNAME);
        }
        if (ca != null) {
            CaTestUtils.removeCa(TOKEN, ca.getCAInfo());
        }
    }
    
    //Test that rfc822Name parameter is being generated for expiring certificates notifications
    @Test
    public void testUserNotificationCertExpirationEmailParam() throws Exception{
        KeyPair userkeys;
        Date now = new Date();
        int caid = ca.getCAId();
        //given
        EndEntityInformation userdata =
                new EndEntityInformation(USERNAME, "CN=cnfoo,O=orgfoo,C=SE", caid, 
                                         "rfc822Name=fooalt@foo.se", "fooee@foo.se", 
                                         EndEntityConstants.STATUS_GENERATED, 
                                         new EndEntityType(EndEntityTypes.ENDUSER), 
                                         EndEntityConstants.EMPTY_END_ENTITY_PROFILE, 
                                         CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, 
                                         now, null, SecConst.TOKEN_SOFT_P12, null);
        userdata.setPassword("foo123");
        userkeys = KeyTools.genKeys("1024", "RSA");
        endEntityManagementSession.addUser(TOKEN, userdata, true);
        X_509_CERTIFICATE = (X509Certificate) signSession.createCertificate(TOKEN, USERNAME, "foo123", new PublicKeyWrapper(userkeys.getPublic()));
        final UserNotificationParamGen paramGen = new UserNotificationParamGen(userdata, X_509_CERTIFICATE);
        assertNotNull("paramGen is null", paramGen);
        //when
        final String msg = paramGen.interpolate("${USERNAME} ${user.USERNAME} ${user.EE.EMAIL} ${user.SAN.EMAIL} ${expiringCert.CERTSUBJECTDN}");
        //then
        assertFalse("Interpolate message failed", (msg==null || msg.length()==0));
        assertEquals("UserNotificationCertExpirationEmailTestUser UserNotificationCertExpirationEmailTestUser fooee@foo.se fooalt@foo.se CN=cnfoo,O=orgfoo,C=SE", msg);
    }
}