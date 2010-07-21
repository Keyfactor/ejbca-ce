package org.ejbca.core.ejb.ca.sign;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.ejb.DuplicateKeyException;
import javax.ejb.EJB;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.CertificateRequestSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionRemote;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.certificateprofiles.EndUserCertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.PKCS10RequestMessage;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.keystore.KeyTools;

public class CustomCertSerialnumberTest extends CaTestCase {
	
    private static final Logger log = Logger.getLogger(CustomCertSerialnumberTest.class);
    
    private final Admin admin = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);
    private static int rsacaid = 0;
    
    int fooCertProfile;
    int fooEEProfile;
    
    @EJB
    private CAAdminSessionRemote caAdminSession;
    
    @EJB
    private CertificateStoreSessionRemote certificateStoreSession;
    
    @EJB
    private CertificateRequestSessionRemote certificateRequestSession;
    
    @EJB
    private RaAdminSessionRemote raAdminSession;
    
    @EJB
    private UserAdminSessionRemote userAdminSession;

    public CustomCertSerialnumberTest(String name) throws Exception {
	    super(name);

	    CryptoProviderTools.installBCProvider();

	    assertTrue("Could not create TestCA.", createTestCA());
	    CAInfo inforsa = caAdminSession.getCAInfo(admin, "TEST");
	    assertTrue("No active RSA CA! Must have at least one active CA to run tests!", inforsa != null);
	    rsacaid = inforsa.getCAId();
    }

    public void setUp() throws Exception {

	certificateStoreSession.removeCertificateProfile(admin,"FOOCERTPROFILE");
	raAdminSession.removeEndEntityProfile(admin, "FOOEEPROFILE");
	    
        final EndUserCertificateProfile certprof = new EndUserCertificateProfile();
        certprof.setAllowKeyUsageOverride(true);
        certprof.setAllowCertSerialNumberOverride(true);
        certificateStoreSession.addCertificateProfile(admin, "FOOCERTPROFILE", certprof);
        fooCertProfile = certificateStoreSession.getCertificateProfileId(admin,"FOOCERTPROFILE");

        final EndEntityProfile profile = new EndEntityProfile(true);
        profile.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, Integer.toString(fooCertProfile));
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES,0,Integer.toString(fooCertProfile));
        profile.setValue(EndEntityProfile.AVAILKEYSTORE, 0, Integer.toString(SecConst.TOKEN_SOFT_BROWSERGEN));
        assertTrue(profile.getUse(EndEntityProfile.CERTSERIALNR, 0));
        raAdminSession.addEndEntityProfile(admin, "FOOEEPROFILE", profile);
        fooEEProfile = raAdminSession.getEndEntityProfileId(admin, "FOOEEPROFILE");
    }    
    
    public void tearDown() throws Exception {
	try {
    	    userAdminSession.deleteUser(admin, "foo");
	    log.debug("deleted user: foo");
	} catch (Exception e) {}
	try {
    	    userAdminSession.deleteUser(admin, "foo2");
	    log.debug("deleted user: foo2");
	} catch (Exception e) {}
	try {
    	    userAdminSession.deleteUser(admin, "foo3");
	    log.debug("deleted user: foo3");
	} catch (Exception e) {}

	certificateStoreSession.revokeAllCertByCA(admin, caAdminSession.getCA(admin, rsacaid).getSubjectDN(), RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
    }

    
    // Create certificate request for user: foo with cert serialnumber=1234567890
    public void test01CreateCertWithCustomSN() throws EndEntityProfileExistsException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, DuplicateKeyException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, EjbcaException, ClassNotFoundException, CertificateEncodingException, CertificateException, WaitingForApprovalException, InvalidAlgorithmParameterException {
	log.trace(">test01CreateCustomCert()");

        KeyPair rsakeys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);    	    
	BigInteger serno = SernoGenerator.instance().getSerno();
	log.debug("serno: " + serno);
	
	PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA1WithRSA",
                CertTools.stringToBcX509Name("C=SE, O=AnaTom, CN=foo"), rsakeys.getPublic(), new DERSet(),
                rsakeys.getPrivate());
        
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req);
        dOut.close();

        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bOut.toByteArray());
        boolean verify = req2.verify();
        log.debug("Verify returned " + verify);
        assertTrue(verify);
        log.debug("CertificationRequest generated successfully.");
        byte[] bcp10 = bOut.toByteArray();
        PKCS10RequestMessage p10 = new PKCS10RequestMessage(bcp10);
        p10.setUsername("foo");
        p10.setPassword("foo123");
        
        UserDataVO user = new UserDataVO("foo", "C=SE,O=AnaTom,CN=foo", rsacaid, null, "foo@anatom.se", SecConst.USER_ENDUSER, fooEEProfile, fooCertProfile,
        		SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
        user.setPassword("foo123");
	ExtendedInformation ei = user.getExtendedinformation();
	ei.setCertificateSerialNumber(serno);
	user.setExtendedinformation(ei);
        IResponseMessage resp = certificateRequestSession.processCertReq(admin, user, p10, Class.forName(org.ejbca.core.protocol.X509ResponseMessage.class.getName()));
        
        X509Certificate cert = (X509Certificate) CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
	log.debug("foo certificate serialnumber: " + cert.getSerialNumber()); 
        assertTrue(cert.getSerialNumber().compareTo(serno) == 0);
        
        log.trace("<test01CreateCustomCert()");
        
    }

    
    // Create certificate request for user: foo2 with random cert serialnumber
    public void test02CreateCertWithRandomSN() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, DuplicateKeyException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, EjbcaException, ClassNotFoundException, CertificateEncodingException, CertificateException, InvalidAlgorithmParameterException {
    	
    	log.trace(">test02CreateCertWithRandomSN()");

	KeyPair rsakeys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
	BigInteger serno = ((X509Certificate) certificateStoreSession.findCertificatesByUsername(admin, "foo").iterator().next()).getSerialNumber();
	log.debug("foo serno: " + serno);

	PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA1WithRSA",
                CertTools.stringToBcX509Name("C=SE, O=AnaTom, CN=foo2"), rsakeys.getPublic(), new DERSet(),
                rsakeys.getPrivate());
        
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req);
        dOut.close();

        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bOut.toByteArray());
        boolean verify = req2.verify();
        log.debug("Verify returned " + verify);
        assertTrue(verify);
        log.debug("CertificationRequest generated successfully.");
        byte[] bcp10 = bOut.toByteArray();
        PKCS10RequestMessage p10 = new PKCS10RequestMessage(bcp10);
        p10.setUsername("foo2");
        p10.setPassword("foo123");
        
        UserDataVO user = new UserDataVO("foo2", "C=SE,O=AnaTom,CN=foo2", rsacaid, null, "foo@anatom.se", SecConst.USER_ENDUSER, fooEEProfile, fooCertProfile,
        		SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
        user.setPassword("foo123");
	
	
	IResponseMessage resp = certificateRequestSession.processCertReq(admin, user, p10, Class.forName(org.ejbca.core.protocol.X509ResponseMessage.class.getName()));
        
        X509Certificate cert = (X509Certificate) CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
	log.debug("foo2 certificate serialnumber: " + cert.getSerialNumber()); 
        assertTrue(cert.getSerialNumber().compareTo(serno) != 0);
        
        log.trace("<test02CreateCertWithRandomSN()");
    }
    
    
    // Create certificate request for user: foo3 with cert serialnumber=1234567890 (the same as cert serialnumber of user foo)
    public void test03CreateCertWithDublicateSN() throws EndEntityProfileExistsException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, DuplicateKeyException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, ClassNotFoundException, CertificateEncodingException, CertificateException, WaitingForApprovalException, InvalidAlgorithmParameterException {
	log.trace(">test03CreateCertWithDublicateSN()");

	KeyPair rsakeys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
	BigInteger serno = ((X509Certificate) certificateStoreSession.findCertificatesByUsername(admin, "foo").iterator().next()).getSerialNumber();
	log.debug("foo serno: " + serno);

	PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA1WithRSA",
                CertTools.stringToBcX509Name("C=SE, O=AnaTom, CN=foo3"), rsakeys.getPublic(), new DERSet(),
                rsakeys.getPrivate());
        
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req);
        dOut.close();

        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bOut.toByteArray());
        boolean verify = req2.verify();
        log.debug("Verify returned " + verify);
        assertTrue(verify);
        log.debug("CertificationRequest generated successfully.");
        byte[] bcp10 = bOut.toByteArray();
        PKCS10RequestMessage p10 = new PKCS10RequestMessage(bcp10);
        p10.setUsername("foo3");
        p10.setPassword("foo123");
        
        UserDataVO user = new UserDataVO("foo3", "C=SE,O=AnaTom,CN=foo3", rsacaid, null, "foo@anatom.se", SecConst.USER_ENDUSER, fooEEProfile, fooCertProfile,
        		SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
        user.setPassword("foo123");
        ExtendedInformation ei = user.getExtendedinformation();
        ei.setCertificateSerialNumber(serno);
	user.setExtendedinformation(ei);

	IResponseMessage resp = null;
	try {
            resp = certificateRequestSession.processCertReq(admin, user, p10, Class.forName(org.ejbca.core.protocol.X509ResponseMessage.class.getName()));
	} catch (EjbcaException e) {
	    log.debug(e.getMessage());
	    assertTrue("Unexpected exception.", e.getMessage().startsWith("There is already a certificate stored in 'CertificateData' with the serial number"));
	}
       	assertNull(resp);
    }

}