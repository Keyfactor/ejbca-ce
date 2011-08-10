package org.ejbca.core.ejb.ca.sign;

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

import javax.persistence.PersistenceException;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ra.CertificateRequestSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.util.InterfaceCache;

/**
 * 
 * @version $Id$
 */
public class CustomCertSerialnumberTest extends CaTestCase {

	private static final Logger log = Logger.getLogger(CustomCertSerialnumberTest.class);

	private final AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
	private static int rsacaid = 0;

	int fooCertProfileId;
	int fooEEProfileId;

	private CaSessionRemote caSession = InterfaceCache.getCaSession();
	private CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();
	private CertificateRequestSessionRemote certificateRequestSession = InterfaceCache.getCertficateRequestSession();
	private CertificateProfileSessionRemote certificateProfileSession = InterfaceCache.getCertificateProfileSession();
	private EndEntityProfileSessionRemote endEntityProfileSession = InterfaceCache.getEndEntityProfileSession();
	private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();

	public CustomCertSerialnumberTest(String name) throws Exception {
		super(name);

		CryptoProviderTools.installBCProvider();

		assertTrue("Could not create TestCA.", createTestCA());
		CAInfo inforsa = caSession.getCAInfo(admin, "TEST");
		assertTrue("No active RSA CA! Must have at least one active CA to run tests!", inforsa != null);
		rsacaid = inforsa.getCAId();
	}

	public void setUp() throws Exception {

		certificateProfileSession.removeCertificateProfile(admin,"FOOCERTPROFILE");
		endEntityProfileSession.removeEndEntityProfile(admin, "FOOEEPROFILE");

		final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
		certprof.setAllowKeyUsageOverride(true);
		certprof.setAllowCertSerialNumberOverride(true);
		certificateProfileSession.addCertificateProfile(admin, "FOOCERTPROFILE", certprof);
		fooCertProfileId = certificateProfileSession.getCertificateProfileId("FOOCERTPROFILE");

		final EndEntityProfile profile = new EndEntityProfile(true);
		profile.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, Integer.toString(fooCertProfileId));
		profile.setValue(EndEntityProfile.AVAILCERTPROFILES,0,Integer.toString(fooCertProfileId));
		profile.setValue(EndEntityProfile.AVAILKEYSTORE, 0, Integer.toString(SecConst.TOKEN_SOFT_BROWSERGEN));
		assertTrue(profile.getUse(EndEntityProfile.CERTSERIALNR, 0));
		endEntityProfileSession.addEndEntityProfile(admin, "FOOEEPROFILE", profile);
		fooEEProfileId = endEntityProfileSession.getEndEntityProfileId(admin, "FOOEEPROFILE");
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

		certificateStoreSession.revokeAllCertByCA(admin, caSession.getCA(admin, rsacaid).getSubjectDN(), RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
	}


	// Create certificate request for user: foo with cert serialnumber=1234567890
	public void test01CreateCertWithCustomSN() throws EndEntityProfileExistsException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, PersistenceException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, EjbcaException, ClassNotFoundException, CertificateEncodingException, CertificateException, WaitingForApprovalException, InvalidAlgorithmParameterException, CesecoreException {
		log.trace(">test01CreateCustomCert()");

		KeyPair rsakeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);    	    
		BigInteger serno = SernoGenerator.instance().getSerno();
		log.debug("serno: " + serno);

		PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA1WithRSA",
				CertTools.stringToBcX509Name("C=SE, O=AnaTom, CN=foo"), rsakeys.getPublic(), new DERSet(),
				rsakeys.getPrivate());

		PKCS10RequestMessage p10 = new PKCS10RequestMessage(req);
		p10.setUsername("foo");
		p10.setPassword("foo123");

		EndEntityInformation user = new EndEntityInformation("foo", "C=SE,O=AnaTom,CN=foo", rsacaid, null, "foo@anatom.se", SecConst.USER_ENDUSER, fooEEProfileId, fooCertProfileId,
				SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
		user.setPassword("foo123");
		ExtendedInformation ei = new ExtendedInformation();
		ei.setCertificateSerialNumber(serno);
		user.setExtendedinformation(ei);
		ResponseMessage resp = certificateRequestSession.processCertReq(admin, user, p10, X509ResponseMessage.class);

		X509Certificate cert = (X509Certificate) CertTools.getCertfromByteArray(resp.getResponseMessage());
		assertNotNull("Failed to create certificate", cert);
		log.debug("Cert=" + cert.toString());
		log.debug("foo certificate serialnumber: " + cert.getSerialNumber()); 
		assertTrue(cert.getSerialNumber().compareTo(serno) == 0);

		log.trace("<test01CreateCustomCert()");

	}


	// Create certificate request for user: foo2 with random cert serialnumber
	public void test02CreateCertWithRandomSN() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, PersistenceException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, EjbcaException, ClassNotFoundException, CertificateEncodingException, CertificateException, InvalidAlgorithmParameterException, CesecoreException {

		log.trace(">test02CreateCertWithRandomSN()");

		KeyPair rsakeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
		BigInteger serno = ((X509Certificate) certificateStoreSession.findCertificatesByUsername("foo").iterator().next()).getSerialNumber();
		log.debug("foo serno: " + serno);

		PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA1WithRSA",
				CertTools.stringToBcX509Name("C=SE, O=AnaTom, CN=foo2"), rsakeys.getPublic(), new DERSet(),
				rsakeys.getPrivate());

		PKCS10RequestMessage p10 = new PKCS10RequestMessage(req);
		p10.setUsername("foo2");
		p10.setPassword("foo123");

		EndEntityInformation user = new EndEntityInformation("foo2", "C=SE,O=AnaTom,CN=foo2", rsacaid, null, "foo@anatom.se", SecConst.USER_ENDUSER, fooEEProfileId, fooCertProfileId,
				SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
		user.setPassword("foo123");


		ResponseMessage resp = certificateRequestSession.processCertReq(admin, user, p10, X509ResponseMessage.class);

		X509Certificate cert = (X509Certificate) CertTools.getCertfromByteArray(resp.getResponseMessage());
		assertNotNull("Failed to create certificate", cert);
		log.debug("Cert=" + cert.toString());
		log.debug("foo2 certificate serialnumber: " + cert.getSerialNumber()); 
		assertTrue(cert.getSerialNumber().compareTo(serno) != 0);

		log.trace("<test02CreateCertWithRandomSN()");
	}


	// Create certificate request for user: foo3 with cert serialnumber=1234567890 (the same as cert serialnumber of user foo)
	public void test03CreateCertWithDublicateSN() throws EndEntityProfileExistsException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, PersistenceException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, ClassNotFoundException, CertificateEncodingException, CertificateException, WaitingForApprovalException, InvalidAlgorithmParameterException, EjbcaException {
		log.trace(">test03CreateCertWithDublicateSN()");

		KeyPair rsakeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
		BigInteger serno = ((X509Certificate) certificateStoreSession.findCertificatesByUsername("foo").iterator().next()).getSerialNumber();
		log.debug("foo serno: " + serno);

		PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA1WithRSA",
				CertTools.stringToBcX509Name("C=SE, O=AnaTom, CN=foo3"), rsakeys.getPublic(), new DERSet(),
				rsakeys.getPrivate());

		PKCS10RequestMessage p10 = new PKCS10RequestMessage(req);
		p10.setUsername("foo3");
		p10.setPassword("foo123");

		EndEntityInformation user = new EndEntityInformation("foo3", "C=SE,O=AnaTom,CN=foo3", rsacaid, null, "foo@anatom.se", SecConst.USER_ENDUSER, fooEEProfileId, fooCertProfileId,
				SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
		user.setPassword("foo123");
		ExtendedInformation ei = new ExtendedInformation();
		ei.setCertificateSerialNumber(serno);
		user.setExtendedinformation(ei);

		ResponseMessage resp = null;
		try {
			resp = certificateRequestSession.processCertReq(admin, user, p10, X509ResponseMessage.class);
		} catch (CesecoreException e) {
			log.debug(e.getMessage());
			assertTrue("Unexpected exception.", e.getMessage().startsWith("There is already a certificate stored in 'CertificateData' with the serial number"));
		}
		assertNull(resp);
	}

	public void test04CreateCertWithCustomSNNotAllowed() throws EndEntityProfileExistsException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, PersistenceException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, EjbcaException, ClassNotFoundException, CertificateEncodingException, CertificateException, WaitingForApprovalException, InvalidAlgorithmParameterException {
		log.trace(">test04CreateCertWithCustomSNNotAllowed()");

		KeyPair rsakeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);    	    
		BigInteger serno = SernoGenerator.instance().getSerno();
		log.debug("serno: " + serno);

		PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA1WithRSA",
				CertTools.stringToBcX509Name("C=SE, O=AnaTom, CN=foo"), rsakeys.getPublic(), new DERSet(),
				rsakeys.getPrivate());

		PKCS10RequestMessage p10 = new PKCS10RequestMessage(req.getEncoded());
		p10.setUsername("foo");
		p10.setPassword("foo123");

		CertificateProfile fooCertProfile = certificateProfileSession.getCertificateProfile("FOOCERTPROFILE");
		fooCertProfile.setAllowCertSerialNumberOverride(false);
		certificateProfileSession.changeCertificateProfile(admin, "FOOCERTPROFILE", fooCertProfile);

		EndEntityInformation user = new EndEntityInformation("foo", "C=SE,O=AnaTom,CN=foo", rsacaid, null, "foo@anatom.se", SecConst.USER_ENDUSER, fooEEProfileId, fooCertProfileId,
				SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
		user.setPassword("foo123");
		ExtendedInformation ei = new ExtendedInformation();
		ei.setCertificateSerialNumber(serno);
		user.setExtendedinformation(ei);
		try {
			certificateRequestSession.processCertReq(admin, user, p10, X509ResponseMessage.class);
			assertTrue("This method should throw exception", false);
		} catch (CesecoreException e) {
			assertTrue(e.getMessage().contains("not allowing certificate serial number override"));
		}
		log.trace("<test04CreateCertWithCustomSNNotAllowed()");
	}

}