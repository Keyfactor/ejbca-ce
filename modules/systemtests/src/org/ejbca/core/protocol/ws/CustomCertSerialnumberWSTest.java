package org.ejbca.core.protocol.ws;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.ejb.CreateException;
import javax.naming.NamingException;
import javax.xml.namespace.QName;

import org.ejbca.core.ejb.ca.sign.SernoGenerator;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfileExistsException;
import org.ejbca.core.model.ca.certificateprofiles.EndUserCertificateProfile;
import org.ejbca.core.protocol.ws.client.gen.ApprovalException_Exception;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.CADoesntExistsException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWSService;
import org.ejbca.core.protocol.ws.client.gen.KeyStore;
import org.ejbca.core.protocol.ws.client.gen.NotFoundException_Exception;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserDoesntFullfillEndEntityProfile_Exception;
import org.ejbca.core.protocol.ws.client.gen.WaitingForApprovalException_Exception;
import org.ejbca.core.protocol.ws.common.KeyStoreHelper;
import org.ejbca.util.InterfaceCache;
import org.jboss.logging.Logger;

/** This test requires that "Enable End Entity Profile Limitations" in syste configuration is turned of.
 * 
 * @version $Id$
 */
public class CustomCertSerialnumberWSTest extends CommonEjbcaWS {

	private static final Logger log = Logger.getLogger(CustomCertSerialnumberWSTest.class);

	private CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();

	public void test00SetupAccessRights() {
		try {
			super.setupAccessRights();
		} catch (Exception e) {
			log.debug(e.getMessage());
		}
	}

	public void test01CreateCertWithCustomSN() throws CreateException, NamingException, CertificateProfileExistsException, ApprovalException_Exception, AuthorizationDeniedException_Exception, CADoesntExistsException_Exception, EjbcaException_Exception, NotFoundException_Exception, UserDoesntFullfillEndEntityProfile_Exception, WaitingForApprovalException_Exception, CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException {

		log.debug(">test01CreateCertWithCustomSN");

		if(new File("p12/wstest.jks").exists()) {
			log.debug("new file exists");
			String urlstr = "https://" + hostname + ":" + httpsPort + "/ejbca/ejbcaws/ejbcaws?wsdl";
			log.info("Contacting web service at " + urlstr);

			System.setProperty("javax.net.ssl.trustStore", "p12/wstest.jks");
			System.setProperty("javax.net.ssl.trustStorePassword", "foo123");
			System.setProperty("javax.net.ssl.keyStore", "p12/wstest.jks");
			System.setProperty("javax.net.ssl.keyStorePassword", "foo123");

			QName qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
			EjbcaWSService service = new EjbcaWSService(new URL(urlstr), qname);
			super.ejbcaraws = service.getEjbcaWSPort();
		} else {
			log.debug("new file does not exist");
		}

		BigInteger serno = SernoGenerator.instance().getSerno();
		log.debug("serno: " + serno);

		if (certificateStoreSession.getCertificateProfileId(intAdmin, "WSTESTPROFILE") != 0) {
			certificateStoreSession.removeCertificateProfile(intAdmin, "WSTESTPROFILE");
		}

		CertificateProfile profile = new EndUserCertificateProfile();
		profile.setAllowCertSerialNumberOverride(true);
		certificateStoreSession.addCertificateProfile(intAdmin, "WSTESTPROFILE", profile);

		//Creating certificate for user: wsfoo
		UserDataVOWS user = new UserDataVOWS("wsfoo", "foo123", true, "C=SE, CN=wsfoo",
				getAdminCAName(), null, "foo@anatom.se", UserDataVOWS.STATUS_NEW,
				UserDataVOWS.TOKEN_TYPE_P12, "EMPTY", "WSTESTPROFILE", null);
		user.setCertificateSerialNumber(serno);

		KeyStore ksenv = ejbcaraws.softTokenRequest(user,null,"1024", AlgorithmConstants.KEYALGORITHM_RSA);
		java.security.KeyStore keyStore = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(),"PKCS12","foo123");
		assertNotNull(keyStore);
		Enumeration<String> en = keyStore.aliases();
		String alias = en.nextElement();
		X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
		log.debug("wsfoo serno: " + cert.getSerialNumber());
		assertTrue(cert.getSerialNumber().compareTo(serno) == 0);

		//Creating certificate for user: wsfoo2
		user = new UserDataVOWS("wsfoo2", "foo123", true, "C=SE, CN=wsfoo2",
				getAdminCAName(), null, "foo@anatom.se", UserDataVOWS.STATUS_NEW,
				UserDataVOWS.TOKEN_TYPE_P12, "EMPTY", "WSTESTPROFILE", null);

		ksenv = ejbcaraws.softTokenRequest(user,null,"1024", AlgorithmConstants.KEYALGORITHM_RSA);
		keyStore = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(),"PKCS12","foo123");
		assertNotNull(keyStore);
		en = keyStore.aliases();
		alias = (String) en.nextElement();
		cert = (X509Certificate) keyStore.getCertificate(alias);
		log.debug("wsfoo2 serno: " + cert.getSerialNumber());
		assertTrue(cert.getSerialNumber().compareTo(serno) != 0);

		//Creating certificate for user: wsfoo3
		user = new UserDataVOWS("wsfoo3", "foo123", true, "C=SE, CN=wsfoo3",
				getAdminCAName(), null, "foo@anatom.se", UserDataVOWS.STATUS_NEW,
				UserDataVOWS.TOKEN_TYPE_P12, "EMPTY", "WSTESTPROFILE", null);
		user.setCertificateSerialNumber(serno);

		ksenv = null;
		try {
			ksenv = ejbcaraws.softTokenRequest(user,null,"1024", AlgorithmConstants.KEYALGORITHM_RSA);
		} catch (Exception e) {
			log.debug(e.getMessage());
			assertTrue("Unexpected Exception." , e.getMessage().startsWith("There is already a certificate stored in 'CertificateData' with the serial number"));
		}
		assertNull(ksenv);


		log.debug("<test01CreateCertWithCustomSN");
	}

	public void test99cleanUpAdmins() throws Exception {
		super.cleanUpAdmins();
	}
}
