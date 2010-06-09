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
package org.ejbca.core.protocol.ws;

import java.io.File;
import java.net.URL;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

import javax.xml.namespace.QName;

import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWSService;
import org.ejbca.core.protocol.ws.client.gen.IllegalQueryException_Exception;
import org.ejbca.core.protocol.ws.client.gen.KeyStore;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;
import org.ejbca.core.protocol.ws.common.KeyStoreHelper;
import org.ejbca.util.CryptoProviderTools;
import org.jboss.logging.Logger;

/**
 * To run you must have the file tmp/bin/junit/jndi.properties
 * 
 * @version $Id$
 */
public class EjbcaWSTest extends CommonEjbcaWS {

    private static final Logger log = Logger.getLogger(EjbcaWSTest.class);
    
    private void setUpAdmin() throws Exception {
        super.setUp();
        CryptoProviderTools.installBCProvider();
        if (new File("p12/wstest.jks").exists()) {
            String urlstr = "https://" + hostname + ":" + httpsPort + "/ejbca/ejbcaws/ejbcaws?wsdl";
            log.info("Contacting webservice at " + urlstr);

            System.setProperty("javax.net.ssl.trustStore", "p12/wstest.jks");
            System.setProperty("javax.net.ssl.trustStorePassword", "foo123");
            System.setProperty("javax.net.ssl.keyStore", "p12/wstest.jks");
            System.setProperty("javax.net.ssl.keyStorePassword", "foo123");

            QName qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
            EjbcaWSService service = new EjbcaWSService(new URL(urlstr), qname);
            super.ejbcaraws = service.getEjbcaWSPort();
        }
    }
    
    

    public void test00SetupAccessRights() throws Exception {
        super.setupAccessRights();
    }
    
    public void test01EditUser() throws Exception {
    	setUpAdmin();
    	super.editUser();
    }


    public void test02FindUser() throws Exception {
        setUpAdmin();
        findUser();
    }

    public void test03_1GeneratePkcs10() throws Exception {
        setUpAdmin();
        generatePkcs10();
    }

    public void test03_2GenerateCrmf() throws Exception {
        setUpAdmin();
        generateCrmf();
    }

    public void test03_3GenerateSpkac() throws Exception {
        setUpAdmin();
        generateSpkac();
    }

    public void test03_4GeneratePkcs10Request() throws Exception {
        setUpAdmin();
        generatePkcs10Request();
    }

    public void test03_5CertificateRequest() throws Exception {
        setUpAdmin();
        certificateRequest();
    }

    public void test03_6EnforcementOfUniquePublicKeys() throws Exception {
        setUpAdmin();
        enforcementOfUniquePublicKeys();
    }

    public void test03_6EnforcementOfUniqueSubjectDN() throws Exception {
        setUpAdmin();
        enforcementOfUniqueSubjectDN();
    }

    public void test04GeneratePkcs12() throws Exception {
        setUpAdmin();
        generatePkcs12();
    }

    public void test05FindCerts() throws Exception {
        setUpAdmin();
        findCerts();
    }

    public void test06RevokeCert() throws Exception {
        setUpAdmin();
        revokeCert();
    }

    public void test07RevokeToken() throws Exception {
        setUpAdmin();
        revokeToken();
    }

    public void test08CheckRevokeStatus() throws Exception {
        setUpAdmin();
        checkRevokeStatus();
    }

    public void test09Utf8() throws Exception {
        setUpAdmin();
        utf8();
    }

    public void test10RevokeUser() throws Exception {
        setUpAdmin();
        revokeUser();
    }

    public void test11IsAuthorized() throws Exception {
        setUpAdmin();

        // This is a superadmin keystore, improve in the future
        assertTrue(ejbcaraws.isAuthorized(AccessRulesConstants.ROLE_SUPERADMINISTRATOR));
    }

    public void test13genTokenCertificates() throws Exception {
        setUpAdmin();
        genTokenCertificates( false);
    }

    public void test14getExistsHardToken() throws Exception {
        setUpAdmin();
        getExistsHardToken();
    }

    public void test15getHardTokenData() throws Exception {
        setUpAdmin();
        getHardTokenData("12345678", false);
    }

    public void test16getHardTokenDatas() throws Exception {
        setUpAdmin();
        getHardTokenDatas();
    }

    public void test17CustomLog() throws Exception {
        setUpAdmin();
        customLog();
    }

    public void test18GetCertificate() throws Exception {
        setUpAdmin();
        getCertificate();
    }

    public void test19RevocationApprovals() throws Exception {
        setUpAdmin();
        revocationApprovals();
    }

    public void test20KeyRecoverNewest() throws Exception {
        setUpAdmin();
        keyRecover();
    }

    public void test21GetAvailableCAs() throws Exception {
        setUpAdmin();
        getAvailableCAs();
    }

    public void test22GetAuthorizedEndEntityProfiles() throws Exception {
        setUpAdmin();
        getAuthorizedEndEntityProfiles();
    }

    public void test23GetAvailableCertificateProfiles() throws Exception {
        setUpAdmin();
        getAvailableCertificateProfiles();
    }

    public void test24GetAvailableCAsInProfile() throws Exception {
        setUpAdmin();
        getAvailableCAsInProfile();
    }

    public void test25GreateCRL() throws Exception {
        setUpAdmin();
        createCRL();
    }

    public void test26CvcRequest() throws Exception {
        setUpAdmin();
        cvcRequest();
    }

    public void test27EjbcaVersion() throws Exception {
        setUpAdmin();
        ejbcaVersion();
    }

    public void test28GetLastCertChain() throws Exception {
        setUpAdmin();
        getLastCertChain();
    }

    public void test29ErrorOnEditUser() throws Exception {
        setUpAdmin();
        errorOnEditUser();
    }

    public void test30ErrorOnGeneratePkcs10() throws Exception {
        setUpAdmin();
        errorOnGeneratePkcs10();
    }

    public void test31ErrorOnGeneratePkcs12() throws Exception {
        setUpAdmin();
        errorOnGeneratePkcs12();
    }

    public void test32OperationOnNonexistingCA() throws Exception {
        setUpAdmin();
        operationOnNonexistingCA();
    }

    public void test33CheckQueueLength() throws Exception {
        setUpAdmin();
        checkQueueLength();
    }

    public void test34CaRenewCertRequest() throws Exception {
        setUpAdmin();
        super.caRenewCertRequest();
    }

    public void test35CleanUpCACertRequest() throws Exception {
        setUpAdmin();
        super.cleanUpCACertRequest();
    }

    /** Simulate a simple SQL injection by sending the illegal char "'". 
     * @throws Exception */
	public void testEvilFind01() throws Exception {
		log.trace(">testEvilFind01()");
        setUpAdmin();
		UserMatch usermatch = new UserMatch();
	    usermatch.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
	    usermatch.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
	    usermatch.setMatchvalue("A' OR '1=1");
	    try {
			List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
			fail("SQL injection did not cause an error! " + userdatas.size());
	    } catch (IllegalQueryException_Exception e) {
	    	// NOPMD, this should be thrown and we ignore it because we fail if it is not thrown
	    } 
	    log.trace("<testEvilFind01()");
	}
    
	/** Use single transaction method for requesting KeyStore with special characters in the certificate SubjectDN. */
	public void testCertificateRequestWithSpecialChars01() throws Exception{
		setUpAdmin();
		long rnd = new SecureRandom().nextLong();
		testCertificateRequestWithSpecialChars("CN=test" + rnd + ", O=foo\\+bar\\\"\\,, C=SE", "CN=test" + rnd + ",O=foo\\+bar\\\"\\,,C=SE");
	}
	
	/** Use single transaction method for requesting KeyStore with special characters in the certificate SubjectDN. */
	public void testCertificateRequestWithSpecialChars02() throws Exception{
		setUpAdmin();
		long rnd = new SecureRandom().nextLong();
		testCertificateRequestWithSpecialChars("CN=test" + rnd + ", O=foo;bar\\;123, C=SE", "CN=test" + rnd + ",O=foo/bar\\;123,C=SE");
	}
	
	/** Use single transaction method for requesting KeyStore with special characters in the certificate SubjectDN. */
	public void testCertificateRequestWithSpecialChars03() throws Exception{
		setUpAdmin();
		long rnd = new SecureRandom().nextLong();
		testCertificateRequestWithSpecialChars("CN=test" + rnd + ", O=foo+bar\\+123, C=SE", "CN=test" + rnd + ",O=foo\\+bar\\+123,C=SE");
	}
	
	/** Use single transaction method for requesting KeyStore with special characters in the certificate SubjectDN. */
	public void testCertificateRequestWithSpecialChars04() throws Exception{
		setUpAdmin();
		long rnd = new SecureRandom().nextLong();
		testCertificateRequestWithSpecialChars("CN=test" + rnd + ", O=foo\\=bar, C=SE", "CN=test" + rnd + ",O=foo\\=bar,C=SE");
	}
	
	/** Use single transaction method for requesting KeyStore with special characters in the certificate SubjectDN. */
	public void testCertificateRequestWithSpecialChars05() throws Exception{
		setUpAdmin();
		long rnd = new SecureRandom().nextLong();
		testCertificateRequestWithSpecialChars("CN=test" + rnd + ", O=\"foo=bar, C=SE\"", "CN=test" + rnd + ",O=foo\\=bar\\, C\\=SE");
	}
	
	/** Use single transaction method for requesting KeyStore with special characters in the certificate SubjectDN. */
	public void testCertificateRequestWithSpecialChars06() throws Exception{
		setUpAdmin();
		long rnd = new SecureRandom().nextLong();
		testCertificateRequestWithSpecialChars("CN=test" + rnd + ", O=\"foo+b\\+ar, C=SE\"", "CN=test" + rnd + ",O=foo\\+b\\\\\\+ar\\, C\\=SE");
	}
	
	/** Use single transaction method for requesting KeyStore with special characters in the certificate SubjectDN. */
	public void testCertificateRequestWithSpecialChars07() throws Exception{
		setUpAdmin();
		long rnd = new SecureRandom().nextLong();
		testCertificateRequestWithSpecialChars("CN=test" + rnd + ", O=\\\"foo+b\\+ar\\, C=SE\\\"", "CN=test" + rnd + ",O=\\\"foo\\+b\\+ar\\, C\\=SE\\\"");
	}
	
    public void test99cleanUpAdmins() throws Exception {
    	super.cleanUpAdmins();
    }

	private void testCertificateRequestWithSpecialChars(String requestedSubjectDN, String expectedSubjectDN) throws Exception {
		String userName = "wsSpecialChars" + new SecureRandom().nextLong();
		final UserDataVOWS userData = new UserDataVOWS();
		userData.setUsername(userName);
		userData.setPassword("foo123");
		userData.setClearPwd(true);
		userData.setSubjectDN(requestedSubjectDN);
		userData.setCaName(getAdminCAName());
		userData.setEmail(null);
		userData.setSubjectAltName(null);
		userData.setStatus(UserDataVOWS.STATUS_NEW);
		userData.setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
		userData.setEndEntityProfileName("EMPTY");
		userData.setCertificateProfileName("ENDUSER");

        KeyStore ksenv = ejbcaraws.softTokenRequest(userData,null,"1024", AlgorithmConstants.KEYALGORITHM_RSA);
        java.security.KeyStore keyStore = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(),"PKCS12","foo123");
        assertNotNull(keyStore);
        Enumeration en = keyStore.aliases();
        String alias = (String) en.nextElement();
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
        
        String resultingSubjectDN = cert.getSubjectDN().toString();
        assertEquals(requestedSubjectDN + " was transformed into " + resultingSubjectDN + " (not the expected " + expectedSubjectDN + ")", expectedSubjectDN, resultingSubjectDN);
	}

}
