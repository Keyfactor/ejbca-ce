package org.ejbca.core.protocol.ws; 

import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

import javax.xml.namespace.QName;

import junit.framework.TestCase;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.ejbca.core.model.ca.catoken.CATokenConstants;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.protocol.ws.client.gen.Certificate;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWSService;
import org.ejbca.core.protocol.ws.client.gen.KeyStore;
import org.ejbca.core.protocol.ws.client.gen.RevokeStatus;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.core.protocol.ws.common.KeyStoreHelper;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.KeyTools;

public class TestEjbcaWS extends TestCase {
	
	private static EjbcaWS ejbcaraws;


	protected void setUp() throws Exception {
		super.setUp();
		CertTools.installBCProvider();
		
		String urlstr = "https://localhost:8443/ejbca/ejbcaws/ejbcaws?wsdl";

        System.out.println("Contacting webservice at " + urlstr);                       
		
        System.setProperty("javax.net.ssl.trustStore","p12/wstest.jks");
        System.setProperty("javax.net.ssl.trustStorePassword","foo123");  
		
        System.setProperty("javax.net.ssl.keyStore","p12/wstest.jks");
        System.setProperty("javax.net.ssl.keyStorePassword","foo123");      
        
                      

		QName qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
		EjbcaWSService service = new EjbcaWSService(new URL(urlstr),qname);
		ejbcaraws = service.getEjbcaWSPort();
	}
	
	public void test01EditUser() throws Exception{
		
		// Test to add a user.
		UserDataVOWS user1 = new UserDataVOWS();
		user1.setUsername("WSTESTUSER1");
		user1.setPassword("foo123");
		user1.setClearPwd(true);
		user1.setSubjectDN("CN=WSTESTUSER1");
		user1.setCaName("AdminCA1");
		user1.setEmail(null);
		user1.setSubjectAltName(null);
		user1.setStatus(10);
		user1.setTokenType("USERGENERATED");
		user1.setEndEntityProfileName("EMPTY");
		user1.setCertificateProfileName("ENDUSER");
			
		ejbcaraws.editUser(user1);
		
        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("WSTESTUSER1");
		
	 	List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
		assertTrue(userdatas != null);
		assertTrue(userdatas.size() == 1);
		UserDataVOWS userdata = userdatas.get(0);
		assertTrue(userdata.getUsername().equals("WSTESTUSER1"));
		assertTrue(userdata.getPassword() == null);
		assertTrue(!userdata.isClearPwd());
        assertTrue(userdata.getSubjectDN().equals("CN=WSTESTUSER1"));
        assertTrue(userdata.getCaName().equals("AdminCA1"));
        assertTrue(userdata.getSubjectAltName() == null);
        assertTrue(userdata.getEmail() == null);
        assertTrue(userdata.getCertificateProfileName().equals("ENDUSER"));
        assertTrue(userdata.getEndEntityProfileName().equals("EMPTY"));
        assertTrue(userdata.getTokenType().equals("USERGENERATED"));        
        assertTrue(userdata.getStatus() == 10);
        
        // Edit the user
        userdata.setSubjectDN("CN=WSTESTUSER1,O=Test");
        ejbcaraws.editUser(userdata);
        List<UserDataVOWS> userdatas2 = ejbcaraws.findUser(usermatch);
		assertTrue(userdatas2 != null);
		assertTrue(userdatas2.size() == 1);  
		UserDataVOWS userdata2 = userdatas.get(0);
        assertTrue(userdata2.getSubjectDN().equals("CN=WSTESTUSER1,O=Test"));
		
	}
	
	public void test02findUser() throws Exception{
		//Nonexisting users should return null		
		UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("WSTESTUSER2");		
		List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
		assertTrue(userdatas != null);
		assertTrue(userdatas.size() == 0);
		
		// Find an exising user
		usermatch = new UserMatch();
        usermatch.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("WSTESTUSER1");	
		
        List<UserDataVOWS> userdatas2 = ejbcaraws.findUser(usermatch);
		assertTrue(userdatas2 != null);
		assertTrue(userdatas2.size() == 1);
		
		// Find by O
		usermatch = new UserMatch();
        usermatch.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_ORGANIZATION);
        usermatch.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_BEGINSWITH);
        usermatch.setMatchvalue("Te");			
        List<UserDataVOWS> userdatas3 = ejbcaraws.findUser(usermatch);
		assertTrue(userdatas3 != null);
		assertTrue(userdatas3.size() == 1);
		assertTrue(userdatas3.get(0).getSubjectDN().equals("CN=WSTESTUSER1,O=Test"));
		
		// Find by subjectDN pattern
		usermatch = new UserMatch();
        usermatch.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_DN);
        usermatch.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_CONTAINS);
        usermatch.setMatchvalue("WSTESTUSER1");				
		List<UserDataVOWS> userdatas4 = ejbcaraws.findUser(usermatch);
		assertTrue(userdatas4 != null);
		assertTrue(userdatas4.size() == 1);
		assertTrue(userdatas4.get(0).getSubjectDN().equals("CN=WSTESTUSER1,O=Test"));
		
		usermatch = new UserMatch();
        usermatch.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_ENDENTITYPROFILE);
        usermatch.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("EMPTY");			
        List<UserDataVOWS> userdatas5 = ejbcaraws.findUser(usermatch);
		assertTrue(userdatas5 != null);
		assertTrue(userdatas5.size() > 0);
		
		usermatch = new UserMatch();
        usermatch.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_CERTIFICATEPROFILE);
        usermatch.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("ENDUSER");		
		List<UserDataVOWS> userdatas6 = ejbcaraws.findUser(usermatch);
		assertTrue(userdatas6 != null);
		assertTrue(userdatas6.size() > 0);

		usermatch = new UserMatch();
        usermatch.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_CA);
        usermatch.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("AdminCA1");			
        List<UserDataVOWS> userdatas7 = ejbcaraws.findUser(usermatch);
		assertTrue(userdatas7 != null);
		assertTrue(userdatas7.size() > 0);

		usermatch = new UserMatch();
        usermatch.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_TOKEN);
        usermatch.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("USERGENERATED");			
		List<UserDataVOWS> userdatas8 = ejbcaraws.findUser(usermatch);
		assertTrue(userdatas8 != null);
		assertTrue(userdatas8.size() > 0);
	}
	
	public void test03GeneratePkcs10() throws Exception{
		KeyPair keys = KeyTools.genKeys("1024", CATokenConstants.KEYALGORITHM_RSA);
		PKCS10CertificationRequest  pkcs10 = new PKCS10CertificationRequest("SHA1WithRSA",
                CertTools.stringToBcX509Name("CN=NOUSED"), keys.getPublic(), null, keys.getPrivate());
		
		Certificate certenv =  ejbcaraws.pkcs10Req("WSTESTUSER1","foo123",new String(Base64.encode(pkcs10.getEncoded())),null);
		
		assertNotNull(certenv);
		
		X509Certificate cert = (X509Certificate) CertificateHelper.getCertificate(certenv.getCertificateData()); 
		
		assertNotNull(cert);
		
		assertTrue(cert.getSubjectDN().toString().equals("CN=WSTESTUSER1,O=Test"));
		System.out.println("test03GeneratePkcs10() Certificate " +cert.getSubjectDN().toString() + " equals CN=WSTESTUSER1,O=Test");
		
	}
	
	public void test04GeneratePkcs12() throws Exception{

		boolean exceptionThrown = false;
		try{
           ejbcaraws.pkcs12Req("WSTESTUSER1","foo123",null,"1024", CATokenConstants.KEYALGORITHM_RSA);
		}catch(EjbcaException_Exception e){
			exceptionThrown = true;
		}
		assertTrue(exceptionThrown);// Should fail
		
		// Change token to P12
        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("WSTESTUSER1");       		
	 	List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
		assertTrue(userdatas != null);
		assertTrue(userdatas.size() == 1);        
        userdatas.get(0).setTokenType("P12");
        ejbcaraws.editUser(userdatas.get(0));
        
        exceptionThrown = false;
		try{
          ejbcaraws.pkcs12Req("WSTESTUSER1","foo123",null,"1024", CATokenConstants.KEYALGORITHM_RSA);
		}catch(EjbcaException_Exception e){
			exceptionThrown = true;
		}
		assertTrue(exceptionThrown); // Should fail
		
		// Change token to P12        		   
        userdatas.get(0).setStatus(10);
        userdatas.get(0).setPassword("foo456");
        userdatas.get(0).setClearPwd(true);
        ejbcaraws.editUser(userdatas.get(0));
        
        KeyStore ksenv = null;
        try{
          ksenv = ejbcaraws.pkcs12Req("WSTESTUSER1","foo456",null,"1024", CATokenConstants.KEYALGORITHM_RSA);
        }catch(EjbcaException_Exception e){        	
        	assertTrue(e.getMessage(),false);
        }
        
        assertNotNull(ksenv);
                
        java.security.KeyStore ks = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(),"PKCS12","foo456");
        
        assertNotNull(ks);
        Enumeration en = ks.aliases();
        String alias = (String) en.nextElement();
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        assertTrue(cert.getSubjectDN().toString().equals("CN=WSTESTUSER1,O=Test"));
        System.out.println("test03GeneratePkcs12() Certificate " +cert.getSubjectDN().toString() + " equals CN=WSTESTUSER1,O=Test");

	}
	
	public void test05findCerts() throws Exception{
		
		// First find all certs
        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("WSTESTUSER1");		
	 	List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
		assertTrue(userdatas != null);
		assertTrue(userdatas.size() == 1);        
        userdatas.get(0).setTokenType("P12");       		   
        userdatas.get(0).setStatus(10);
        userdatas.get(0).setPassword("foo123");
        userdatas.get(0).setClearPwd(true);
        ejbcaraws.editUser(userdatas.get(0));        
        KeyStore ksenv = null;
        try{
            ksenv = ejbcaraws.pkcs12Req("WSTESTUSER1","foo123",null,"1024", CATokenConstants.KEYALGORITHM_RSA);
        }catch(EjbcaException_Exception e){        	
          	assertTrue(e.getMessage(),false);
        }
        java.security.KeyStore ks = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(),"PKCS12","foo123");
        
        assertNotNull(ks);
        Enumeration en = ks.aliases();
        String alias = (String) en.nextElement();
        X509Certificate gencert = (X509Certificate) ks.getCertificate(alias);
        
        List<Certificate> foundcerts = ejbcaraws.findCerts("WSTESTUSER1",false);
        assertTrue(foundcerts != null);
        assertTrue(foundcerts.size() > 0);
        
        boolean certFound = false;
        for(int i=0;i<foundcerts.size();i++){
        	X509Certificate cert = (X509Certificate) CertificateHelper.getCertificate(foundcerts.get(i).getCertificateData());
        	if(gencert.getSerialNumber().equals(cert.getSerialNumber())){
        		certFound = true;
        	}
        }
        assertTrue(certFound);
		
        String issuerdn = gencert.getIssuerDN().toString();
        String serno = gencert.getSerialNumber().toString(16);
        
        ejbcaraws.revokeCert(issuerdn,serno, RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);
        
        foundcerts = ejbcaraws.findCerts("WSTESTUSER1",true);
        assertTrue(foundcerts != null);
        assertTrue(foundcerts.size() > 0);
        
        certFound = false;
        for(int i=0;i<foundcerts.size();i++){
        	X509Certificate cert = (X509Certificate) CertificateHelper.getCertificate(foundcerts.get(i).getCertificateData());
        	if(gencert.getSerialNumber().equals(cert.getSerialNumber())){
        		certFound = true;
        	}
        }
        assertFalse(certFound);       
        
        
	}
	
	public void test06revokeCert() throws Exception{
        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("WSTESTUSER1");			
		List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
		assertTrue(userdatas != null);
		assertTrue(userdatas.size() == 1);        
		userdatas.get(0).setTokenType("P12");
		userdatas.get(0).setStatus(10);
		userdatas.get(0).setPassword("foo456");
		userdatas.get(0).setClearPwd(true);
		ejbcaraws.editUser(userdatas.get(0));
		
        KeyStore ksenv = null;
        try{
          ksenv = ejbcaraws.pkcs12Req("WSTESTUSER1","foo456",null,"1024", CATokenConstants.KEYALGORITHM_RSA);
        }catch(EjbcaException_Exception e){        	
        	assertTrue(e.getMessage(),false);
        }
        
        java.security.KeyStore ks = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(),"PKCS12","foo456");        
        assertNotNull(ks);
        Enumeration en = ks.aliases();
        String alias = (String) en.nextElement();
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        assertTrue(cert.getSubjectDN().toString().equals("CN=WSTESTUSER1,O=Test"));       
		
        String issuerdn = cert.getIssuerDN().toString();
        String serno = cert.getSerialNumber().toString(16);
        
        ejbcaraws.revokeCert(issuerdn,serno, RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);
        
        RevokeStatus revokestatus = ejbcaraws.checkRevokationStatus(issuerdn,serno);
        assertNotNull(revokestatus);
        assertTrue(revokestatus.getReason() == RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);
        
        assertTrue(revokestatus.getCertificateSN().equals(serno));
        assertTrue(revokestatus.getIssuerDN().equals(issuerdn));
        assertNotNull(revokestatus.getRevocationDate());
        	
	}
	
	public void test07revokeToken() throws Exception{
        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("WSTESTUSER1");			
		List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);    
		userdatas.get(0).setTokenType("P12");       		   
		userdatas.get(0).setStatus(10);
		userdatas.get(0).setPassword("foo123");
		userdatas.get(0).setClearPwd(true);
		ejbcaraws.editUser(userdatas.get(0));        
		KeyStore ksenv = null;
		try{
			ksenv = ejbcaraws.pkcs12Req("WSTESTUSER1","foo123","12345678","1024", CATokenConstants.KEYALGORITHM_RSA);
		}catch(EjbcaException_Exception e){        	
			assertTrue(e.getMessage(),false);
		}
		java.security.KeyStore ks = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(),"PKCS12","foo123");
		
		assertNotNull(ks);
		Enumeration en = ks.aliases();
		String alias = (String) en.nextElement();
		X509Certificate cert1 = (X509Certificate) ks.getCertificate(alias);
		
		userdatas.get(0).setStatus(10);
		userdatas.get(0).setPassword("foo123");
		userdatas.get(0).setClearPwd(true);
		ejbcaraws.editUser(userdatas.get(0));  
		
		try{
			ksenv = ejbcaraws.pkcs12Req("WSTESTUSER1","foo123","12345678","1024", CATokenConstants.KEYALGORITHM_RSA);
		}catch(EjbcaException_Exception e){        	
			assertTrue(e.getMessage(),false);
		}
		ks = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(),"PKCS12","foo123");
		
		assertNotNull(ks);
		en = ks.aliases();
		alias = (String) en.nextElement();
		X509Certificate cert2 = (X509Certificate) ks.getCertificate(alias);
		
		ejbcaraws.revokeToken("12345678",RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);
		
		String issuerdn1 = cert1.getIssuerDN().toString();
		String serno1 = cert1.getSerialNumber().toString(16);
		
		RevokeStatus revokestatus = ejbcaraws.checkRevokationStatus(issuerdn1,serno1);
		assertNotNull(revokestatus);
		assertTrue(revokestatus.getReason() == RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);
		
		String issuerdn2 = cert2.getIssuerDN().toString();
		String serno2 = cert2.getSerialNumber().toString(16);
		
		revokestatus = ejbcaraws.checkRevokationStatus(issuerdn2,serno2);
		assertNotNull(revokestatus);
		assertTrue(revokestatus.getReason() == RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);
		
	}
	
	public void test08checkRevokeStatus() throws Exception{
		UserMatch usermatch = new UserMatch();
		usermatch.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
		usermatch.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
		usermatch.setMatchvalue("WSTESTUSER1");				
		List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);    
		userdatas.get(0).setTokenType("P12");       		   
		userdatas.get(0).setStatus(10);
		userdatas.get(0).setPassword("foo123");
		userdatas.get(0).setClearPwd(true);
		ejbcaraws.editUser(userdatas.get(0));        
		KeyStore ksenv = null;
		try{
			ksenv = ejbcaraws.pkcs12Req("WSTESTUSER1","foo123","12345678","1024", CATokenConstants.KEYALGORITHM_RSA);
		}catch(EjbcaException_Exception e){        	
			assertTrue(e.getMessage(),false);
		}
		java.security.KeyStore ks = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(),"PKCS12","foo123");
		
		assertNotNull(ks);
		Enumeration en = ks.aliases();
		String alias = (String) en.nextElement();
		X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
		
        String issuerdn = cert.getIssuerDN().toString();
        String serno = cert.getSerialNumber().toString(16);
		
		RevokeStatus revokestatus = ejbcaraws.checkRevokationStatus(issuerdn,serno);
		assertNotNull(revokestatus);
		assertTrue(revokestatus.getReason() == RevokedCertInfo.NOT_REVOKED);		
        
        ejbcaraws.revokeCert(issuerdn,serno, RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);
		
		revokestatus = ejbcaraws.checkRevokationStatus(issuerdn,serno);
		assertNotNull(revokestatus);
		assertTrue(revokestatus.getReason() == RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);
        assertTrue(revokestatus.getCertificateSN().equals(serno));
        assertTrue(revokestatus.getIssuerDN().equals(issuerdn));
        assertNotNull(revokestatus.getRevocationDate());
	}
	
	public void test01UTF8() throws Exception{
		
		// Test to add a user.
		UserDataVOWS user1 = new UserDataVOWS();
		user1.setUsername("WSTESTUSER1");
		user1.setPassword("foo123");
		user1.setClearPwd(true);
		user1.setSubjectDN("CN=WS≈ƒ÷Â‰ˆ");
		user1.setCaName("AdminCA1");
		user1.setEmail(null);
		user1.setSubjectAltName(null);
		user1.setStatus(10);
		user1.setTokenType("USERGENERATED");
		user1.setEndEntityProfileName("EMPTY");
		user1.setCertificateProfileName("ENDUSER");
			
		ejbcaraws.editUser(user1);
		
        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("WSTESTUSER1");
		
	 	List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
		assertTrue(userdatas != null);
		assertTrue(userdatas.size() == 1);
		UserDataVOWS userdata = userdatas.get(0);
		assertTrue(userdata.getUsername().equals("WSTESTUSER1"));
        assertTrue(userdata.getSubjectDN().equals("CN=WS≈ƒ÷Â‰ˆ"));
		
	}
	
	
	public void test10revokeUser() throws Exception{
		
		// Revoke and delete
		ejbcaraws.revokeUser("WSTESTUSER1",RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE,true);
		
		UserMatch usermatch = new UserMatch();
		usermatch.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
		usermatch.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
		usermatch.setMatchvalue("WSTESTUSER1");	
		List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
		assertTrue(userdatas != null);
		assertTrue(userdatas.size() == 0);

	}

}

