package org.ejbca.core.protocol.ws; 

import java.io.File;
import java.net.URL;
import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

import javax.ejb.CreateException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.xml.namespace.QName;

import junit.framework.TestCase;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.ejbca.core.ejb.approval.IApprovalSessionHome;
import org.ejbca.core.ejb.approval.IApprovalSessionRemote;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionHome;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionHome;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.approvalrequests.TestRevocationApproval;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.catoken.CATokenConstants;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.EndUserCertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.core.protocol.ws.client.gen.AlreadyRevokedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.ApprovalException_Exception;
import org.ejbca.core.protocol.ws.client.gen.Certificate;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWSService;
import org.ejbca.core.protocol.ws.client.gen.HardTokenDataWS;
import org.ejbca.core.protocol.ws.client.gen.HardTokenDoesntExistsException_Exception;
import org.ejbca.core.protocol.ws.client.gen.HardTokenExistsException_Exception;
import org.ejbca.core.protocol.ws.client.gen.KeyStore;
import org.ejbca.core.protocol.ws.client.gen.PinDataWS;
import org.ejbca.core.protocol.ws.client.gen.RevokeStatus;
import org.ejbca.core.protocol.ws.client.gen.TokenCertificateRequestWS;
import org.ejbca.core.protocol.ws.client.gen.TokenCertificateResponseWS;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;
import org.ejbca.core.protocol.ws.client.gen.WaitingForApprovalException_Exception;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.core.protocol.ws.common.HardTokenConstants;
import org.ejbca.core.protocol.ws.common.IEjbcaWS;
import org.ejbca.core.protocol.ws.common.KeyStoreHelper;
import org.ejbca.ui.cli.batch.BatchMakeP12;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.KeyTools;

public class CommonEjbcaWSTest extends TestCase {
	
	protected static EjbcaWS ejbcaraws;

	protected IHardTokenSessionRemote hardTokenSession;
    protected static IHardTokenSessionHome hardTokenSessionHome;
	protected ICertificateStoreSessionRemote certStoreSession;
    protected static ICertificateStoreSessionHome certStoreSessionHome;
	protected IRaAdminSessionRemote raAdminSession;
    protected static IRaAdminSessionHome raAdminSessionHome;
    protected IUserAdminSessionRemote userAdminSession;
    protected static IUserAdminSessionHome userAdminSessionHome;
    protected ICAAdminSessionRemote caAdminSession;
    protected static ICAAdminSessionHome caAdminSessionHome;
    protected IAuthorizationSessionRemote authSession;
    protected static IAuthorizationSessionHome authSessionHome;
    protected IApprovalSessionRemote approvalSession;
    protected static IApprovalSessionHome approvalSessionHome;
    
    protected static Admin intAdmin = new Admin(Admin.TYPE_INTERNALUSER);
    
    protected String getAdminCAName() {
    	return "AdminCA1";
    }
    
	protected void setUpAdmin() throws Exception {
		super.setUp();
		CertTools.installBCProvider();
		
        if(new File("p12/wstest.jks").exists()){

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
	}
	
	protected void setUpNonAdmin() throws Exception {
		super.setUp();
		CertTools.installBCProvider();
		
        if(new File("p12/wsnonadmintest.jks").exists()){

        	String urlstr = "https://localhost:8443/ejbca/ejbcaws/ejbcaws?wsdl";

        	System.out.println("Contacting webservice at " + urlstr);                       

        	System.setProperty("javax.net.ssl.trustStore","p12/wsnonadmintest.jks");
        	System.setProperty("javax.net.ssl.trustStorePassword","foo123");  

        	System.setProperty("javax.net.ssl.keyStore","p12/wsnonadmintest.jks");
        	System.setProperty("javax.net.ssl.keyStorePassword","foo123");      



        	QName qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
        	EjbcaWSService service = new EjbcaWSService(new URL(urlstr),qname);
        	ejbcaraws = service.getEjbcaWSPort();
        }
	}




	protected void tearDown() throws Exception {
		super.tearDown();
		
		
	}


	protected Context getInitialContext() throws NamingException {
        Context ctx = new javax.naming.InitialContext();
        return ctx;
    }

	protected IHardTokenSessionRemote getHardTokenSession() throws RemoteException, CreateException, NamingException {
	    if (hardTokenSession == null) {
	        if (hardTokenSessionHome == null) {
	            Context jndiContext = getInitialContext();
	            Object obj1 = jndiContext.lookup(IHardTokenSessionHome.JNDI_NAME);
	            hardTokenSessionHome = (IHardTokenSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IHardTokenSessionHome.class);
	        }
	        hardTokenSession = hardTokenSessionHome.create();
	    }
	    return hardTokenSession;
	}

	
	protected ICertificateStoreSessionRemote getCertStore() throws RemoteException, CreateException, NamingException{
        if (certStoreSession == null) {
            if (certStoreSessionHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup(ICertificateStoreSessionHome.JNDI_NAME);
                certStoreSessionHome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionHome.class);

            }

            certStoreSession = certStoreSessionHome.create();            
        }
        return certStoreSession;
	}
	
	protected IRaAdminSessionRemote getRAAdmin() throws RemoteException, CreateException, NamingException{
        if (raAdminSession == null) {
            if (raAdminSessionHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup(IRaAdminSessionHome.JNDI_NAME);
                raAdminSessionHome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IRaAdminSessionHome.class);

            }

            raAdminSession = raAdminSessionHome.create();            
        }
        return raAdminSession;
	}
	
	protected IUserAdminSessionRemote getUserAdminSession() throws RemoteException, CreateException, NamingException{
        if (userAdminSession == null) {
            if (userAdminSessionHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup(IUserAdminSessionHome.JNDI_NAME);
                userAdminSessionHome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IUserAdminSessionHome.class);
            }

            userAdminSession = userAdminSessionHome.create();            
        }
        return userAdminSession;
	}
	
	protected ICAAdminSessionRemote getCAAdminSession() throws RemoteException, CreateException, NamingException{
        if (caAdminSession == null) {
            if (caAdminSessionHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup(ICAAdminSessionHome.JNDI_NAME);
                caAdminSessionHome = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICAAdminSessionHome.class);
            }

            caAdminSession = caAdminSessionHome.create();            
        }
        return caAdminSession;
	}
	
	protected IAuthorizationSessionRemote getAuthSession() throws RemoteException, CreateException, NamingException{
        if (authSession == null) {
            if (authSessionHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup(IAuthorizationSessionHome.JNDI_NAME);
                authSessionHome = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IAuthorizationSessionHome.class);
            }

            authSession = authSessionHome.create();            
        }
        return authSession;
	}
	
	protected IApprovalSessionRemote getApprovalSession() throws RemoteException, CreateException, NamingException {
		if (approvalSession == null) {
			if (approvalSessionHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup(IApprovalSessionHome.JNDI_NAME);
                approvalSessionHome = (IApprovalSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IApprovalSessionHome.class);
			}
			approvalSession = approvalSessionHome.create();
		}
		return approvalSession;
	}
	
	public void test00SetupAccessRights() throws Exception{
		Admin intAdmin = new Admin(Admin.TYPE_INTERNALUSER);
		boolean userAdded = false;
		
		if(!getUserAdminSession().existsUser(intAdmin, "wstest")){
			UserDataVO user1 = new UserDataVO();
			user1.setUsername("wstest");
			user1.setPassword("foo123");			
			user1.setDN("CN=wstest");			
			CAInfo cainfo = getCAAdminSession().getCAInfo(intAdmin, getAdminCAName());
			user1.setCAId(cainfo.getCAId());
			user1.setEmail(null);
			user1.setSubjectAltName(null);
			user1.setStatus(10);
			user1.setTokenType(SecConst.TOKEN_SOFT_JKS);
			user1.setEndEntityProfileId(SecConst.EMPTY_ENDENTITYPROFILE);
			user1.setCertificateProfileId(SecConst.CERTPROFILE_FIXED_ENDUSER);
			user1.setType(65);
			
			getUserAdminSession().addUser(intAdmin, user1, true);
			userAdded = true;

			boolean adminExists = false;
			AdminGroup admingroup = getAuthSession().getAdminGroup(intAdmin, "Temporary Super Administrator Group", cainfo.getCAId());
			Iterator iter = admingroup.getAdminEntities().iterator();
			while(iter.hasNext()){
				AdminEntity adminEntity = (AdminEntity) iter.next();
				if(adminEntity.getMatchValue().equals("wstest")){
					adminExists = true;
				}
			}
			
			if(!adminExists){
				ArrayList list = new ArrayList();
				list.add(new AdminEntity(AdminEntity.WITH_COMMONNAME,AdminEntity.TYPE_EQUALCASE,"wstest",cainfo.getCAId()));
				getAuthSession().addAdminEntities(intAdmin, "Temporary Super Administrator Group", cainfo.getCAId(), list);
				getAuthSession().forceRuleUpdate(intAdmin);
			}
			
		}
		
		if(!getUserAdminSession().existsUser(intAdmin, "wsnonadmintest")){
			UserDataVO user1 = new UserDataVO();
			user1.setUsername("wsnonadmintest");
			user1.setPassword("foo123");			
			user1.setDN("CN=wsnonadmintest");			
			CAInfo cainfo = getCAAdminSession().getCAInfo(intAdmin, getAdminCAName());
			user1.setCAId(cainfo.getCAId());
			user1.setEmail(null);
			user1.setSubjectAltName(null);
			user1.setStatus(10);
			user1.setTokenType(SecConst.TOKEN_SOFT_JKS);
			user1.setEndEntityProfileId(SecConst.EMPTY_ENDENTITYPROFILE);
			user1.setCertificateProfileId(SecConst.CERTPROFILE_FIXED_ENDUSER);
			user1.setType(1);
			
			getUserAdminSession().addUser(intAdmin, user1, true);
			userAdded = true;	
		}
		
		if(userAdded){
			BatchMakeP12 batch = new BatchMakeP12();
			batch.setMainStoreDir("p12");
			batch.createAllNew();
		}
		
		
		
	}
	

	protected void test01EditUser(boolean performSetup) throws Exception{
		if(performSetup){
		  setUpAdmin();
		}
		// Test to add a user.
		UserDataVOWS user1 = new UserDataVOWS();
		user1.setUsername("WSTESTUSER1");
		user1.setPassword("foo123");
		user1.setClearPwd(true);
		user1.setSubjectDN("CN=WSTESTUSER1");
		user1.setCaName(getAdminCAName());
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
        assertTrue(userdata.getCaName().equals(getAdminCAName()));
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
	

	protected void test02findUser(boolean performSetup) throws Exception{
		if(performSetup){
		  setUpAdmin();
		}
		
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
        usermatch.setMatchvalue(getAdminCAName());			
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
	

	
	protected void test03GeneratePkcs10(boolean performSetup) throws Exception{
		if(performSetup){
			setUpAdmin();
		}
		
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
	

	
	protected void test04GeneratePkcs12(boolean performSetup) throws Exception{
		if(performSetup){
			setUpAdmin();
		}

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

	protected void test05findCerts(boolean performSetup) throws Exception{
		if(performSetup){
			setUpAdmin();
		}
		
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
	

	
	protected void test06revokeCert(boolean performSetup) throws Exception{
		if(performSetup){
			setUpAdmin();
		}
		
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
        
        ejbcaraws.revokeCert(issuerdn,serno, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
        
        RevokeStatus revokestatus = ejbcaraws.checkRevokationStatus(issuerdn,serno);
        assertNotNull(revokestatus);
        assertTrue(revokestatus.getReason() == RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
        
        assertTrue(revokestatus.getCertificateSN().equals(serno));
        assertTrue(revokestatus.getIssuerDN().equals(issuerdn));
        assertNotNull(revokestatus.getRevocationDate());
        
        ejbcaraws.revokeCert(issuerdn,serno, RevokedCertInfo.NOT_REVOKED);
        
        revokestatus = ejbcaraws.checkRevokationStatus(issuerdn,serno);
        assertNotNull(revokestatus);
        assertTrue(revokestatus.getReason() == RevokedCertInfo.NOT_REVOKED);
        
        ejbcaraws.revokeCert(issuerdn,serno, RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);
        
        revokestatus = ejbcaraws.checkRevokationStatus(issuerdn,serno);
        assertNotNull(revokestatus);
        assertTrue(revokestatus.getReason() == RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);
        
        try{
          ejbcaraws.revokeCert(issuerdn,serno, RevokedCertInfo.NOT_REVOKED);
          assertTrue(false);
        }catch(EjbcaException_Exception e){}
        
	}
	

	
	protected void test07revokeToken(boolean performSetup) throws Exception{
		if(performSetup){
			setUpAdmin();
		}
		
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


	
	protected void test08checkRevokeStatus(boolean performSetup) throws Exception{
		if(performSetup){
			setUpAdmin();
		}
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
	

	
	protected void test09UTF8(boolean performSetup) throws Exception{
		if(performSetup){
			setUpAdmin();
		}
		
		// Test to add a user.
		UserDataVOWS user1 = new UserDataVOWS();
		user1.setUsername("WSTESTUSER1");
		user1.setPassword("foo123");
		user1.setClearPwd(true);
		user1.setSubjectDN("CN=WS������");
		user1.setCaName(getAdminCAName());
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
        assertTrue(userdata.getSubjectDN().equals("CN=WS������"));
		
	}
	
	

	protected void test10revokeUser(boolean performSetup) throws Exception{
		if(performSetup){
		 setUpAdmin();
		}
		
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

    
    protected void test12genTokenCertificates(boolean performSetup, boolean onlyOnce) throws Exception{
    	if(performSetup){
    		setUpAdmin();
    	}
    	
    	GlobalConfiguration gc = getRAAdmin().loadGlobalConfiguration(intAdmin);
    	boolean originalProfileSetting = gc.getEnableEndEntityProfileLimitations();
    	gc.setEnableEndEntityProfileLimitations(false);
    	getRAAdmin().saveGlobalConfiguration(intAdmin, gc);
    	if(getCertStore().getCertificateProfileId(intAdmin, "WSTESTPROFILE") != 0){
        	getCertStore().removeCertificateProfile(intAdmin, "WSTESTPROFILE");
        }
        
        CertificateProfile profile = new EndUserCertificateProfile();
        profile.setAllowValidityOverride(true);
        getCertStore().addCertificateProfile(intAdmin, "WSTESTPROFILE", profile);
    	
    	// first a simple test
		UserDataVOWS tokenUser1 = new UserDataVOWS();
		tokenUser1.setUsername("WSTESTTOKENUSER1");
		tokenUser1.setPassword("foo123");
		tokenUser1.setClearPwd(true);
		tokenUser1.setSubjectDN("CN=WSTESTTOKENUSER1");
		tokenUser1.setCaName(getAdminCAName());
		tokenUser1.setEmail(null);
		tokenUser1.setSubjectAltName(null);
		tokenUser1.setStatus(10);
		tokenUser1.setTokenType("USERGENERATED");
		tokenUser1.setEndEntityProfileName("EMPTY");
		tokenUser1.setCertificateProfileName("ENDUSER"); 
		
		KeyPair basickeys = KeyTools.genKeys("1024", CATokenConstants.KEYALGORITHM_RSA);		
		PKCS10CertificationRequest  basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA",
                CertTools.stringToBcX509Name("CN=NOUSED"), basickeys.getPublic(), null, basickeys.getPrivate());

		ArrayList<TokenCertificateRequestWS> requests = new ArrayList<TokenCertificateRequestWS>();
		TokenCertificateRequestWS tokenCertReqWS = new TokenCertificateRequestWS();
		tokenCertReqWS.setCAName(getAdminCAName());
		tokenCertReqWS.setCertificateProfileName("WSTESTPROFILE");
		tokenCertReqWS.setValidityIdDays("1");
		tokenCertReqWS.setPkcs10Data(basicpkcs10.getDEREncoded());
		tokenCertReqWS.setType(HardTokenConstants.REQUESTTYPE_PKCS10_REQUEST);
		requests.add(tokenCertReqWS);
		tokenCertReqWS = new TokenCertificateRequestWS();
		tokenCertReqWS.setCAName(getAdminCAName());
		tokenCertReqWS.setCertificateProfileName("ENDUSER");
		tokenCertReqWS.setKeyalg("RSA");
		tokenCertReqWS.setKeyspec("1024");
		tokenCertReqWS.setType(HardTokenConstants.REQUESTTYPE_KEYSTORE_REQUEST);
		requests.add(tokenCertReqWS);
		
		HardTokenDataWS hardTokenDataWS = new HardTokenDataWS();
		hardTokenDataWS.setLabel(HardTokenConstants.LABEL_PROJECTCARD);
		hardTokenDataWS.setTokenType(HardTokenConstants.TOKENTYPE_SWEDISHEID);
		hardTokenDataWS.setHardTokenSN("12345678");		
		PinDataWS basicPinDataWS = new PinDataWS();
		basicPinDataWS.setType(HardTokenConstants.PINTYPE_BASIC);
		basicPinDataWS.setInitialPIN("1234");
		basicPinDataWS.setPUK("12345678");
		PinDataWS signaturePinDataWS = new PinDataWS();
		signaturePinDataWS.setType(HardTokenConstants.PINTYPE_SIGNATURE);
		signaturePinDataWS.setInitialPIN("5678");
		signaturePinDataWS.setPUK("23456789");
		
		hardTokenDataWS.getPinDatas().add(basicPinDataWS);
		hardTokenDataWS.getPinDatas().add(signaturePinDataWS);
				
		List<TokenCertificateResponseWS> responses = ejbcaraws.genTokenCertificates(tokenUser1, requests, hardTokenDataWS, true, false);
		assertTrue(responses.size() == 2);
		
		Iterator<TokenCertificateResponseWS> iter= responses.iterator();		
		TokenCertificateResponseWS next = iter.next();
		assertTrue(next.getType() == HardTokenConstants.RESPONSETYPE_CERTIFICATE_RESPONSE);
		Certificate cert = next.getCertificate();
		X509Certificate realcert = (X509Certificate) CertificateHelper.getCertificate(cert.getCertificateData());
		assertNotNull(realcert);
		assertTrue(realcert.getNotAfter().toString(),realcert.getNotAfter().before(new Date(System.currentTimeMillis() + 2 *24* 3600 *1000)));
		next = iter.next();
		assertTrue(next.getType() == HardTokenConstants.RESPONSETYPE_KEYSTORE_RESPONSE);
		KeyStore keyStore = next.getKeyStore();
		java.security.KeyStore realKeyStore = KeyStoreHelper.getKeyStore(keyStore.getKeystoreData(), HardTokenConstants.TOKENTYPE_PKCS12, "foo123");
		assertTrue(realKeyStore.containsAlias("WSTESTTOKENUSER1"));
		assertTrue(((X509Certificate) realKeyStore.getCertificate("WSTESTTOKENUSER1")).getNotAfter().after(new Date(System.currentTimeMillis() + 48 * 24 * 3600 *1000)));
		
		if(!onlyOnce){
			try{
				responses = ejbcaraws.genTokenCertificates(tokenUser1, requests, hardTokenDataWS, false, false);
				assertTrue(false);
			}catch(HardTokenExistsException_Exception e){

			}
		}
		
		getCertStore().removeCertificateProfile(intAdmin, "WSTESTPROFILE");
		gc.setEnableEndEntityProfileLimitations(originalProfileSetting);
    	getRAAdmin().saveGlobalConfiguration(intAdmin, gc);
		//hardTokenAdmin.removeHardToken(intAdmin, "12345678");
		
		
		
	} 
    
   
    
    protected void test13getExistsHardToken(boolean performSetup) throws Exception{
    	if(performSetup){
    		setUpAdmin();
    	}
    	assertTrue(ejbcaraws.existsHardToken("12345678"));
    	assertFalse(ejbcaraws.existsHardToken("23456789"));    
    }

    
    
    protected void test14getHardTokenData(boolean performSetup, boolean onlyOnce) throws Exception{
    	if(performSetup){
    		setUpAdmin();
    	}
    	HardTokenDataWS hardTokenDataWS = ejbcaraws.getHardTokenData("12345678", true, true);
    	assertNotNull(hardTokenDataWS);
    	assertTrue(""+hardTokenDataWS.getTokenType(), hardTokenDataWS.getTokenType() == HardTokenConstants.TOKENTYPE_SWEDISHEID);
    	assertTrue(hardTokenDataWS.getHardTokenSN().equals("12345678"));
    	assertTrue(hardTokenDataWS.getCopyOfSN(), hardTokenDataWS.getCopyOfSN() == null);
    	assertTrue(hardTokenDataWS.getCopies().size()==0);
    	//assertTrue(hardTokenDataWS.getCertificates().size() == 2);
    	assertTrue(hardTokenDataWS.getPinDatas().size() == 2);
    	
    	Iterator<PinDataWS> iter = hardTokenDataWS.getPinDatas().iterator();
    	while(iter.hasNext()){
    		PinDataWS next = iter.next();
    		if(next.getType() == HardTokenConstants.PINTYPE_BASIC){
    			assertTrue(next.getPUK().equals("12345678"));
    			assertTrue(next.getInitialPIN().equals("1234"));
    		}
    		if(next.getType() == HardTokenConstants.PINTYPE_SIGNATURE){
    			assertTrue(next.getPUK(),next.getPUK().equals("23456789"));
    			assertTrue(next.getInitialPIN().equals("5678"));    			
    		}
    	}
    	if(!onlyOnce){
    		hardTokenDataWS = ejbcaraws.getHardTokenData("12345678", false, false);
    		assertNotNull(hardTokenDataWS);
    		//assertTrue(""+ hardTokenDataWS.getCertificates().size(), hardTokenDataWS.getCertificates().size() == 2);
    		assertTrue(""+ hardTokenDataWS.getPinDatas().size(), hardTokenDataWS.getPinDatas().size() == 0);

    		try{
    			ejbcaraws.getHardTokenData("12345679", false, false);
    			assertTrue(false);
    		}catch(HardTokenDoesntExistsException_Exception e){

    		}
    	}

            
    }
    
  
    protected void test15getHardTokenDatas(boolean performSetup) throws Exception{
    	if(performSetup){
    		setUpAdmin();
    	}
    	
    	Collection<HardTokenDataWS> hardTokenDatas = ejbcaraws.getHardTokenDatas("WSTESTTOKENUSER1", true, true);
    	assertTrue(hardTokenDatas.size() == 1);
    	HardTokenDataWS hardTokenDataWS = hardTokenDatas.iterator().next();
    	assertNotNull(hardTokenDataWS);
    	assertTrue(""+hardTokenDataWS.getTokenType(), hardTokenDataWS.getTokenType() == HardTokenConstants.TOKENTYPE_SWEDISHEID);
    	assertTrue(hardTokenDataWS.getHardTokenSN().equals("12345678"));
    	assertTrue(hardTokenDataWS.getCopyOfSN(), hardTokenDataWS.getCopyOfSN() == null);
    	assertTrue(hardTokenDataWS.getCopies().size()==0);
    	assertTrue(hardTokenDataWS.getCertificates().size() == 2);
    	assertTrue(hardTokenDataWS.getPinDatas().size() == 2);
    	
    	Iterator<PinDataWS> iter = hardTokenDataWS.getPinDatas().iterator();
    	while(iter.hasNext()){
    		PinDataWS next = iter.next();
    		if(next.getType() == HardTokenConstants.PINTYPE_BASIC){
    			assertTrue(next.getPUK().equals("12345678"));
    			assertTrue(next.getInitialPIN().equals("1234"));
    		}
    		if(next.getType() == HardTokenConstants.PINTYPE_SIGNATURE){
    			assertTrue(next.getPUK(),next.getPUK().equals("23456789"));
    			assertTrue(next.getInitialPIN().equals("5678"));    			
    		}
    	}

    	try{
    	  hardTokenDatas = ejbcaraws.getHardTokenDatas("WSTESTTOKENUSER2", true, true);    	
    	  assertTrue(hardTokenDatas.size() == 0);
    	}catch(EjbcaException_Exception e){
    		
    	}
    }


    protected void test16CustomLog(boolean performSetup) throws Exception{
    	if(performSetup){
    		setUpAdmin();
    	}
        // The logging have to be checked manually	     
        ejbcaraws.customLog(IEjbcaWS.CUSTOMLOG_LEVEL_INFO, "Test", getAdminCAName(), "WSTESTTOKENUSER1", null, "Message 1 generated from WS test Script");
        ejbcaraws.customLog(IEjbcaWS.CUSTOMLOG_LEVEL_ERROR, "Test", getAdminCAName(), "WSTESTTOKENUSER1", null, "Message 1 generated from WS test Script");
    }

   
    
  
    
    protected void test17GetCertificate(boolean performSetup) throws Exception{
    	if(performSetup){
    		setUpAdmin();
    	}
    	
    	List<Certificate> certs = ejbcaraws.findCerts("WSTESTTOKENUSER1", true);
    	Certificate cert = certs.get(0);
    	X509Certificate realcert = (X509Certificate) CertificateHelper.getCertificate(cert.getCertificateData());
    	
    	cert = ejbcaraws.getCertificate(realcert.getSerialNumber().toString(16), CertTools.getIssuerDN(realcert));
    	assertNotNull(cert);
    	X509Certificate realcert2 = (X509Certificate) CertificateHelper.getCertificate(cert.getCertificateData());
    	
    	assertTrue(realcert.getSerialNumber().equals(realcert2.getSerialNumber()));
    	
    	cert = ejbcaraws.getCertificate("1234567", CertTools.getIssuerDN(realcert));
    	assertNull(cert);
    }
    
	public void test18RevocationApprovals(boolean performSetup) throws Exception {
		final String APPROVINGADMINNAME = "superadmin";
        final String TOKENSERIALNUMBER = "42424242";
        final String TOKENUSERNAME = "WSTESTTOKENUSER3";
		final String ERRORNOTSENTFORAPPROVAL = "The request was never sent for approval."; 
    	final String ERRORNOTSUPPORTEDSUCCEEDED = "Reactivation of users is not supported, but succeeded anyway.";
		if(performSetup){
			  setUpAdmin();
		}
	    // Generate random username and CA name
		String randomPostfix = Integer.toString((new Random(new Date().getTime() + 4711)).nextInt(999999));
		String caname = "wsRevocationCA" + randomPostfix;
		String username = "wsRevocationUser" + randomPostfix;
		int caID = -1;
	    try {
	    	caID = TestRevocationApproval.createApprovalCA(intAdmin, caname, CAInfo.REQ_APPROVAL_REVOCATION, getCAAdminSession());
			X509Certificate adminCert = (X509Certificate) getCertStore().findCertificatesByUsername(intAdmin, APPROVINGADMINNAME).iterator().next();
	    	Admin approvingAdmin = new Admin(adminCert);
	    	try {
	    		X509Certificate cert = createUserAndCert(username,caID);
		        String issuerdn = cert.getIssuerDN().toString();
		        String serno = cert.getSerialNumber().toString(16);
			    // revoke via WS and verify response
	        	try {
					ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
					assertTrue(ERRORNOTSENTFORAPPROVAL, false);
				} catch (WaitingForApprovalException_Exception e1) {
				}
	        	try {
					ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
					assertTrue(ERRORNOTSENTFORAPPROVAL, false);
				} catch (ApprovalException_Exception e1) {
				}
				RevokeStatus revokestatus = ejbcaraws.checkRevokationStatus(issuerdn,serno);
		        assertNotNull(revokestatus);
		        assertTrue(revokestatus.getReason() == RevokedCertInfo.NOT_REVOKED);
				// Approve revocation and verify success
		        TestRevocationApproval.approveRevocation(intAdmin, approvingAdmin, username, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD,
		        		ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, getCertStore(), getApprovalSession());
		        // Try to unrevoke certificate
		        try {
		        	ejbcaraws.revokeCert(issuerdn,serno, RevokedCertInfo.NOT_REVOKED);
		        	assertTrue(ERRORNOTSENTFORAPPROVAL, false);
				} catch (WaitingForApprovalException_Exception e) {
				}
		        try {
		        	ejbcaraws.revokeCert(issuerdn,serno, RevokedCertInfo.NOT_REVOKED);
		        	assertTrue(ERRORNOTSENTFORAPPROVAL, false);
		        } catch (ApprovalException_Exception e) {
		        }
				// Approve revocation and verify success
		        TestRevocationApproval.approveRevocation(intAdmin, approvingAdmin, username, RevokedCertInfo.NOT_REVOKED,
		        		ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, getCertStore(), getApprovalSession());
		        // Revoke user
		        try {
		        	ejbcaraws.revokeUser(username, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD, false);
		        	assertTrue(ERRORNOTSENTFORAPPROVAL, false);
				} catch (WaitingForApprovalException_Exception e) {
				}
		        try {
		        	ejbcaraws.revokeUser(username, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD, false);
		        	assertTrue(ERRORNOTSENTFORAPPROVAL, false);
		        } catch (ApprovalException_Exception e) {
		        }
				// Approve revocation and verify success
		        TestRevocationApproval.approveRevocation(intAdmin, approvingAdmin, username, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD,
		        		ApprovalDataVO.APPROVALTYPE_REVOKEENDENTITY, getCertStore(), getApprovalSession());
		        // Try to reactivate user
		        try {
		        	ejbcaraws.revokeUser(username, RevokedCertInfo.NOT_REVOKED, false);
		        	assertTrue(ERRORNOTSUPPORTEDSUCCEEDED, false);
		        } catch (AlreadyRevokedException_Exception e) {
		        }
	    	} finally {
		    	getUserAdminSession().deleteUser(intAdmin, username);
	    	}
	        try {
		        // Create a hard token issued by this CA
		        createHardToken(TOKENUSERNAME, caname, TOKENSERIALNUMBER);
		    	assertTrue(ejbcaraws.existsHardToken(TOKENSERIALNUMBER));
		        // Revoke token
		        try {
			    	ejbcaraws.revokeToken(TOKENSERIALNUMBER, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
		        	assertTrue(ERRORNOTSENTFORAPPROVAL, false);
				} catch (WaitingForApprovalException_Exception e) {
				}
		        try {
			    	ejbcaraws.revokeToken(TOKENSERIALNUMBER, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
		        	assertTrue(ERRORNOTSENTFORAPPROVAL, false);
		        } catch (ApprovalException_Exception e) {
		        }
		        // Approve actions and verify success
		        TestRevocationApproval.approveRevocation(intAdmin, approvingAdmin, TOKENUSERNAME, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD,
		        		ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, getCertStore(), getApprovalSession());
	        } finally {
		        getHardTokenSession().removeHardToken(intAdmin, TOKENSERIALNUMBER);
	        }
	    } finally {
			// Nuke CA
	        try {
	        	getCAAdminSession().revokeCA(intAdmin, caID, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
	        } finally {
	        	getCAAdminSession().removeCA(intAdmin, caID);
	        }
	    }
	} // testRevocationApprovals
	
	/**
	 * Create a user a generate cert. 
	 */
	private X509Certificate createUserAndCert(String username, int caID) throws Exception {
		UserDataVO userdata = new UserDataVO(username,"CN="+username,caID,null,null,1,SecConst.EMPTY_ENDENTITYPROFILE,
				SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.TOKEN_SOFT_P12,0,null);
		userdata.setPassword("foo123");
		getUserAdminSession().addUser(intAdmin, userdata , true);
	    BatchMakeP12 makep12 = new BatchMakeP12();
	    File tmpfile = File.createTempFile("ejbca", "p12");
	    makep12.setMainStoreDir(tmpfile.getParent());
	    makep12.createAllNew();
	    Collection userCerts = getCertStore().findCertificatesByUsername(intAdmin, username);
	    assertTrue( userCerts.size() == 1 );
	    return (X509Certificate) userCerts.iterator().next();
	}

	/**
	 * Creates a "hardtoken" with certficates. 
	 */
	private void createHardToken(String username, String caName, String serialNumber) throws Exception {
    	GlobalConfiguration gc = getRAAdmin().loadGlobalConfiguration(intAdmin);
    	boolean originalProfileSetting = gc.getEnableEndEntityProfileLimitations();
    	gc.setEnableEndEntityProfileLimitations(false);
    	getRAAdmin().saveGlobalConfiguration(intAdmin, gc);
    	if(getCertStore().getCertificateProfileId(intAdmin, "WSTESTPROFILE") != 0){
        	getCertStore().removeCertificateProfile(intAdmin, "WSTESTPROFILE");
        }
        CertificateProfile profile = new EndUserCertificateProfile();
        profile.setAllowValidityOverride(true);
        getCertStore().addCertificateProfile(intAdmin, "WSTESTPROFILE", profile);
		UserDataVOWS tokenUser1 = new UserDataVOWS();
		tokenUser1.setUsername(username);
		tokenUser1.setPassword("foo123");
		tokenUser1.setClearPwd(true);
		tokenUser1.setSubjectDN("CN="+username);
		tokenUser1.setCaName(caName);
		tokenUser1.setEmail(null);
		tokenUser1.setSubjectAltName(null);
		tokenUser1.setStatus(10);
		tokenUser1.setTokenType("USERGENERATED");
		tokenUser1.setEndEntityProfileName("EMPTY");
		tokenUser1.setCertificateProfileName("ENDUSER"); 
		KeyPair basickeys = KeyTools.genKeys("1024", CATokenConstants.KEYALGORITHM_RSA);		
		PKCS10CertificationRequest  basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA",
                CertTools.stringToBcX509Name("CN=NOTUSED"), basickeys.getPublic(), null, basickeys.getPrivate());
		ArrayList<TokenCertificateRequestWS> requests = new ArrayList<TokenCertificateRequestWS>();
		TokenCertificateRequestWS tokenCertReqWS = new TokenCertificateRequestWS();
		tokenCertReqWS.setCAName(caName);
		tokenCertReqWS.setCertificateProfileName("WSTESTPROFILE");
		tokenCertReqWS.setValidityIdDays("1");
		tokenCertReqWS.setPkcs10Data(basicpkcs10.getDEREncoded());
		tokenCertReqWS.setType(HardTokenConstants.REQUESTTYPE_PKCS10_REQUEST);
		requests.add(tokenCertReqWS);
		tokenCertReqWS = new TokenCertificateRequestWS();
		tokenCertReqWS.setCAName(caName);
		tokenCertReqWS.setCertificateProfileName("ENDUSER");
		tokenCertReqWS.setKeyalg("RSA");
		tokenCertReqWS.setKeyspec("1024");
		tokenCertReqWS.setType(HardTokenConstants.REQUESTTYPE_KEYSTORE_REQUEST);
		requests.add(tokenCertReqWS);
		HardTokenDataWS hardTokenDataWS = new HardTokenDataWS();
		hardTokenDataWS.setLabel(HardTokenConstants.LABEL_PROJECTCARD);
		hardTokenDataWS.setTokenType(HardTokenConstants.TOKENTYPE_SWEDISHEID);
		hardTokenDataWS.setHardTokenSN(serialNumber);		
		PinDataWS basicPinDataWS = new PinDataWS();
		basicPinDataWS.setType(HardTokenConstants.PINTYPE_BASIC);
		basicPinDataWS.setInitialPIN("1234");
		basicPinDataWS.setPUK("12345678");
		PinDataWS signaturePinDataWS = new PinDataWS();
		signaturePinDataWS.setType(HardTokenConstants.PINTYPE_SIGNATURE);
		signaturePinDataWS.setInitialPIN("5678");
		signaturePinDataWS.setPUK("23456789");
		hardTokenDataWS.getPinDatas().add(basicPinDataWS);
		hardTokenDataWS.getPinDatas().add(signaturePinDataWS);
		List<TokenCertificateResponseWS> responses = ejbcaraws.genTokenCertificates(tokenUser1, requests, hardTokenDataWS, true, false);
		assertTrue(responses.size() == 2);
		getCertStore().removeCertificateProfile(intAdmin, "WSTESTPROFILE");
		gc.setEnableEndEntityProfileLimitations(originalProfileSetting);
    	getRAAdmin().saveGlobalConfiguration(intAdmin, gc);
	} // createHardToken
}
