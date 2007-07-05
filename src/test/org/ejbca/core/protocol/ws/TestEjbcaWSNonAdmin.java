package org.ejbca.core.protocol.ws; 

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Random;

import javax.naming.Context;

import org.ejbca.core.ejb.approval.IApprovalSessionHome;
import org.ejbca.core.ejb.approval.IApprovalSessionRemote;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionHome;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionRemote;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.GenerateTokenApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.ViewHardTokenDataApprovalRequest;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.authorization.AvailableAccessRules;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.hardtoken.types.HardToken;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.protocol.ws.client.gen.ApprovalRequestExecutionException_Exception;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.core.protocol.ws.client.gen.WaitingForApprovalException_Exception;
import org.ejbca.ui.cli.batch.BatchMakeP12;
import org.ejbca.util.CertTools;

public class TestEjbcaWSNonAdmin extends CommonEjbcaWSTest {	
    private static String adminusername1 = null;               
    private static X509Certificate admincert1 = null;        
    private static Admin admin1 = null;
    private static Context ctx;
    private static IApprovalSessionRemote pub;
    private static IAuthorizationSessionRemote auth;
    private static IUserAdminSessionRemote user;    
    private static ICertificateStoreSessionRemote store;
    private static int caid;
	private ArrayList adminentities;
	Admin intadmin = new Admin(Admin.TYPE_INTERNALUSER);
	private Admin reqadmin;  

	public void test00SetupAccessRights() throws Exception{
		Admin intAdmin = new Admin(Admin.TYPE_INTERNALUSER);
		boolean userAdded = false;
		
		if(!getUserAdminSession().existsUser(intAdmin, "wstest")){
			UserDataVO user1 = new UserDataVO();
			user1.setUsername("wstest");
			user1.setPassword("foo123");			
			user1.setDN("CN=wstest");			
			CAInfo cainfo = getCAAdminSession().getCAInfo(intAdmin, "AdminCA1");
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
			CAInfo cainfo = getCAAdminSession().getCAInfo(intAdmin, "AdminCA1");
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
	

    
    public void test01checkNonAuthorizatied() throws Exception{	
    	setUpNonAdmin();
    	
		// This is a superadmin keystore, improve in the future
		assertFalse(ejbcaraws.isAuthorized(AvailableAccessRules.ROLE_SUPERADMINISTRATOR));
		
		try{
			test01EditUser(false);
			assertTrue(false);
		}catch(AuthorizationDeniedException_Exception e){}
		
		try{
			test02findUser(false);
			assertTrue(false);
		}catch(AuthorizationDeniedException_Exception e){}
		
		try{
			test03GeneratePkcs10(false);
			assertTrue(false);
		}catch(AuthorizationDeniedException_Exception e){}
		
		try{
			test04GeneratePkcs12(false);
			assertTrue(false);
		}catch(AuthorizationDeniedException_Exception e){}
		
		try{
			test05findCerts(false);
			assertTrue(false);
		}catch(AuthorizationDeniedException_Exception e){}
		
		try{
			test06revokeCert(false);
			assertTrue(false);
		}catch(AuthorizationDeniedException_Exception e){}
		
		try{
			test07revokeToken(false);
			assertTrue(false);
		}catch(AuthorizationDeniedException_Exception e){}
		
		try{
			test08checkRevokeStatus(false);
			assertTrue(false);
		}catch(AuthorizationDeniedException_Exception e){}
		
		try{
			test09UTF8(false);
			assertTrue(false);
		}catch(AuthorizationDeniedException_Exception e){}

		try{
			test10revokeUser(false);
			assertTrue(false);
		}catch(AuthorizationDeniedException_Exception e){}
		
		try{
			test13getExistsHardToken(false);
			assertTrue(false);
		}catch(EjbcaException_Exception e){}
		
		try{
			test15getHardTokenDatas(false);
			assertTrue(false);
		}catch(AuthorizationDeniedException_Exception e){}
		
		try{
			test16CustomLog(false);
			assertTrue(false);
		}catch(AuthorizationDeniedException_Exception e){}

		try{
			test17GetCertificate(false);
			assertTrue(false);
		}catch(AuthorizationDeniedException_Exception e){}		
	}
    
    public void test02GetHardTokenDataWithApprovals() throws Exception{
    	setUpNonAdmin();    	
    	
    	setupApprovals();
    	
    	try{
    	  test14getHardTokenData(false,true);
    	  assertTrue(false);
    	}catch(WaitingForApprovalException_Exception e){}
    	
    	try{
      	  test14getHardTokenData(false,true);
      	  assertTrue(false);
      	}catch(WaitingForApprovalException_Exception e){}
      	
      	Approval approval1 = new Approval("ap1test");
      	
      	ApprovalRequest ar = new ViewHardTokenDataApprovalRequest("WSTESTTOKENUSER1", "CN=WSTESTTOKENUSER1", "12345678", true,reqadmin,null,1,0,0);      	
      	pub.approve(admin1, ar.generateApprovalId(), approval1);
      	
      	test14getHardTokenData(false, true);
      	
      	try{
      		test14getHardTokenData(false, true);
      		assertTrue(false);
      	}catch(WaitingForApprovalException_Exception e){}
      	
      	pub.reject(admin1, ar.generateApprovalId(), approval1);
      	
      	try{
      		test14getHardTokenData(false, true);
      		assertTrue(false);
      	}catch(ApprovalRequestExecutionException_Exception e){}     
      	
      	removeApprovalAdmins();
    }
    
    public void test03CleanGetHardTokenDataWithApprovals() throws Exception{
    	setupApprovals();
      	ApprovalRequest ar = new ViewHardTokenDataApprovalRequest("WSTESTTOKENUSER1", "CN=WSTESTTOKENUSER1", "12345678", true,reqadmin,null,1,0,0);      	
 
      	Collection result = pub.findApprovalDataVO(intAdmin, ar.generateApprovalId());
      	Iterator iter = result.iterator();
      	while(iter.hasNext()){      		
      	  ApprovalDataVO next = (ApprovalDataVO) iter.next();
      	  pub.removeApprovalRequest(admin1, next.getId());
      	}      	      
      	
      	removeApprovalAdmins();
    }
    
    public void test04GenTokenCertificatesWithApprovals() throws Exception{
    	setUpNonAdmin();
    	setupApprovals();
    	try{
    	  test12genTokenCertificates(false, true);
    	  assertTrue(false);
    	}catch(WaitingForApprovalException_Exception e){}
    	
    	try{
      	  test12genTokenCertificates(false,true);
      	  assertTrue(false);
      	}catch(WaitingForApprovalException_Exception e){}
    	
      	Approval approval1 = new Approval("ap1test");
      	
      	ApprovalRequest ar = new GenerateTokenApprovalRequest("WSTESTTOKENUSER1", "CN=WSTESTTOKENUSER1",  HardToken.LABEL_PROJECTCARD,reqadmin,null,1,0,0);      	
      	pub.approve(admin1, ar.generateApprovalId(), approval1);
      	
      	
      	test12genTokenCertificates(false,true);
      	
    	try{
    		test14getHardTokenData(false, true);
        	assertTrue(false);
       }catch(WaitingForApprovalException_Exception e){}
       
       try{
   		 test12genTokenCertificates(false,true);
    	 assertTrue(false);
       }catch(WaitingForApprovalException_Exception e){}
       
     	pub.reject(admin1, ar.generateApprovalId(), approval1);
      	
      	try{
      		test12genTokenCertificates(false, true);
      		assertTrue(false);
      	}catch(ApprovalRequestExecutionException_Exception e){} 
      	
      	removeApprovalAdmins();
    }
    
    public void test05CleanGenTokenCertificatesWithApprovals() throws Exception{
    	setupApprovals();
    	ApprovalRequest ar = new GenerateTokenApprovalRequest("WSTESTTOKENUSER1", "CN=WSTESTTOKENUSER1",  HardToken.LABEL_PROJECTCARD,reqadmin,null,1,0,0);      	
 
      	Collection result = pub.findApprovalDataVO(intAdmin, ar.generateApprovalId());
      	Iterator iter = result.iterator();
      	while(iter.hasNext()){      		
      	  ApprovalDataVO next = (ApprovalDataVO) iter.next();
      	  pub.removeApprovalRequest(admin1, next.getId());
      	}
      	
    	ar = new ViewHardTokenDataApprovalRequest("WSTESTTOKENUSER1", "CN=WSTESTTOKENUSER1", "12345678", true,reqadmin,null,1,0,0);
    	 
      	result = pub.findApprovalDataVO(intAdmin, ar.generateApprovalId());
      	iter = result.iterator();
      	while(iter.hasNext()){      		
      	  ApprovalDataVO next = (ApprovalDataVO) iter.next();
      	  pub.removeApprovalRequest(admin1, next.getId());
      	}  
      	
      	removeApprovalAdmins();
    }
    
    private void setupApprovals() throws Exception{
		ctx = getInitialContext();
		Object obj = ctx.lookup("ApprovalSession");
		IApprovalSessionHome home = (IApprovalSessionHome) javax.rmi.PortableRemoteObject.narrow(obj,
				IApprovalSessionHome.class);
		pub = home.create();
		
		obj = ctx.lookup("AuthorizationSession");
		IAuthorizationSessionHome authhome = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(obj,
				IAuthorizationSessionHome.class);
		auth = authhome.create();
		
		obj = ctx.lookup("UserAdminSession");
		IUserAdminSessionHome userhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj,
				IUserAdminSessionHome.class);
		user = userhome.create();
		
	    obj = ctx.lookup("CertificateStoreSession");
	    ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, ICertificateStoreSessionHome.class);        
	    store = storehome.create();

		CertTools.installBCProvider();
		
		adminusername1 = genRandomUserName();
 		
             
        Collection admingroups = auth.getAuthorizedAdminGroupNames(intadmin);
        Iterator iter = admingroups.iterator();
        
        while(iter.hasNext()){
        	AdminGroup group = (AdminGroup) iter.next();
        	if(group.getAdminGroupName().equals("Temporary Super Administrator Group")){
        		caid = group.getCAId();
        		
        	}
        }
		
		UserDataVO userdata = new UserDataVO(adminusername1,"CN="+adminusername1,caid,null,null,1,SecConst.EMPTY_ENDENTITYPROFILE,
				SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.TOKEN_SOFT_P12,0,null);
		userdata.setPassword("foo123");
		user.addUser(intadmin, userdata , true);
			
		
        BatchMakeP12 makep12 = new BatchMakeP12();
        File tmpfile = File.createTempFile("ejbca", "p12");

        //System.out.println("tempdir="+tmpfile.getParent());
        makep12.setMainStoreDir(tmpfile.getParent());
        makep12.createAllNew();
        
        adminentities = new ArrayList();
		adminentities.add(new AdminEntity(AdminEntity.WITH_COMMONNAME,AdminEntity.TYPE_EQUALCASEINS,adminusername1,caid));	
		auth.addAdminEntities(intadmin, "Temporary Super Administrator Group", caid, adminentities);
		
		auth.forceRuleUpdate(intadmin);
		
		admincert1 = (X509Certificate) store.findCertificatesByUsername(intadmin, adminusername1).iterator().next();
		
		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(new FileInputStream("p12/wsnonadmintest.jks"), "foo123".toCharArray());
		Enumeration enumer = ks.aliases();
		X509Certificate reqadmincert = null;
		while(enumer.hasMoreElements()){
			String nextAlias = (String) enumer.nextElement();
			if(nextAlias.equals("wsnonadmintest")){
			  reqadmincert = (X509Certificate) ks.getCertificate(nextAlias);
			}
		}
		
		
		
		admin1 = new Admin(admincert1);
		reqadmin = new Admin(reqadmincert);

    }

    private String genRandomUserName() throws Exception {
        // Gen random user
        Random rand = new Random(new Date().getTime() + 4711);
        String username = "";
        for (int i = 0; i < 6; i++) {
            int randint = rand.nextInt(9);
            username += (new Integer(randint)).toString();
        }

        return username;
    } // genRandomUserName
    
    protected void removeApprovalAdmins() throws Exception {
		user.deleteUser(intadmin, adminusername1);
		auth.removeAdminEntities(intadmin, "Temporary Super Administrator Group", caid, adminentities);					
		
	}
}

