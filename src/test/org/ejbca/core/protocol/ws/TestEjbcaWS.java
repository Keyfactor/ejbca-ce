package org.ejbca.core.protocol.ws; 

import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;

import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.authorization.AvailableAccessRules;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.ui.cli.batch.BatchMakeP12;

/** To run you must have the file tmp/bin/junit/jndi.properties
 * 
 * @version $Id: TestEjbcaWS.java,v 1.11 2007-08-22 12:07:39 herrvendil Exp $
 */
public class TestEjbcaWS extends CommonEjbcaWSTest {
	
	private final static String wsTestAdminUsername = "wstest";
	private final static String wsTestNonAdminUsername = "wsnonadmintest";
	private final static Admin intAdmin = new Admin(Admin.TYPE_INTERNALUSER);
	
	public void test00SetupAccessRights() throws Exception{
		//Admin intAdmin = new Admin(Admin.TYPE_INTERNALUSER);
		boolean userAdded = false;
		
		if(!getUserAdminSession().existsUser(intAdmin, wsTestAdminUsername)){
			UserDataVO user1 = new UserDataVO();
			user1.setUsername(wsTestAdminUsername);
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
				if(adminEntity.getMatchValue().equals(wsTestAdminUsername)){
					adminExists = true;
				}
			}
			
			if(!adminExists){
				ArrayList list = new ArrayList();
				list.add(new AdminEntity(AdminEntity.WITH_COMMONNAME,AdminEntity.TYPE_EQUALCASE,wsTestAdminUsername,cainfo.getCAId()));
				getAuthSession().addAdminEntities(intAdmin, "Temporary Super Administrator Group", cainfo.getCAId(), list);
				getAuthSession().forceRuleUpdate(intAdmin);
			}
			
		}
		
		if(!getUserAdminSession().existsUser(intAdmin, wsTestNonAdminUsername)){
			UserDataVO user1 = new UserDataVO();
			user1.setUsername(wsTestNonAdminUsername);
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
	
	public void test01EditUser() throws Exception{
		test01EditUser(true);
	}

	
	public void test02findUser() throws Exception{
		test02findUser(true);
	}		
	
	
	
	public void test03GeneratePkcs10() throws Exception{
		test03GeneratePkcs10(true);
	}
	
    public void test03_2GeneratePkcs10Request() throws Exception {
    	test19GeneratePkcs10Request(true);  
    }
	

	public void test04GeneratePkcs12() throws Exception{
		test04GeneratePkcs12(true);
	}
	
	public void test05findCerts() throws Exception{
	  test05findCerts(true);	
	}
	
	public void test06revokeCert() throws Exception{
		test06revokeCert(true);
	}

	public void test07revokeToken() throws Exception{
		test07revokeToken(true);
	}
	
	public void test08checkRevokeStatus() throws Exception{
	   test08checkRevokeStatus(true);
	}
	
	
	public void test09UTF8() throws Exception{
		test09UTF8(true);
	}
	
	public void test10revokeUser() throws Exception{
		test10revokeUser(true);
	}
	
    public void test11IsAuthorized() throws Exception{
    	setUpAdmin();
    	
		// This is a superadmin keystore, improve in the future
		assertTrue(ejbcaraws.isAuthorized(AvailableAccessRules.ROLE_SUPERADMINISTRATOR));
	}

 
  
    public void test13genTokenCertificates() throws Exception{
    	test12genTokenCertificates(true,false);
    }
    
    
    public void test14getExistsHardToken() throws Exception{
    	test13getExistsHardToken(true);
    }
  

    public void test15getHardTokenData() throws Exception{
    	test14getHardTokenData(true, false);
    }
    
    
    public void test16getHardTokenDatas() throws Exception{
       test15getHardTokenDatas(true);
    }

    public void test17CustomLog() throws Exception{
      test16CustomLog(true);
    }

    public void test18GetCertificate() throws Exception{
      test17GetCertificate(true);
    }
    
    public void test19RevocationApprovals() throws Exception {
    	test18RevocationApprovals(true);  
    }
    

    
    public void test99cleanUp() throws Exception {
		//getHardTokenSession().removeHardToken(intAdmin, "12345678");
		//getUserAdminSession().revokeAndDeleteUser(intAdmin, "WSTESTTOKENUSER1", RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
		if (getUserAdminSession().existsUser(intAdmin, wsTestAdminUsername)) {
			// Remove from admin group
			CAInfo cainfo = getCAAdminSession().getCAInfo(intAdmin, getAdminCAName());
			AdminGroup admingroup = getAuthSession().getAdminGroup(intAdmin, "Temporary Super Administrator Group", cainfo.getCAId());
			Iterator iter = admingroup.getAdminEntities().iterator();
			while(iter.hasNext()){
				AdminEntity adminEntity = (AdminEntity) iter.next();
				if(adminEntity.getMatchValue().equals(wsTestAdminUsername)){
					ArrayList list = new ArrayList();
					list.add(new AdminEntity(AdminEntity.WITH_COMMONNAME,AdminEntity.TYPE_EQUALCASE,wsTestAdminUsername,cainfo.getCAId()));
					getAuthSession().removeAdminEntities(intAdmin, "Temporary Super Administrator Group", cainfo.getCAId(), list);
					getAuthSession().forceRuleUpdate(intAdmin);
				}
			}
			// Remove user
			getUserAdminSession().revokeAndDeleteUser(intAdmin, wsTestAdminUsername, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
		}
		if (getUserAdminSession().existsUser(intAdmin, wsTestNonAdminUsername)) {
			getUserAdminSession().revokeAndDeleteUser(intAdmin, wsTestNonAdminUsername, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
		}
        if (new File("p12/" + wsTestAdminUsername + ".jks").exists()) {
        	new File("p12/" + wsTestAdminUsername + ".jks").delete();
        }
        if (new File("p12/" + wsTestNonAdminUsername + ".jks").exists()) {
        	new File("p12/" + wsTestNonAdminUsername + ".jks").delete();
        }
    }
    
}

