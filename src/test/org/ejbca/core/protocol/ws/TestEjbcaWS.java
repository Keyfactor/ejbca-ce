package org.ejbca.core.protocol.ws; 

import java.util.ArrayList;
import java.util.Iterator;

import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.authorization.AvailableAccessRules;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.ui.cli.batch.BatchMakeP12;

public class TestEjbcaWS extends CommonEjbcaWSTest {
	

	
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
	
	public void test01EditUser() throws Exception{
		test01EditUser(true);
	}

	
	public void test02findUser() throws Exception{
		test02findUser(true);
	}		
	
	
	
	public void test03GeneratePkcs10() throws Exception{
		test03GeneratePkcs10(true);
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
    
  
    
}

