package org.ejbca.core.protocol.ws; 

import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;

import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.authorization.AvailableAccessRules;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;

/** To run you must have the file tmp/bin/junit/jndi.properties
 * 
 * @version $Id: TestEjbcaWS.java,v 1.12 2007-11-22 17:17:21 anatom Exp $
 */
public class TestEjbcaWS extends CommonEjbcaWSTest {
	
	
	public void test00SetupAccessRights() throws Exception{
		super.test00SetupAccessRights();
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

    public void test20KeyRecoverNewest() throws Exception {
    	test20KeyRecover(true);  
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
        
		// Remove test user
        try {
        	getUserAdminSession().revokeAndDeleteUser(intAdmin, "WSTESTUSER1", RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
        } catch (Exception e) {
        	e.printStackTrace();
        }
        try {
        	getUserAdminSession().revokeAndDeleteUser(intAdmin, "WSTESTUSERKEYREC1", RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
        } catch (Exception e) {
        	e.printStackTrace();
        }
        // Remove Key recovery end entity profile
        try {
        	getRAAdmin().removeEndEntityProfile(intAdmin, "KEYRECOVERY");
        } catch (Exception e) {
        	e.printStackTrace();
        }

    }
    
}

