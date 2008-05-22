package org.ejbca.core.protocol.ws; 

import org.ejbca.core.model.authorization.AvailableAccessRules;

/** To run you must have the file tmp/bin/junit/jndi.properties
 * 
 * @version $Id$
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

	public void test03_1GeneratePkcs10() throws Exception{
		test03GeneratePkcs10(true);
	}

	public void test03_2GenerateCrmf() throws Exception{
		test03GenerateCrmf(true);
	}

	public void test03_3GenerateSpkac() throws Exception{
		test03GenerateSpkac(true);
	}

    public void test03_4GeneratePkcs10Request() throws Exception {
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

    public void test21GetAvailableCAs() throws Exception {
    	test21GetAvailableCAs(true);  
    }

    public void test22GetAuthorizedEndEntityProfiles() throws Exception {
    	test22GetAuthorizedEndEntityProfiles(true);  
    }
    public void test23GetAvailableCertificateProfiles() throws Exception {
    	test23GetAvailableCertificateProfiles(true);  
    }
    public void test24GetAvailableCAsInProfile() throws Exception {
    	test24GetAvailableCAsInProfile(true);  
    }

    public void test25CreateCRL() throws Exception {
    	test25CreateCRL(true);  
    }

    public void test26CVCRequest() throws Exception {
    	test26CVCRequest(true);  
    }
    
    public void test99cleanUpAdmins() throws Exception {
    	super.test99cleanUpAdmins();
    }
    
}

