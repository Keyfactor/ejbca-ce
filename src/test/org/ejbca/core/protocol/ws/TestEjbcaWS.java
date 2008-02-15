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
 * @version $Id: TestEjbcaWS.java,v 1.14 2008-02-15 14:50:27 anatom Exp $
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

    public void test21GetAvailableCAs() throws Exception {
    	test21GetAvailableCAs(true);  
    }

    
    public void test99cleanUpAdmins() throws Exception {
    	super.test99cleanUpAdmins();
    }
    
}

