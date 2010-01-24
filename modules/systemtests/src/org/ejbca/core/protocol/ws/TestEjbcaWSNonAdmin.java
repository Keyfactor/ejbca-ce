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
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Random;

import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.GenerateTokenApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.ViewHardTokenDataApprovalRequest;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.hardtoken.types.HardToken;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.core.protocol.ws.client.gen.ApprovalRequestExecutionException_Exception;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.core.protocol.ws.client.gen.WaitingForApprovalException_Exception;
import org.ejbca.ui.cli.batch.BatchMakeP12;
import org.ejbca.util.CertTools;
import org.ejbca.util.TestTools;

/** 
 * 
 * @version $Id$
 */
public class TestEjbcaWSNonAdmin extends CommonEjbcaWSTest {

    private static String adminusername1 = null;               
    private static X509Certificate admincert1 = null;        
    private static Admin admin1 = null;
    private static int caid;
	private static GlobalConfiguration gc = null;

    private ArrayList adminentities;
	private Admin intadmin = new Admin(Admin.TYPE_INTERNALUSER);
	private Admin reqadmin;
	
	public void test00SetupAccessRights() throws Exception {
		super.test00SetupAccessRights();
		gc = TestTools.getRaAdminSession().loadGlobalConfiguration(new Admin(Admin.INTERNALCAID));
	}
    
    public void test01checkNonAuthorizatied() throws Exception{	
    	setUpNonAdmin();
    	
		// This is a superadmin keystore, improve in the future
		assertFalse(ejbcaraws.isAuthorized(AccessRulesConstants.ROLE_SUPERADMINISTRATOR));
		
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
		try{
			test33checkQueueLength(false);
		}catch(AuthorizationDeniedException_Exception e){
			assertTrue(false);
		}
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
      	getApprovalSession().approve(admin1, ar.generateApprovalId(), approval1, gc);
      	
      	test14getHardTokenData(false, true);
      	
      	try{
      		test14getHardTokenData(false, true);
      		assertTrue(false);
      	}catch(WaitingForApprovalException_Exception e){}
      	
      	getApprovalSession().reject(admin1, ar.generateApprovalId(), approval1, gc);
      	
      	try{
      		test14getHardTokenData(false, true);
      		assertTrue(false);
      	}catch(ApprovalRequestExecutionException_Exception e){}     
      	
      	removeApprovalAdmins();
    }
    
    public void test03CleanGetHardTokenDataWithApprovals() throws Exception{
    	setupApprovals();
      	ApprovalRequest ar = new ViewHardTokenDataApprovalRequest("WSTESTTOKENUSER1", "CN=WSTESTTOKENUSER1", "12345678", true,reqadmin,null,1,0,0);      	
 
      	Collection result = getApprovalSession().findApprovalDataVO(intAdmin, ar.generateApprovalId());
      	Iterator iter = result.iterator();
      	while(iter.hasNext()){      		
      	  ApprovalDataVO next = (ApprovalDataVO) iter.next();
      	  getApprovalSession().removeApprovalRequest(admin1, next.getId());
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
      	getApprovalSession().approve(admin1, ar.generateApprovalId(), approval1, gc);
      	
      	
      	test12genTokenCertificates(false,true);
      	
    	try{
    		test14getHardTokenData(false, true);
        	assertTrue(false);
       }catch(WaitingForApprovalException_Exception e){}
       
       try{
   		 test12genTokenCertificates(false,true);
    	 assertTrue(false);
       }catch(WaitingForApprovalException_Exception e){}
       
       getApprovalSession().reject(admin1, ar.generateApprovalId(), approval1, gc);
      	
      	try{
      		test12genTokenCertificates(false, true);
      		assertTrue(false);
      	}catch(ApprovalRequestExecutionException_Exception e){} 
      	
      	removeApprovalAdmins();
    }
    
    public void test05CleanGenTokenCertificatesWithApprovals() throws Exception{
    	setupApprovals();
    	ApprovalRequest ar = new GenerateTokenApprovalRequest("WSTESTTOKENUSER1", "CN=WSTESTTOKENUSER1",  HardToken.LABEL_PROJECTCARD,reqadmin,null,1,0,0);      	
 
      	Collection result = getApprovalSession().findApprovalDataVO(intAdmin, ar.generateApprovalId());
      	Iterator iter = result.iterator();
      	while(iter.hasNext()){      		
      	  ApprovalDataVO next = (ApprovalDataVO) iter.next();
      	getApprovalSession().removeApprovalRequest(admin1, next.getId());
      	}
      	
    	ar = new ViewHardTokenDataApprovalRequest("WSTESTTOKENUSER1", "CN=WSTESTTOKENUSER1", "12345678", true,reqadmin,null,1,0,0);
    	 
      	result = getApprovalSession().findApprovalDataVO(intAdmin, ar.generateApprovalId());
      	iter = result.iterator();
      	while(iter.hasNext()){      		
      	  ApprovalDataVO next = (ApprovalDataVO) iter.next();
      	  getApprovalSession().removeApprovalRequest(admin1, next.getId());
      	}  
      	
      	removeApprovalAdmins();
      	getHardTokenSession().removeHardToken(intAdmin, "12345678");
		getUserAdminSession().revokeAndDeleteUser(intAdmin, "WSTESTTOKENUSER1", RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);

    }
    
    public void test99cleanUpAdmins() throws Exception {
    	super.test99cleanUpAdmins();
    }

    //
    // private helper functions
    //
    private void setupApprovals() throws Exception{
		CertTools.installBCProvider();
		
		adminusername1 = genRandomUserName();
 		
		CAInfo cainfo = getCAAdminSession().getCAInfo(intAdmin, getAdminCAName());
		caid = cainfo.getCAId();
             
		UserDataVO userdata = new UserDataVO(adminusername1,"CN="+adminusername1,caid,null,null,1,SecConst.EMPTY_ENDENTITYPROFILE,
				SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.TOKEN_SOFT_P12,0,null);
		userdata.setPassword("foo123");
		getUserAdminSession().addUser(intadmin, userdata , true);
			
		
        BatchMakeP12 makep12 = new BatchMakeP12();
        File tmpfile = File.createTempFile("ejbca", "p12");

        makep12.setMainStoreDir(tmpfile.getParent());
        makep12.createAllNew();
        
        adminentities = new ArrayList();
		adminentities.add(new AdminEntity(AdminEntity.WITH_COMMONNAME,AdminEntity.TYPE_EQUALCASEINS,adminusername1,caid));	
		getAuthSession().addAdminEntities(intadmin, AdminGroup.TEMPSUPERADMINGROUP, adminentities);
		
		getAuthSession().forceRuleUpdate(intadmin);
		
		admincert1 = (X509Certificate) getCertStore().findCertificatesByUsername(intadmin, adminusername1).iterator().next();
		
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

		admin1 = new Admin(admincert1, adminusername1, null);
		reqadmin = TestTools.getUserAdminSession().getAdmin(reqadmincert);
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
		getUserAdminSession().deleteUser(intadmin, adminusername1);
		getAuthSession().removeAdminEntities(intadmin, AdminGroup.TEMPSUPERADMINGROUP, adminentities);					
		
	}
}

