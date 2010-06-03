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
package org.ejbca.core.model.approval.approvalrequests;

import java.io.File;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;

import junit.framework.TestCase;

import org.ejbca.core.ejb.approval.IApprovalSessionRemote;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStatus;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.catoken.CATokenInfo;
import org.ejbca.core.model.ca.catoken.SoftCATokenInfo;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.ui.cli.batch.BatchMakeP12;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.TestTools;
import org.ejbca.util.query.ApprovalMatch;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.Query;

public class RevocationApprovalTest extends TestCase {

    private static IApprovalSessionRemote approvalSession = TestTools.getApprovalSession();
    private static IAuthorizationSessionRemote authorizationSession = TestTools.getAuthorizationSession();
    private static IUserAdminSessionRemote userAdminSession = TestTools.getUserAdminSession();
    private static ICertificateStoreSessionRemote certificateStoreSession = TestTools.getCertificateStoreSession();
    private static ICAAdminSessionRemote caAdminSession = TestTools.getCAAdminSession();
    
    private static String requestingAdminUsername = null;
    private static String adminUsername = null;
    
    private static final Admin internalAdmin = new Admin(Admin.TYPE_INTERNALUSER);
    private static Admin reuestingAdmin = null;
    private static Admin approvingAdmin = null;
    private static ArrayList adminentities;
    
    private static int caid = TestTools.getTestCAId();
    private int approvalCAID;

    public RevocationApprovalTest(String name) {
        super(name);
        CryptoProviderTools.installBCProvider();
        TestTools.createTestCA();
    }
    
	protected void setUp() throws Exception {
		super.setUp();
		adminUsername = genRandomUserName("revocationTestAdmin");
		requestingAdminUsername = genRandomUserName("revocationTestRequestingAdmin");
		UserDataVO userdata = new UserDataVO(adminUsername,"CN="+adminUsername,caid,null,null,1,SecConst.EMPTY_ENDENTITYPROFILE,
				SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.TOKEN_SOFT_P12,0,null);
		userdata.setPassword("foo123");
		userAdminSession.addUser(internalAdmin, userdata , true);
		UserDataVO userdata2 = new UserDataVO(requestingAdminUsername,"CN="+requestingAdminUsername,caid,null,null,1,SecConst.EMPTY_ENDENTITYPROFILE,
				SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.TOKEN_SOFT_P12,0,null);
		userdata2.setPassword("foo123");
		userAdminSession.addUser(internalAdmin, userdata2 , true);
	    BatchMakeP12 makep12 = new BatchMakeP12();
	    File tmpfile = File.createTempFile("ejbca", "p12");
	    makep12.setMainStoreDir(tmpfile.getParent());
	    makep12.createAllNew();
		adminentities = new ArrayList();
		adminentities.add(new AdminEntity(AdminEntity.WITH_COMMONNAME,AdminEntity.TYPE_EQUALCASEINS,adminUsername,caid));	
		adminentities.add(new AdminEntity(AdminEntity.WITH_COMMONNAME,AdminEntity.TYPE_EQUALCASEINS,requestingAdminUsername,caid));
		authorizationSession.addAdminEntities(internalAdmin, AdminGroup.TEMPSUPERADMINGROUP, adminentities);
		authorizationSession.forceRuleUpdate(internalAdmin);
		X509Certificate admincert = (X509Certificate) certificateStoreSession.findCertificatesByUsername(internalAdmin, adminUsername).iterator().next();
		X509Certificate reqadmincert = (X509Certificate) certificateStoreSession.findCertificatesByUsername(internalAdmin, requestingAdminUsername).iterator().next();
		approvingAdmin = new Admin(admincert, adminUsername, null);
		reuestingAdmin = new Admin(reqadmincert, requestingAdminUsername, null);
		// Create new CA using approvals
        String caname = RevocationApprovalTest.class.getSimpleName();
		approvalCAID = createApprovalCA(internalAdmin, caname, CAInfo.REQ_APPROVAL_REVOCATION, caAdminSession);
	}
	
	protected void tearDown() throws Exception {
		super.tearDown();
		userAdminSession.deleteUser(internalAdmin, adminUsername);
		userAdminSession.deleteUser(internalAdmin, requestingAdminUsername);
		authorizationSession.removeAdminEntities(internalAdmin, AdminGroup.TEMPSUPERADMINGROUP, adminentities);					
		caAdminSession.removeCA(internalAdmin, approvalCAID);
	}

	private String genRandomUserName(String usernameBase) {
	    usernameBase += (new Integer((new Random(new Date().getTime() + 4711)).nextInt(999999))).toString();
	    return usernameBase;
	}
	
	private void createUser(Admin admin, String username, int caID) throws Exception {
		UserDataVO userdata = new UserDataVO(username,"CN="+username,caID,null,null,1,SecConst.EMPTY_ENDENTITYPROFILE,
				SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.TOKEN_SOFT_P12,0,null);
		userdata.setPassword("foo123");
		userAdminSession.addUser(admin, userdata , true);
	    BatchMakeP12 makep12 = new BatchMakeP12();
	    File tmpfile = File.createTempFile("ejbca", "p12");
	    makep12.setMainStoreDir(tmpfile.getParent());
	    makep12.createAllNew();
	}

	/**
	 *	Find all certificates for a user and approve any outstanding revocation. 
	 */
	static public int approveRevocation(Admin internalAdmin, Admin approvingAdmin, String username, int reason, int approvalType,
			ICertificateStoreSessionRemote certificateStoreSession, IApprovalSessionRemote approvalSession, int approvalCAID) throws Exception {
	    Collection userCerts = certificateStoreSession.findCertificatesByUsername(internalAdmin, username);
	    Iterator i = userCerts.iterator();
	    int approvedRevocations = 0;
	    while ( i.hasNext() ) {
	    	X509Certificate cert = (X509Certificate) i.next();
	        String issuerDN = cert.getIssuerDN().toString();
	        BigInteger serialNumber = cert.getSerialNumber();
	        boolean isRevoked = certificateStoreSession.isRevoked(issuerDN, serialNumber);
		    if ( (reason != RevokedCertInfo.NOT_REVOKED && !isRevoked )
		    		|| (reason == RevokedCertInfo.NOT_REVOKED && isRevoked) )  {
				int approvalID;
				if (approvalType == ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE) {
					approvalID = RevocationApprovalRequest.generateApprovalId(approvalType, username, reason, serialNumber, issuerDN);
				} else {
					approvalID = RevocationApprovalRequest.generateApprovalId(approvalType, username, reason, null, null);
				}
				Query q = new Query(Query.TYPE_APPROVALQUERY);
				q.add(ApprovalMatch.MATCH_WITH_APPROVALID, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(approvalID));
				ApprovalDataVO approvalData = (ApprovalDataVO) (approvalSession.query(internalAdmin, q, 0, 1, "cAId="+approvalCAID, "(endEntityProfileId="+SecConst.EMPTY_ENDENTITYPROFILE+")").get(0));
				Approval approval = new Approval("Approved during testing.");
				approvalSession.approve(approvingAdmin, approvalID, approval, TestTools.getRaAdminSession().loadGlobalConfiguration(new Admin(Admin.INTERNALCAID)));
				approvalData = (ApprovalDataVO) approvalSession.findApprovalDataVO(internalAdmin, approvalID).iterator().next();
				assertEquals(approvalData.getStatus(), ApprovalDataVO.STATUS_EXECUTED);
		        CertificateStatus status = certificateStoreSession.getStatus(issuerDN, serialNumber);
				assertEquals(status.revocationReason, reason);
				approvalSession.removeApprovalRequest(internalAdmin, approvalData.getId());
		        approvedRevocations++;
		    }
	    }
	    return approvedRevocations;
	} // approveRevocation
	
	/**
	 * Create a CA with one of the approval-requirements enabled.
	 * @return the CA's ID.
	 */
	static public int createApprovalCA(Admin internalAdmin, String nameOfCA, int approvalRequirementType, ICAAdminSessionRemote caAdminSession) throws Exception {
        CATokenInfo catokeninfo = new SoftCATokenInfo();
        catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
        ((SoftCATokenInfo) catokeninfo).setSignKeySpec("1024");
        catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
        ((SoftCATokenInfo) catokeninfo).setEncKeySpec("1024");
        ArrayList approvalSettings = new ArrayList();
        approvalSettings.add(approvalRequirementType);
		X509CAInfo cainfo = new X509CAInfo("CN="+nameOfCA, nameOfCA, SecConst.CA_ACTIVE, new Date(), "", SecConst.CERTPROFILE_FIXED_ROOTCA,
        		365, new Date(System.currentTimeMillis()+364*24*3600*1000), CAInfo.CATYPE_X509, CAInfo.SELFSIGNED, null,
        		catokeninfo, "Used for testing approvals", -1, null, null, 24, 0, 10, 0, new ArrayList(), true,
        		false, true, false, "", "", "", "", true, new ArrayList(), false, approvalSettings, 1, false, true, false, false, true, true, true, false);
		int caID = cainfo.getCAId();
        try {
        	caAdminSession.revokeCA(internalAdmin, caID, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
        	caAdminSession.removeCA(internalAdmin, caID);
        } catch (Exception e) {
        }
        caAdminSession.createCA(internalAdmin, cainfo);
		cainfo = (X509CAInfo) caAdminSession.getCAInfo(internalAdmin, caID);
        assertNotNull(cainfo);
        return caID;
	}

	
	/**
	 * Verify that normal operations are working
	 */ 
	public void test01VerifyAddRemoveUser() throws Exception {
		String username = genRandomUserName("test01Revocation");
		try {
			createUser(internalAdmin, username, approvalCAID);
		} finally {
			userAdminSession.deleteUser(internalAdmin, username);
		}
	} // test01VerifyAddRemoveUser

	public void test02RevokeUser() throws Exception {
		String username = genRandomUserName("test02Revocation");
		try {
			createUser(internalAdmin, username, approvalCAID);
		    try {
				userAdminSession.revokeUser(reuestingAdmin, username, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
				assertTrue("Approval code never interrupted run.",false);
			} catch (ApprovalException e) {
				assertTrue("Reporting that approval request exists, when it does not.",false);
			} catch (WaitingForApprovalException e) {
			}
		    try {
				userAdminSession.revokeUser(reuestingAdmin, username, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
				assertTrue("Approval code never interrupted run.",false);
			} catch (ApprovalException e) {
			} catch (WaitingForApprovalException e) {
				assertTrue("Allowing addition of identical approval requests.",false);
			}
			approveRevocation(internalAdmin, approvingAdmin, username, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED,
					ApprovalDataVO.APPROVALTYPE_REVOKEENDENTITY, certificateStoreSession, approvalSession, approvalCAID);
			// Make sure userstatus changed to revoked
			UserDataVO userdata = userAdminSession.findUser(internalAdmin, username);
			assertTrue("User was not revoked when last cert was.", userdata.getStatus() == UserDataConstants.STATUS_REVOKED); 
		} finally {
			userAdminSession.deleteUser(internalAdmin, username);
		}
	} // test02RevokeUser

	public void test03RevokeAndDeleteUser() throws Exception {
		String username = genRandomUserName("test03Revocation");
		try {
			createUser(internalAdmin, username, approvalCAID);
		    try {
				userAdminSession.revokeAndDeleteUser(reuestingAdmin, username, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
				assertTrue("Approval code never interrupted run.",false);
			} catch (ApprovalException e) {
				assertTrue("Reporting that approval request exists, when it does not.",false);
			} catch (WaitingForApprovalException e) {
			}
		    try {
				userAdminSession.revokeAndDeleteUser(reuestingAdmin, username, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
				assertTrue("Approval code never interrupted run.",false);
			} catch (ApprovalException e) {
			} catch (WaitingForApprovalException e) {
				assertTrue("Allowing addition of identical approval requests.",false);
			}
			approveRevocation(internalAdmin, approvingAdmin, username, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED,
					ApprovalDataVO.APPROVALTYPE_REVOKEANDDELETEENDENTITY, certificateStoreSession, approvalSession, approvalCAID);
		} finally {
			try {
				userAdminSession.deleteUser(internalAdmin, username);
			} catch (NotFoundException e) {
				// This is what we expect if everything went ok
			}
		}
	} // test03RevokeAndDeleteUser

	public void test04RevokeAndUnrevokeCertificateOnHold() throws Exception {
		String username = genRandomUserName("test04Revocation");
		final String ERRORNOTSENTFORAPPROVAL = "The request was never sent for approval.";
		final String ERRORNONEXISTINGAPPROVALREPORTED = "Reporting that approval request exists, when it does not.";
		final String ERRORALLOWMORETHANONE = "Allowing more than one identical approval requests.";
		try {
			createUser(internalAdmin, username, approvalCAID);
			X509Certificate usercert = (X509Certificate) certificateStoreSession.findCertificatesByUsername(internalAdmin, username).iterator().next();
			try {
		    	userAdminSession.revokeCert(reuestingAdmin, usercert.getSerialNumber(), usercert.getIssuerDN().toString(), username, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
				assertTrue(ERRORNOTSENTFORAPPROVAL, false);
			} catch (ApprovalException e) {
				assertTrue(ERRORNONEXISTINGAPPROVALREPORTED, false);
			} catch (WaitingForApprovalException e) {
			}
		    try {
		    	userAdminSession.revokeCert(reuestingAdmin, usercert.getSerialNumber(), usercert.getIssuerDN().toString(), username, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
				assertTrue(ERRORNOTSENTFORAPPROVAL, false);
			} catch (ApprovalException e) {
			} catch (WaitingForApprovalException e) {
				assertTrue(ERRORALLOWMORETHANONE, false);
			}
			approveRevocation(internalAdmin, approvingAdmin, username, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD,
					ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, certificateStoreSession, approvalSession, approvalCAID);
			// Unrevoke
			try {
		    	userAdminSession.revokeCert(reuestingAdmin, usercert.getSerialNumber(), usercert.getIssuerDN().toString(), username, RevokedCertInfo.NOT_REVOKED);
				assertTrue(ERRORNOTSENTFORAPPROVAL, false);
			} catch (ApprovalException e) {
				assertTrue(ERRORNONEXISTINGAPPROVALREPORTED, false);
			} catch (WaitingForApprovalException e) {
			}
		    try {
		    	userAdminSession.revokeCert(reuestingAdmin, usercert.getSerialNumber(), usercert.getIssuerDN().toString(), username, RevokedCertInfo.NOT_REVOKED);
				assertTrue(ERRORNOTSENTFORAPPROVAL, false);
			} catch (ApprovalException e) {
			} catch (WaitingForApprovalException e) {
				assertTrue(ERRORALLOWMORETHANONE, false);
			}
			approveRevocation(internalAdmin, approvingAdmin, username, RevokedCertInfo.NOT_REVOKED,
					ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, certificateStoreSession, approvalSession, approvalCAID);
		} finally {
			userAdminSession.deleteUser(internalAdmin, username);
		}
	} // test04RevokeAndUnrevokeCertificateOnHold

	public void testZZZCleanUp() throws Exception {
		TestTools.removeTestCA();
	}
}
