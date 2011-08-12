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

package org.ejbca.core.ejb.ra;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.rmi.RemoteException;
import java.rmi.ServerException;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Random;

import javax.ejb.EJBException;
import javax.persistence.PersistenceException;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ErrorCode;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.util.InterfaceCache;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.Query;
import org.ejbca.util.query.UserMatch;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/** Tests the UserData entity bean and some parts of UserAdminSession.
 *
 * @version $Id$
 */
public class UserAdminSessionTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(UserAdminSessionTest.class);
    private static final AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
    private int caid = getTestCAId();

    private static String username;
    private static String pwd;
    private static ArrayList<String> usernames = new ArrayList<String>();
    private static String serialnumber;

    private CAAdminSessionRemote caAdminSession = InterfaceCache.getCAAdminSession();
    private CaSessionRemote caSession = InterfaceCache.getCaSession();
    private EndEntityProfileSessionRemote endEntityProfileSession = InterfaceCache.getEndEntityProfileSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();
    private CertificateStoreSessionRemote storeSession = InterfaceCache.getCertificateStoreSession();
    private SignSessionRemote signSession = InterfaceCache.getSignSession();

    @BeforeClass
    public static void beforeClass() {
 
		CryptoProviderTools.installBCProviderIfNotAvailable();        

    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        for (int i = 0; i < usernames.size(); i++) {
            try {
                userAdminSession.deleteUser(admin, (String) usernames.get(i));
            } catch (Exception e) {
            } // NOPMD, ignore errors so we don't stop deleting users because
              // one of them does not exist.
        }
        try {
            endEntityProfileSession.removeEndEntityProfile(admin, "TESTMERGEWITHWS");
        } catch (Exception e) {
        } // NOPMD, ignore errors so we don't stop deleting users because one of
          // them does not exist.

    }

    private void genRandomSerialnumber() throws Exception {
        // Gen random number
        Random rand = new Random(new Date().getTime() + 4913);
        serialnumber = "";
        for (int i = 0; i < 8; i++) {
            int randint = rand.nextInt(9);
            serialnumber += (Integer.valueOf(randint)).toString();
        }
        log.debug("Generated random serialnumber: serialnumber =" + serialnumber);

    } // genRandomSerialnumber

    /**
     * tests creation of new user and duplicate user
     * 
     * @throws Exception
     *             error
     */
    @Test
    public void test01AddUser() throws Exception {
        log.trace(">test01AddUser()");

        // Make user that we know later...
        username = genRandomUserName();
        pwd = genRandomPwd();
        String email = username + "@anatom.se";
        userAdminSession.addUser(admin, username, pwd, "C=SE, O=AnaTom, CN=" + username, "rfc822name=" + email, email, true, SecConst.EMPTY_ENDENTITYPROFILE,
                SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, caid);
        usernames.add(username);
        log.debug("created user: " + username + ", " + pwd + ", C=SE, O=AnaTom, CN=" + username);
        // Add the same user again
        boolean userexists = false;
        try {
            userAdminSession.addUser(admin, username, pwd, "C=SE, O=AnaTom, CN=" + username, "rfc822name=" + email, email, true,
                    SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, caid);
        } catch (EJBException ejbException) {
        	// On Glassfish, ejbException.getCause() returns null, getCausedByException() should be used. 
        	Exception e = ejbException.getCausedByException();
           	log.debug("Exception cause thrown: " + e.getClass().getName() + " message: " + e.getMessage());
        	if (e instanceof PersistenceException) {
        		userexists = true;	// This is what we want
        	} else if (e instanceof ServerException) {
                // Glassfish 2 throws EJBException(java.rmi.ServerException(java.rmi.RemoteException(javax.persistence.EntityExistsException)))), can you believe this?
        		Throwable t = e.getCause();
            	if (t != null && t instanceof RemoteException) {
            		t = t.getCause();
                	log.debug("Exception cause thrown: " + t.getClass().getName() + " message: " + t.getMessage());
            		if (t != null && t instanceof PersistenceException) {
                		userexists = true;	// This is what we want
            		}
            	}
        	}
        }
        assertTrue("User already exist does not throw DuplicateKeyException", userexists);

        // try to add user with non-existing CA-id
        String username2 = genRandomUserName();
        int fakecaid = -1;
        boolean thrown = false;
        try {
            userAdminSession.addUser(admin, username2, pwd, "C=SE, O=AnaTom, CN=" + username2, null, null, true, SecConst.EMPTY_ENDENTITYPROFILE,
                    SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, fakecaid);
            assertTrue(false);
        } catch (CADoesntExistsException e) {
            thrown = true;
        }
        assertTrue(thrown);

        log.trace("<test01AddUser()");
    }

    /**
     * tests creation of new user with unique serialnumber
     * 
     * @throws Exception
     *             error
     */
    @Test
    public void test02AddUserWithUniqueDNSerialnumber() throws Exception {
        log.trace(">test02AddUserWithUniqueDNSerialnumber()");

        // Make user that we know later...
        String thisusername = genRandomUserName();
        String email = thisusername + "@anatom.se";
        genRandomSerialnumber();
        userAdminSession.addUser(admin, thisusername, pwd, "C=SE, CN=" + thisusername + ", SN=" + serialnumber, "rfc822name=" + email, email, false,
                SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, caid);
        assertTrue("User " + thisusername + " was not added to the database.", userAdminSession.existsUser(admin, thisusername));
        usernames.add(thisusername);

        // Set the CA to enforce unique subjectDN serialnumber
        CAInfo cainfo = caSession.getCAInfo(admin, caid);
        boolean requiredUniqueSerialnumber = cainfo.isDoEnforceUniqueSubjectDNSerialnumber();
        cainfo.setDoEnforceUniqueSubjectDNSerialnumber(true);
        caAdminSession.editCA(admin, cainfo);

        // Add another user with the same serialnumber
        thisusername = genRandomUserName();
        try {
            userAdminSession.addUser(admin, thisusername, pwd, "C=SE, CN=" + thisusername + ", SN=" + serialnumber, "rfc822name=" + email, email, false,
                    SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, caid);
            usernames.add(thisusername);
        } catch (EjbcaException e) {
            assertEquals(ErrorCode.SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS, e.getErrorCode());
        }
        assertFalse(userAdminSession.existsUser(admin, thisusername));

        // Set the CA to NOT enforcing unique subjectDN serialnumber
        cainfo.setDoEnforceUniqueSubjectDNSerialnumber(false);
        caAdminSession.editCA(admin, cainfo);
        userAdminSession.addUser(admin, thisusername, pwd, "C=SE, CN=" + thisusername + ", SN=" + serialnumber, "rfc822name=" + email, email, false,
                SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, caid);
        assertTrue(userAdminSession.existsUser(admin, thisusername));
        usernames.add(thisusername);

        // Set the CA back to its original settings of enforcing unique
        // subjectDN serialnumber.
        cainfo.setDoEnforceUniqueSubjectDNSerialnumber(requiredUniqueSerialnumber);
        caAdminSession.editCA(admin, cainfo);

        log.trace("<test02AddUserWithUniqueDNSerialnumber()");
    }

    public void test03ChangeUserWithUniqueDNSerialnumber() throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile,
            WaitingForApprovalException, EjbcaException, CADoesntExistsException {
        log.trace(">test03ChangeUserWithUniqueDNSerialnumber()");

        // Make user that we know later...
        String thisusername;
        if (usernames.size() > 1) {
            thisusername = (String) usernames.get(1);
        } else {
            thisusername = username;
        }
        String email = thisusername + username + "@anatomanatom.se";

        CAInfo cainfo = caSession.getCAInfo(admin, caid);
        boolean requiredUniqueSerialnumber = cainfo.isDoEnforceUniqueSubjectDNSerialnumber();

        // Set the CA to enforce unique serialnumber
        cainfo.setDoEnforceUniqueSubjectDNSerialnumber(true);
        caAdminSession.editCA(admin, cainfo);
        try {
            userAdminSession.changeUser(admin, thisusername, pwd, "C=SE, CN=" + thisusername + ", SN=" + serialnumber, "rfc822name=" + email, email, false,
                    SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0,
                    UserDataConstants.STATUS_NEW, caid);
        } catch (EjbcaException e) {
            assertEquals(ErrorCode.SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS, e.getErrorCode());
        }
        assertTrue("The user '" + thisusername + "' was changed eventhough the serialnumber already exists.", userAdminSession.findUserByEmail(admin, email)
                .size() == 0);

        // Set the CA to NOT enforcing unique subjectDN serialnumber
        cainfo.setDoEnforceUniqueSubjectDNSerialnumber(false);
        caAdminSession.editCA(admin, cainfo);
        userAdminSession.changeUser(admin, thisusername, pwd, "C=SE, CN=" + thisusername + ", SN=" + serialnumber, "rfc822name=" + email, email, false,
                SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0,
                UserDataConstants.STATUS_NEW, caid);
        assertTrue("The user '" + thisusername + "' was not changed even though unique serialnumber is not enforced", userAdminSession.findUserByEmail(admin,
                email).size() > 0);

        // Set the CA back to its original settings of enforcing unique
        // subjectDN serialnumber.
        cainfo.setDoEnforceUniqueSubjectDNSerialnumber(requiredUniqueSerialnumber);
        caAdminSession.editCA(admin, cainfo);

        log.trace("<test03ChangeUserWithUniqueDNSerialnumber()");
    }

    /**
     * tests findUser and existsUser
     * 
     * @throws Exception
     *             error
     */
    public void test03FindUser() throws Exception {
        log.trace(">test03FindUser()");
        EndEntityInformation data = userAdminSession.findUser(admin, username);
        assertNotNull(data);
        assertEquals(username, data.getUsername());
        boolean exists = userAdminSession.existsUser(admin, username);
        assertTrue(exists);

        String notexistusername = genRandomUserName();
        exists = userAdminSession.existsUser(admin, notexistusername);
        assertFalse(exists);
        data = userAdminSession.findUser(admin, notexistusername);
        assertNull(data);
        log.trace("<test03FindUser()");
    }

    /**
     * tests query function
     * 
     * @throws Exception
     *             error
     */
    @Test
    public void test03_1QueryUser() throws Exception {
        log.trace(">test03_1QueryUser()");
        Query query = new Query(Query.TYPE_USERQUERY);
        query.add(UserMatch.MATCH_WITH_USERNAME, BasicMatch.MATCH_TYPE_EQUALS, username);
        String caauthstring = null;
        String eeprofilestr = null;
        Collection<EndEntityInformation> col = userAdminSession.query(admin, query, caauthstring, eeprofilestr,0);
        assertNotNull(col);
        assertEquals(1, col.size());
        log.trace("<test03_1QueryUser()");
    }

    /**
     * tests changeUser
     * 
     * @throws Exception
     *             error
     */
    @Test
    public void test04ChangeUser() throws Exception {
        log.trace(">test04ChangeUser()");
        EndEntityInformation data = userAdminSession.findUser(admin, username);
        assertNotNull(data);
        assertEquals(username, data.getUsername());
        assertNull(data.getCardNumber());
        assertEquals(pwd, data.getPassword()); // Note that changing the user
                                               // sets the password to null!!!
        assertEquals("CN=" + username + ",O=AnaTom,C=SE", data.getDN());
        String email = username + "@anatom.se";
        assertEquals("rfc822name=" + email, data.getSubjectAltName());
        data.setCardNumber("123456");
        data.setPassword("bar123");
        data.setDN("C=SE, O=AnaTom1, CN=" + username);
        data.setSubjectAltName("dnsName=a.b.se, rfc822name=" + email);

        userAdminSession.changeUser(admin, data, true);
        EndEntityInformation data1 = userAdminSession.findUser(admin, username);
        assertNotNull(data1);
        assertEquals(username, data1.getUsername());
        assertEquals("123456", data1.getCardNumber());
        assertEquals("bar123", data1.getPassword());
        assertEquals("CN=" + username + ",O=AnaTom1,C=SE", data1.getDN());
        assertEquals("dnsName=a.b.se, rfc822name=" + email, data1.getSubjectAltName());
        log.trace("<test04ChangeUser()");
    }

    public void test05RevokeCert() throws Exception {
    	KeyPair keypair = KeyTools.genKeys("512", "RSA");

        EndEntityInformation data1 = userAdminSession.findUser(admin, username);
        assertNotNull(data1);
        data1.setPassword("foo123");
        userAdminSession.changeUser(admin, data1, true);

    	Certificate cert = signSession.createCertificate(admin, username, "foo123", keypair.getPublic());
        CertificateStatus status = storeSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.NOT_REVOKED, status.revocationReason);
        // Revoke the certificate, put on hold        
        userAdminSession.revokeCert(admin, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert), RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
        status = storeSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, status.revocationReason);

        // Unrevoke the certificate        
        userAdminSession.revokeCert(admin, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert), RevokedCertInfo.NOT_REVOKED);
        status = storeSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.NOT_REVOKED, status.revocationReason);

        // Revoke again certificate        
        userAdminSession.revokeCert(admin, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert), RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
        status = storeSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, status.revocationReason);

        // Unrevoke the certificate, but with different code        
        userAdminSession.revokeCert(admin, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert), RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL);
        status = storeSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.NOT_REVOKED, status.revocationReason);

        // Revoke again certificate permanently        
        userAdminSession.revokeCert(admin, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert), RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE);
        status = storeSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE, status.revocationReason);

        // Unrevoke the certificate, should not work
        try {
        	userAdminSession.revokeCert(admin, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert), RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL);
            assertTrue(false); // should not reach this
        } catch (AlreadyRevokedException e) {}
        status = storeSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE, status.revocationReason);
    }

    /**
     * tests deletion of user, and user that does not exist
     * 
     * @throws Exception
     *             error
     */
    @Test
    public void test05DeleteUser() throws Exception {
        log.trace(">test05DeleteUser()");
        userAdminSession.deleteUser(admin, username);
        log.debug("deleted user: " + username);
        // Delete the the same user again
        boolean removed = false;
        try {
            userAdminSession.deleteUser(admin, username);
        } catch (NotFoundException e) {
            removed = true;
        }
        assertTrue("User does not exist does not throw NotFoundException", removed);
        log.trace("<test05DeleteUser()");
    }

    /**
     * tests deletion of user, and user that does not exist
     * 
     * @throws Exception
     *             error
     */
    @Test
    public void test06MergeWithWS() throws Exception {
        EndEntityProfile profile = new EndEntityProfile();
        profile.addField(DnComponents.COMMONNAME);
        profile.addField(DnComponents.DNEMAIL);
        profile.addField(DnComponents.ORGANIZATIONUNIT);
        profile.setUse(DnComponents.ORGANIZATIONUNIT, 0, true);
        profile.setValue(DnComponents.ORGANIZATIONUNIT, 0, "FooOrgUnit");
        profile.addField(DnComponents.ORGANIZATION);
        profile.addField(DnComponents.COUNTRY);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        profile.setAllowMergeDnWebServices(true);

        endEntityProfileSession.addEndEntityProfile(admin, "TESTMERGEWITHWS", profile);
        int profileId = endEntityProfileSession.getEndEntityProfileId(admin, "TESTMERGEWITHWS");

        EndEntityInformation addUser = new EndEntityInformation(username, "C=SE, O=AnaTom, CN=" + username, caid, null, null, UserDataConstants.STATUS_NEW, SecConst.USER_ENDUSER,
                profileId, SecConst.CERTPROFILE_FIXED_ENDUSER, new Date(), new Date(), SecConst.TOKEN_SOFT_P12, 0, null);
        addUser.setPassword("foo123");
        userAdminSession.addUserFromWS(admin, addUser, false);
        EndEntityInformation data = userAdminSession.findUser(admin, username);
        assertEquals("CN=" + username + ",OU=FooOrgUnit,O=AnaTom,C=SE", data.getDN());

        addUser.setDN("EMAIL=foo@bar.com, OU=hoho");
        endEntityProfileSession.changeEndEntityProfile(admin, "TESTMERGEWITHWS", profile);
        userAdminSession.changeUser(admin, addUser, false, true);
        data = userAdminSession.findUser(admin, username);
        // E=foo@bar.com,CN=430208,OU=FooOrgUnit,O=hoho,C=NO
        assertEquals("E=foo@bar.com,CN=" + username + ",OU=hoho,O=AnaTom,C=SE", data.getDN());
    }


}
