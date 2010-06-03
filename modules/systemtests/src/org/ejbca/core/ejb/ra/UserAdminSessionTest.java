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

import java.rmi.ServerException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Random;

import javax.ejb.DuplicateKeyException;
import javax.transaction.TransactionRolledbackException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ErrorCode;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.util.TestTools;

/** Tests the UserData entity bean and some parts of UserAdminSession.
 *
 * @version $Id$
 */
public class UserAdminSessionTest extends TestCase {

    private static final Logger log = Logger.getLogger(UserAdminSessionTest.class);
    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
    private static final int caid = TestTools.getTestCAId();

    private static String username;
    private static String pwd;
    private static ArrayList usernames = new ArrayList();

    /**
     * Creates a new TestUserData object.
     *
     * @param name DOCUMENT ME!
     */
    public UserAdminSessionTest(String name) {
        super(name);
        assertTrue("Could not create TestCA.", TestTools.createTestCA());
    }

    protected void setUp() throws Exception {
    }

    protected void tearDown() throws Exception {
    }

    private String genRandomUserName() throws Exception {
        // Gen random user
        Random rand = new Random(new Date().getTime() + 4711);
        String username = "";
        for (int i = 0; i < 6; i++) {
            int randint = rand.nextInt(9);
            username += (new Integer(randint)).toString();
        }
        log.debug("Generated random username: username =" + username);

        return username;
    } // genRandomUserName

    private String genRandomPwd() throws Exception {
        // Gen random pwd
        Random rand = new Random(new Date().getTime() + 4812);
        String password = "";

        for (int i = 0; i < 8; i++) {
            int randint = rand.nextInt(9);
            password += (new Integer(randint)).toString();
        }

        log.debug("Generated random pwd: password=" + password);

        return password;
    } // genRandomPwd

    private String genRandomSerialnumber() throws Exception {
        // Gen random number
        Random rand = new Random(new Date().getTime() + 4913);
        String serialnumber = "";
        for (int i = 0; i < 8; i++) {
            int randint = rand.nextInt(9);
            serialnumber += (new Integer(randint)).toString();
        }
        log.debug("Generated random serialnumber: serialnumber =" + serialnumber);

        return serialnumber;
    } // genRandomSerialnumber

    /**
     * tests creation of new user and duplicate user
     *
     * @throws Exception error
     */
    public void test01AddUser() throws Exception {
        log.trace(">test01AddUser()");

        // Make user that we know later...
        username = genRandomUserName();
        pwd = genRandomPwd();
        String email = username + "@anatom.se";
        TestTools.getUserAdminSession().addUser(admin, username, pwd, "C=SE, O=AnaTom, CN=" + username, "rfc822name=" + email, email, false, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, caid);
        log.debug("created user: " + username + ", " + pwd + ", C=SE, O=AnaTom, CN=" + username);
        // Add the same user again
        boolean userexists = false;
        try {
            TestTools.getUserAdminSession().addUser(admin, username, pwd, "C=SE, O=AnaTom, CN=" + username, "rfc822name=" + email, email, false, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, caid);
        } catch (DuplicateKeyException e) {
            // This is what we want
            userexists = true;
        } catch (TransactionRolledbackException e) {
        	// weblogic throws transactionrolledbackexception instead wrapping the duplicatekey ex
        	if (e.getCause() instanceof DuplicateKeyException) {
                userexists = true;
			}
        } catch (ServerException e) {
        	// glassfish throws serverexception, can you believe this?
        	userexists = true;
        }
        assertTrue("User already exist does not throw DuplicateKeyException", userexists);

        log.trace("<test01AddUser()");
    }

    
    /**
     * tests creation of new user with unique serialnumber
     *
     * @throws Exception error
     */
    public void test02AddUserWithUniqueDNSerialnumber() throws Exception {
        log.trace(">test02AddUserWithUniqueDNSerialnumber()");

        // Make user that we know later...
        String thisusername = genRandomUserName();
        pwd = genRandomPwd();
        String email = username + "@anatom.se";
        String serialnumber = genRandomSerialnumber();
        TestTools.getUserAdminSession().addUser(admin, thisusername, pwd, "C=SE, CN=" + thisusername + ", SN=" + serialnumber, "rfc822name=" + email, email, false, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, caid);
        if(TestTools.getUserAdminSession().existsUser(admin, thisusername)){
        		usernames.add(thisusername);
                log.debug("Failed to create user: " + thisusername + ", " + pwd + ", C=SE, CN=" + thisusername + ", SN=" + serialnumber);
        } else {
            log.debug("created user: " + thisusername + ", " + pwd + ", C=SE, CN=" + thisusername + ", SN=" + serialnumber);
        }
        
        //Set the CA to enforce unique subjectDN serialnumber
        CAInfo cainfo = TestTools.getCAAdminSession().getCA(admin, caid).getCAInfo();
        boolean requiredUniqueSerialnumber = cainfo.isDoEnforceUniqueSubjectDNSerialnumber();
        cainfo.setDoEnforceUniqueSubjectDNSerialnumber(true);
        TestTools.getCAAdminSession().editCA(admin, cainfo);
               
        // Add another user with the same serialnumber
        boolean uniqueserialnumber = false;
        thisusername = genRandomUserName();
        try {
        	TestTools.getUserAdminSession().addUser(admin, thisusername, pwd, "C=SE, CN=" + thisusername + ", SN=" + serialnumber, "rfc822name=" + email, email, false, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, caid);
            if(TestTools.getUserAdminSession().existsUser(admin, thisusername)){
            	usernames.add(thisusername);
                log.debug("Failed to create user: " + thisusername + ", " + pwd + ", C=SE, CN=" + thisusername + ", SN=" + serialnumber);
            } else {
                log.debug("Created user: " + thisusername + ", " + pwd + ", C=SE, CN=" + thisusername + ", SN=" + serialnumber);
            }
        } catch (EjbcaException e){
        	//This is what we want
        	if(e.getErrorCode().equals(ErrorCode.SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS)){
        		uniqueserialnumber = true;
        	}
        }
        
        //Set the CA back to its original settings of enforcing unique subjectDN serialnumber
		cainfo.setDoEnforceUniqueSubjectDNSerialnumber(requiredUniqueSerialnumber);
		TestTools.getCAAdminSession().editCA(admin, cainfo);
		
        assertTrue("User with the same SubjectDN serialnumber already exist does not throw EjbcaException with the ErrorCode: " + ErrorCode.SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS, uniqueserialnumber);
        
		TestTools.getUserAdminSession().addUser(admin, thisusername, pwd, "C=SE, CN=" + thisusername + ", SN=" + serialnumber, "rfc822name=" + email, email, false, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, caid);	
		assertTrue("User was not added eventhough the CA does not enforce unique SubjectDN Serialnumber.", TestTools.getUserAdminSession().existsUser(admin, thisusername));
		usernames.add(thisusername);

        log.trace("<test02AddUserWithUniqueDNSerialnumber()");
    }    
    
    
    
    
    
    
    
    
    
    
    
    
    /**
     * tests deletion of user, and user that does not exist
     *
     * @throws Exception error
     */
    public void test02DeleteUser() throws Exception {
        log.trace(">test01DeleteUser()");

        TestTools.getUserAdminSession().deleteUser(admin, username);
        log.debug("deleted user: " + username);
        // Delete the the same user again
        boolean removed = false;
        try {
            TestTools.getUserAdminSession().deleteUser(admin, username);
        } catch (NotFoundException e) {
            removed = true;
        }
        assertTrue("User does not exist does not throw NotFoundException", removed);

        log.trace("<test01DeleteUser()");
    }

	public void test99RemoveTestCA() throws Exception {
		for(int i=0; i<usernames.size(); i++){
			TestTools.getUserAdminSession().deleteUser(admin, (String) usernames.get(i));
		}
		TestTools.removeTestCA();
	}
}
