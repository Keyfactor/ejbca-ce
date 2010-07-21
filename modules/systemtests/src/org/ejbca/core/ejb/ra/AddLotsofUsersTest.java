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

import javax.ejb.EJB;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.CertTools;

/**
 * Tests the UserData entity bean and some parts of UserAdminSession.
 *
 * @version $Id$
 */
public class AddLotsofUsersTest extends CaTestCase {

	private static final Logger log = Logger.getLogger(AddLotsofUsersTest.class);

    private int userNo = 0;
    
    @EJB
    private UserAdminSessionRemote userAdminSession;

    /**
     * Creates a new TestAddLotsofUsers object.
     */
    public AddLotsofUsersTest(String name) {
        super(name);
    }

    public void setUp() throws Exception {
        createTestCA();
    }

    public void tearDown() throws Exception {
        removeTestCA();
    }

    /**
     * Generate a new user name
     */
    private String genUserName(String baseUsername) throws Exception {
        userNo++;
        return baseUsername + userNo;
    }

    /**
     * Tests creation of 2000 users
     *
     * @throws Exception error
     */
    public void test01Create2000Users() throws Exception {
        log.trace(">test01Create2000Users()");
        final Admin administrator = new Admin(Admin.TYPE_INTERNALUSER);
        final String baseUsername = "lotsausers" + System.currentTimeMillis() + "-";
        for (int i = 0; i < 2000; i++) {
            String username = genUserName(baseUsername);
            String pwd = genRandomPwd();
            int type = SecConst.USER_ENDUSER;
            int token = SecConst.TOKEN_SOFT_P12;
            int profileid = SecConst.EMPTY_ENDENTITYPROFILE;
            int certificatetypeid = SecConst.CERTPROFILE_FIXED_ENDUSER;
            int hardtokenissuerid = SecConst.NO_HARDTOKENISSUER;
            String dn = "C=SE, O=AnaTom, CN=" + username;
            String subjectaltname = "rfc822Name=" + username + "@foo.se";
            String email = username + "@foo.se";
            if (userAdminSession.findUser(administrator, username) != null) {
                log.warn("User already exists in the database.");
            } else {
            	userAdminSession.addUser(administrator, username, pwd, CertTools.stringToBCDNString(dn), subjectaltname, email, false, profileid, certificatetypeid,
                        type, token, hardtokenissuerid, getTestCAId());
            }
            userAdminSession.setClearTextPassword(administrator, username, pwd);
            if (i % 100 == 0) {
                log.debug("Created " + i + " users...");
            }
        }
        log.debug("Created 2000 users!");
        log.trace("<test01Create2000Users()");
    }
}
