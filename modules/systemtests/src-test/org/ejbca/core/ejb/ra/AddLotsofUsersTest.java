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

import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.UserAdminConstants;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.util.InterfaceCache;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests the UserData entity bean and some parts of UserAdminSession.
 *
 * @version $Id$
 */
public class AddLotsofUsersTest extends CaTestCase {

	private static final Logger log = Logger.getLogger(AddLotsofUsersTest.class);

    private int userNo = 0;
    
    private EndEntityAccessSessionRemote endEntityAccessSession = JndiHelper.getRemoteSession(EndEntityAccessSessionRemote.class);
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();

    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    public String getRoleName() {
        return "AddLotsofUsersTest"; 
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
    @Test
    public void test01Create2000Users() throws Exception {
        log.trace(">test01Create2000Users()");
        final AuthenticationToken administrator = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("AddLotsofUsersTest"));
        final String baseUsername = "lotsausers" + System.currentTimeMillis() + "-";
        for (int i = 0; i < 2000; i++) {
            String username = genUserName(baseUsername);
            String pwd = genRandomPwd();
            int type = SecConst.USER_ENDUSER;
            int token = SecConst.TOKEN_SOFT_P12;
            int profileid = SecConst.EMPTY_ENDENTITYPROFILE;
            int certificatetypeid = CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER;
            int hardtokenissuerid = SecConst.NO_HARDTOKENISSUER;
            String dn = "C=SE, O=AnaTom, CN=" + username;
            String subjectaltname = "rfc822Name=" + username + "@foo.se";
            String email = username + "@foo.se";
            if (endEntityAccessSession.findUser(administrator, username) != null) {
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
    
    @Test
    public void test02FindAllBatchUsersByStatusWithLimit() {
        log.trace(">test02FindAllBatchUsersByStatusWithLimit()");
    	List<EndEntityInformation> userDataVOs = userAdminSession.findAllBatchUsersByStatusWithLimit(UserDataConstants.STATUS_NEW);
    	assertEquals("Did not returned the maximum hardcoded limit in query.", UserAdminConstants.MAXIMUM_QUERY_ROWCOUNT, userDataVOs.size());
        log.trace("<test02FindAllBatchUsersByStatusWithLimit()");
    }
}
