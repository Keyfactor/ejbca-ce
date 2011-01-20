package org.ejbca.core.model.ra;

import java.util.Date;

import junit.framework.TestCase;

import org.ejbca.core.model.SecConst;

/** Tests some substitution variables for user notifications
 * @author Aveen Ismail
 * @version $Id$
 */
public class UserNotificationParamGenTest extends TestCase {

	public void setUp() throws Exception {
		super.setUp();		
	}
	
	public void testInterpolate(){
		Date now = new Date();
		int caid = 123;
		String approvalAdminDN = "CN=approvaluser,O=Org,C=SE";
		UserDataVO userdata = new UserDataVO("foo", "CN=foo,O=Org,C=SE", caid, "rfc822Name=fooalt@foo.se", "fooee@foo.se", UserDataConstants.STATUS_GENERATED, SecConst.USER_ENDUSER, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, now, null, SecConst.TOKEN_SOFT_P12, SecConst.NO_HARDTOKENISSUER, null);
		userdata.setPassword("foo123");
		UserDataVO admindata = new UserDataVO("admin", "CN=Test Admin,C=NO", caid, "rfc822Name=adminalt@foo.se", "adminee@foo.se", UserDataConstants.STATUS_GENERATED, SecConst.USER_ENDUSER, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, now, null, SecConst.TOKEN_SOFT_P12, SecConst.NO_HARDTOKENISSUER, null);
        UserNotificationParamGen paramGen = new UserNotificationParamGen(userdata, approvalAdminDN, admindata);
        assertNotNull("paramGen is null", paramGen);
        
        String msg = paramGen.interpolate("${USERNAME} ${user.USERNAME} ${PASSWORD} ${user.PASSWORD} ${CN} ${user.CN} ${C}" +
        						" ${approvalAdmin.CN} ${approvalAdmin.C} ${approvalAdmin.O}" +
        						" ${user.ee.email} ${user.san.email} ${requestAdmin.ee.email} ${requestAdmin.CN} ${requestAdmin.san.email}");
        assertFalse("Interpolating message failed", (msg==null || msg.length()==0));
        assertEquals("foo foo foo123 foo123 foo foo SE approvaluser SE Org fooee@foo.se fooalt@foo.se adminee@foo.se Test Admin adminalt@foo.se", msg);
		
	}
	

}
