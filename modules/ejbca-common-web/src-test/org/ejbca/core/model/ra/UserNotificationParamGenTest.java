package org.ejbca.core.model.ra;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.util.Date;

import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.ejbca.core.model.SecConst;
import org.junit.Test;

/** Tests some substitution variables for user notifications
 * @version $Id$
 */
public class UserNotificationParamGenTest {

	@Test
	public void testInterpolate(){
		Date now = new Date();
		int caid = 123;
		String approvalAdminDN = "CN=approvaluser,O=Org,C=SE";
		EndEntityInformation userdata =
		        new EndEntityInformation("foo", "CN=foo,O=Org,C=SE", caid, 
		                                 "rfc822Name=fooalt@foo.se", "fooee@foo.se", 
		                                 EndEntityConstants.STATUS_GENERATED, 
		                                 new EndEntityType(EndEntityTypes.ENDUSER), 
		                                 SecConst.EMPTY_ENDENTITYPROFILE, 
		                                 CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, 
		                                 now, null, SecConst.TOKEN_SOFT_P12, SecConst.NO_HARDTOKENISSUER, null);
		userdata.setPassword("foo123");
		EndEntityInformation admindata =
		        new EndEntityInformation("admin", "CN=Test Admin,C=NO", caid, 
		                                 "rfc822Name=adminalt@foo.se", "adminee@foo.se",
		                                 EndEntityConstants.STATUS_GENERATED, 
		                                 new EndEntityType(EndEntityTypes.ENDUSER), 
		                                 SecConst.EMPTY_ENDENTITYPROFILE, 
		                                 CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, 
		                                 now, null, SecConst.TOKEN_SOFT_P12, 
		                                 SecConst.NO_HARDTOKENISSUER, null);
        UserNotificationParamGen paramGen = new UserNotificationParamGen(userdata, approvalAdminDN, admindata);
        assertNotNull("paramGen is null", paramGen);
        
        String msg = paramGen.interpolate("${USERNAME} ${user.USERNAME} ${PASSWORD} ${user.PASSWORD} ${CN} ${user.CN} ${C}" +
        						" ${approvalAdmin.CN} ${approvalAdmin.C} ${approvalAdmin.O}" +
        						" ${user.EE.EMAIL} ${user.SAN.EMAIL} ${requestAdmin.EE.EMAIL} ${requestAdmin.CN} ${requestAdmin.SAN.EMAIL}");
        assertFalse("Interpolating message failed", (msg==null || msg.length()==0));
        assertEquals("foo foo foo123 foo123 foo foo SE approvaluser SE Org fooee@foo.se fooalt@foo.se adminee@foo.se Test Admin adminalt@foo.se", msg);
		
	}
	

}
