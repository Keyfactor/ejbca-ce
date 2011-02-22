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

package org.ejbca.core.model.ra;

import java.security.cert.Certificate;
import java.text.DateFormat;

import org.ejbca.core.model.approval.ApprovalNotificationParamGen;
import org.ejbca.util.CertTools;
import org.ejbca.util.dn.DNFieldExtractor;

/**
 * Variables used with userdata
 * ${USERNAME} or ${user.USERNAME} = The users username
 * ${PASSWORD} or ${user.PASSWORD} = The users password 
 * ${CN} or ${user.CN}             = The common name of the user.
 * ${SN} or ${user.SN}             = The serial number (in DN) of the user.
 * ${O} or ${user.O}               = The user's organization
 * ${OU} or ${user.OU}             = The user's organization unit
 * ${C} or ${user.C}               = The user's country
 * ${user.TIMECREATED}             = The time the user was created
 * ${user.TIMEMODIFIED}            = The time the user was modified          
 * 
 * Variables used with  expiring certificates. 
 * ${expiringCert.CERTSERIAL}      = The serial number of the certificate about to expire 
 * ${expiringCert.EXPIREDATE}      = The date the certificate will expire
 * ${expiringCert.CERTSUBJECTDN}   = The certificate subject dn
 * ${expiringCert.CERTISSUERDN}    = The certificate issuer dn
 * The variables ${CN}, ${SN}, ${O}, ${OU}, ${C} are also available.
 * 
 * @version $Id$
 */
public class UserNotificationParamGen extends ApprovalNotificationParamGen {

	public UserNotificationParamGen(UserDataVO userData) {
		populateWithUserData(userData);
	}

	public UserNotificationParamGen(UserDataVO userData, Certificate expiringCert) {
		populateWithUserData(userData);
		populateWithExpiringCert(expiringCert);
	}

	public UserNotificationParamGen(UserDataVO userData, String approvalAdminDN, UserDataVO admin) {
		populateWithUserData(userData);
		populateWithApprovalAdminDN(approvalAdminDN);
		populateWithEmailAddresses(userData, admin);
	}

	protected void populateWithExpiringCert(Certificate expiringCert) {
		if(expiringCert != null){
			paramPut("expiringCert.CERTSERIAL",CertTools.getSerialNumberAsString(expiringCert));
			String dateString = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(CertTools.getNotAfter(expiringCert));
			paramPut("expiringCert.EXPIREDATE",dateString);
			paramPut("expiringCert.CERTSUBJECTDN",CertTools.getSubjectDN(expiringCert));
			paramPut("expiringCert.CERTISSUERDN",CertTools.getIssuerDN(expiringCert));          
		}
	}

	protected void populateWithUserData(UserDataVO userData) {
		if (userData != null) {
			paramPut("USERNAME", userData.getUsername());
			paramPut("user.USERNAME", userData.getUsername());

			paramPut("PASSWORD", userData.getPassword());
			paramPut("user.PASSWORD", userData.getPassword());

			DNFieldExtractor dnfields = new DNFieldExtractor(userData.getDN(), DNFieldExtractor.TYPE_SUBJECTDN);
			paramPut("CN", dnfields.getField(DNFieldExtractor.CN, 0));
			paramPut("user.CN", dnfields.getField(DNFieldExtractor.CN, 0));
			paramPut("SN", dnfields.getField(DNFieldExtractor.SN, 0));
			paramPut("user.SN", dnfields.getField(DNFieldExtractor.SN, 0));
			paramPut("O", dnfields.getField(DNFieldExtractor.O, 0));
			paramPut("user.O", dnfields.getField(DNFieldExtractor.O, 0));
			paramPut("OU", dnfields.getField(DNFieldExtractor.OU, 0));
			paramPut("user.OU", dnfields.getField(DNFieldExtractor.OU, 0));
			paramPut("C", dnfields.getField(DNFieldExtractor.C, 0));
			paramPut("user.E", dnfields.getField(DNFieldExtractor.E, 0));

			String time = "(time not available)";
			if (userData.getTimeCreated() != null) {
				time = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(userData.getTimeCreated());
			}
			paramPut("user.TIMECREATED", time);
			time = "(time not available)";
			if (userData.getTimeModified() != null) {
				time = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(userData.getTimeModified());
			}
			paramPut("user.TIMEMODIFIED", time);
			
		}
	}
	
	protected void populateWithEmailAddresses(UserDataVO userdata, UserDataVO admin) {
		if(userdata != null) {
			paramPut("user.EE.EMAIL", userdata.getEmail());
			final DNFieldExtractor sanfields = new DNFieldExtractor(userdata.getSubjectAltName(), DNFieldExtractor.TYPE_SUBJECTALTNAME);
			paramPut("user.SAN.EMAIL", sanfields.getField(DNFieldExtractor.RFC822NAME, 0));
		}
		if(admin != null) {
			paramPut("requestAdmin.EE.EMAIL", admin.getEmail());
			final DNFieldExtractor sdnFields = new DNFieldExtractor(admin.getDN(), DNFieldExtractor.TYPE_SUBJECTDN);
			paramPut("requestAdmin.CN", sdnFields.getField(DNFieldExtractor.CN, 0));
			final DNFieldExtractor sanFields = new DNFieldExtractor(admin.getSubjectAltName(), DNFieldExtractor.TYPE_SUBJECTALTNAME);
			paramPut("requestAdmin.SAN.EMAIL", sanFields.getField(DNFieldExtractor.RFC822NAME, 0));
		}
	}
}
