/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.approval.ApprovalNotificationParamGen;

/**
 * Variables used with userdata
 * ${USERNAME} or ${user.USERNAME} = The users username
 * ${PASSWORD} or ${user.PASSWORD} = The users password 
 * ${UID} or ${user.UID}           = The user's unique identifier
 * ${CN} or ${user.CN}             = The common name of the user.
 * ${SN} or ${user.SN}             = The serial number (in DN) of the user.
 * ${O} or ${user.O}               = The user's organization
 * ${OU} or ${user.OU}             = The user's organization unit
 * ${C} or ${user.C}               = The user's country
 * ${user.E}                       = The user's email address from Subject DN
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

	public UserNotificationParamGen(EndEntityInformation userData) {
		populateWithUserData(userData);
	}

	public UserNotificationParamGen(EndEntityInformation userData, Certificate expiringCert) {
		populateWithUserData(userData);
		populateWithExpiringCert(expiringCert);
	}

	public UserNotificationParamGen(EndEntityInformation userData, String approvalAdminDN, EndEntityInformation admin) {
		populateWithUserData(userData);
		populateWithApprovalAdminDN(approvalAdminDN);
		populateWithEmailAddresses(userData, admin);
	}

	protected void populateWithExpiringCert(Certificate expiringCert) {
		if(expiringCert != null){
			paramPut("expiringCert.CERTSERIAL",CertTools.getSerialNumberAsString(expiringCert));
			paramPut("expiringCert.EXPIREDATE", fastDateFormat(CertTools.getNotAfter(expiringCert)));
			paramPut("expiringCert.CERTSUBJECTDN",CertTools.getSubjectDN(expiringCert));
			paramPut("expiringCert.CERTISSUERDN",CertTools.getIssuerDN(expiringCert));          
		}
	}

	protected void populateWithUserData(EndEntityInformation userData) {
		if (userData != null) {
			paramPut("USERNAME", userData.getUsername());
			paramPut("user.USERNAME", userData.getUsername());

			paramPut("PASSWORD", userData.getPassword());
			paramPut("user.PASSWORD", userData.getPassword());

			DNFieldExtractor dnfields = new DNFieldExtractor(userData.getDN(), DNFieldExtractor.TYPE_SUBJECTDN);
			paramPut("UID", dnfields.getField(DNFieldExtractor.UID, 0));
			paramPut("user.UID", dnfields.getField(DNFieldExtractor.UID, 0));
			paramPut("CN", dnfields.getField(DNFieldExtractor.CN, 0));
			paramPut("user.CN", dnfields.getField(DNFieldExtractor.CN, 0));
			paramPut("SN", dnfields.getField(DNFieldExtractor.SN, 0));
			paramPut("user.SN", dnfields.getField(DNFieldExtractor.SN, 0));
			paramPut("O", dnfields.getField(DNFieldExtractor.O, 0));
			paramPut("user.O", dnfields.getField(DNFieldExtractor.O, 0));
			paramPut("OU", dnfields.getField(DNFieldExtractor.OU, 0));
			paramPut("user.OU", dnfields.getField(DNFieldExtractor.OU, 0));
			paramPut("C", dnfields.getField(DNFieldExtractor.C, 0));
			paramPut("user.C", dnfields.getField(DNFieldExtractor.C, 0));
			paramPut("user.E", dnfields.getField(DNFieldExtractor.E, 0));

			String time = "(time not available)";
			if (userData.getTimeCreated() != null) {
				time = fastDateFormat(userData.getTimeCreated());
			}
			paramPut("user.TIMECREATED", time);
			time = "(time not available)";
			if (userData.getTimeModified() != null) {
				time = fastDateFormat(userData.getTimeModified());
			}
			paramPut("user.TIMEMODIFIED", time);
			
		}
	}
	
	protected void populateWithEmailAddresses(EndEntityInformation userdata, EndEntityInformation admin) {
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
