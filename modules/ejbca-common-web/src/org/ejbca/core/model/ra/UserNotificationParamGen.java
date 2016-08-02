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
import java.util.Date;

import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.util.CertTools;
import org.ejbca.util.NotificationParamGen;

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
 * ${requestAdmin.CN}              = The common name of the requesting administrator.
 * ${requestAdmin.EE.EMAIL}        = The email address of the administrator adding the end entity according to the administrator's End Entity data.
 * ${requestAdmin.SAN.EMAIL}       = The email address of the administrator adding the end entity according to the administrator's Subject Alternative Name, RFC822Name field.
 *
 * Variables used with  expiring certificates. 
 * ${expiringCert.CERTSERIAL}      = The serial number of the certificate about to expire 
 * ${expiringCert.EXPIREDATE}      = The date the certificate will expire
 * ${expiringCert.CERTSUBJECTDN}   = The certificate subject dn
 * ${expiringCert.CERTISSUERDN}    = The certificate issuer dn
 * The variables ${CN}, ${SN}, ${O}, ${OU}, ${C} are also available.
 * 
 * Variable used with notification where approval is involved in the state change (approvalAdmin = last admin to approve).
 * ${approvalAdmin.USERNAME}          = The approving administrator's username
 * ${approvalAdmin.CN}                = The common name of the approving administrator.
 * ${approvalAdmin.SN}                = The common name of the approving administrator.
 * ${approvalAdmin.O}                 = The approving administrator's organization
 * ${approvalAdmin.OU}                = The approving administrator's organization unit
 * ${approvalAdmin.C}                 = The approving administrator's country
 * ${approvalRequestId}               = The id of the approval request
 * 
 * @version $Id$
 */
public class UserNotificationParamGen extends NotificationParamGen {

	public UserNotificationParamGen(EndEntityInformation userData) {
		populateWithUserData(userData);
	}

	public UserNotificationParamGen(EndEntityInformation userData, Certificate expiringCert) {
		populateWithUserData(userData);
		populateWithExpiringCert(expiringCert);
	}

	/** Notification parameter generation when notifying about end entity events (new, generated, revoked etc).
	 * 
	 * @param userData The end entity that is being operated on. Populates USERNAME, CN etc variables
	 * @param approvalAdminDN The DN of the administrator that approved the request, if approvals were used. Populates approvalAdmin variables.
	 * @param requestAdmin The end entity that requested the event from the beginning, either the admin that adds an end entity if no approvals 
	 *         are used, of if approvals were used the admin requesting (creating the approval request) to add an end entity. Populates requestAdmin variables
	 * @param approvalRequestId
	 * @param revokedCertificate the certificate that is revoked, in case of a revocation event. Populates revokedCertificate variables
	 */
	public UserNotificationParamGen(EndEntityInformation userData, String approvalAdminDN, EndEntityInformation requestAdmin, int approvalRequestId, 
	        CertificateDataWrapper revokedCertificate) {
		populateWithUserData(userData);
		populateWithApprovalData(approvalAdminDN, approvalRequestId);
		populateWithEmailAddresses(userData, requestAdmin);
		populateWithRevokedCertificate(revokedCertificate);
	}

	private void populateWithApprovalData(String approvalAdminDN, final int approvalRequestId) {
	    if (approvalAdminDN == null) {
	        approvalAdminDN = "";
	    }
	    DNFieldExtractor dnfields = new DNFieldExtractor(approvalAdminDN, DNFieldExtractor.TYPE_SUBJECTDN);       
	    paramPut("approvalAdmin.CN", dnfields.getField(DNFieldExtractor.CN, 0));          
	    paramPut("approvalAdmin.SN", dnfields.getField(DNFieldExtractor.SN, 0));
	    paramPut("approvalAdmin.O", dnfields.getField(DNFieldExtractor.O, 0));
	    paramPut("approvalAdmin.OU", dnfields.getField(DNFieldExtractor.OU, 0));
	    paramPut("approvalAdmin.C", dnfields.getField(DNFieldExtractor.C, 0));
	    paramPut("approvalAdmin.E", dnfields.getField(DNFieldExtractor.E, 0));
	    
	    paramPut("approvalRequestId", approvalRequestId);
	}

	protected void populateWithRevokedCertificate(final CertificateDataWrapper revokedCertificate) {
	    if (revokedCertificate!=null) {
	        final CertificateData certificateData = revokedCertificate.getCertificateData();
	        if (certificateData != null) {
	            paramPut("revokedCertificate.CERTSERIAL", certificateData.getSerialNumberHex());
	            paramPut("revokedCertificate.EXPIREDATE", fastDateFormat(new Date(certificateData.getExpireDate())));
	            paramPut("revokedCertificate.CERTSUBJECTDN", certificateData.getSubjectDN());
	            paramPut("revokedCertificate.CERTISSUERDN", certificateData.getIssuerDN());
	            String newStatus = "Unknown";
	            switch (certificateData.getStatus()) {
	            case CertificateConstants.CERT_ACTIVE:
                case CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION:
                    newStatus = "Active";
                    break;
                case CertificateConstants.CERT_REVOKED:
                case CertificateConstants.CERT_ARCHIVED:
                    newStatus = "Revoked";
                    break;
	            }
                String newRevocationReason = "";
                // Use plain RFC5280 CRLReason naming until we localize this
                switch (RevocationReasons.getFromDatabaseValue(certificateData.getRevocationReason())) {
                case UNSPECIFIED: newRevocationReason = "unspecified"; break;
                case KEYCOMPROMISE: newRevocationReason = "keyCompromise"; break;
                case CACOMPROMISE: newRevocationReason = "cACompromise"; break;
                case AFFILIATIONCHANGED: newRevocationReason = "affiliationChanged"; break;
                case SUPERSEDED: newRevocationReason = "superseded"; break;
                case CESSATIONOFOPERATION: newRevocationReason = "cessationOfOperation"; break;
                case CERTIFICATEHOLD: newRevocationReason = "certificateHold"; break;
                case REMOVEFROMCRL: newRevocationReason = "removeFromCRL"; break;
                case PRIVILEGESWITHDRAWN: newRevocationReason = "privilegeWithdrawn"; break;
                case AACOMPROMISE: newRevocationReason = "aACompromise"; break;
                default: break;
                }
                paramPut("revokedCertificate.REVOCATIONSTATUS", newStatus);
                paramPut("revokedCertificate.REVOCATIONREASON", newRevocationReason);
	        }
	    }
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
	
	protected void populateWithEmailAddresses(EndEntityInformation userdata, EndEntityInformation requestAdmin) {
		if(userdata != null) {
			paramPut("user.EE.EMAIL", userdata.getEmail());
			final DNFieldExtractor sanfields = new DNFieldExtractor(userdata.getSubjectAltName(), DNFieldExtractor.TYPE_SUBJECTALTNAME);
			paramPut("user.SAN.EMAIL", sanfields.getField(DNFieldExtractor.RFC822NAME, 0));
		}
		if(requestAdmin != null) {
			paramPut("requestAdmin.EE.EMAIL", requestAdmin.getEmail());
			final DNFieldExtractor sdnFields = new DNFieldExtractor(requestAdmin.getDN(), DNFieldExtractor.TYPE_SUBJECTDN);
			paramPut("requestAdmin.CN", sdnFields.getField(DNFieldExtractor.CN, 0));
			final DNFieldExtractor sanFields = new DNFieldExtractor(requestAdmin.getSubjectAltName(), DNFieldExtractor.TYPE_SUBJECTALTNAME);
			paramPut("requestAdmin.SAN.EMAIL", sanFields.getField(DNFieldExtractor.RFC822NAME, 0));
		}
	}
}
