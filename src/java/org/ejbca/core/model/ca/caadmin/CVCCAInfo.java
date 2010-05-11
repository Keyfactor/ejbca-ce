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

package org.ejbca.core.model.ca.caadmin;

import java.util.Collection;
import java.util.Date;

import org.ejbca.core.model.ca.catoken.CATokenInfo;
import org.ejbca.util.CertTools;
import org.ejbca.util.StringTools;


/**
 * Holds non-sensitive information about a CVC CA (Card Verifiable Certificate).
 *
 * @version $Id$
 */
public class CVCCAInfo extends CAInfo {

	private static final long serialVersionUID = 2L;

	/**
	 * Constructor that should be used when creating CA and retrieving CA info.
	 */
	public CVCCAInfo(String subjectdn, String name, int status, Date updateTime, int certificateprofileid, 
			long validity, Date expiretime, int catype, int signedby, Collection certificatechain, 
			CATokenInfo catokeninfo, String description, int revokationreason, Date revokationdate,
			long crlperiod, long crlIssueInterval, long crlOverlapTime, long deltacrlperiod, 
			Collection crlpublishers,boolean finishuser,Collection extendedcaserviceinfos, 
			Collection approvalSettings, int numOfReqApprovals,
			boolean includeInHealthCheck, boolean _doEnforceUniquePublicKeys,
			boolean _doEnforceUniqueDistinguishedName) {
		this.subjectdn = CertTools.stringToBCDNString(StringTools.strip(subjectdn));
		this.caid = this.subjectdn.hashCode();
		this.name = name;
		this.status = status;
		this.updatetime = updateTime;
		this.validity = validity;
		this.expiretime = expiretime;
		this.catype = catype;
		this.signedby = signedby;
        this.certificatechain = certificatechain;	
		this.catokeninfo = catokeninfo; 
		this.description = description;
		this.revokationreason = revokationreason;
		this.revokationdate = revokationdate;
		this.crlperiod = crlperiod;
		this.crlIssueInterval = crlIssueInterval;
		this.crlOverlapTime = crlOverlapTime;
		this.deltacrlperiod = deltacrlperiod;
		this.crlpublishers = crlpublishers;
		this.finishuser = finishuser;                     
		this.certificateprofileid = certificateprofileid;
		this.extendedcaserviceinfos = extendedcaserviceinfos; 
		this.approvalSettings = approvalSettings;
		this.numOfReqApprovals = numOfReqApprovals;
		this.includeInHealthCheck = includeInHealthCheck;
		this.doEnforceUniquePublicKeys = _doEnforceUniquePublicKeys;
		this.doEnforceUniqueDistinguishedName = _doEnforceUniqueDistinguishedName;
	}

	/**
	 * Constructor that should be used when updating CA data.
     * Used by the web. Jsp and stuff like that.
	 */
	public CVCCAInfo(int caid, long validity, CATokenInfo catokeninfo, String description,
			long crlperiod, long crlIssueInterval, long crlOverlapTime, long deltacrlperiod, 
			Collection crlpublishers,
			boolean finishuser, Collection extendedcaserviceinfos, 
			Collection approvalSettings, int numOfReqApprovals,
			boolean includeInHealthCheck, boolean _doEnforceUniquePublicKeys,
			boolean _doEnforceUniqueDistinguishedName) {        
		this.caid = caid;
		this.validity=validity;
		this.catokeninfo = catokeninfo; 
		this.description = description;    
		this.crlperiod = crlperiod;
		this.crlIssueInterval = crlIssueInterval;
		this.crlOverlapTime = crlOverlapTime;
		this.deltacrlperiod = deltacrlperiod;
		this.crlpublishers = crlpublishers;
		this.finishuser = finishuser;
		this.extendedcaserviceinfos = extendedcaserviceinfos; 
		this.approvalSettings = approvalSettings;
		this.numOfReqApprovals = numOfReqApprovals;
		this.includeInHealthCheck = includeInHealthCheck;
		this.doEnforceUniquePublicKeys = _doEnforceUniquePublicKeys;
		this.doEnforceUniqueDistinguishedName = _doEnforceUniqueDistinguishedName;
	}  


	public CVCCAInfo(){}

}
