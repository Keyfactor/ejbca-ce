/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.certificates.ca;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.util.CertTools;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.StringTools;


/**
 * Holds non-sensitive information about a CVC CA (Card Verifiable Certificate).
 *
 * @version $Id$
 */
public class CVCCAInfo extends CAInfo {

	private static final long serialVersionUID = 2L;

    /**
     * This constructor can be used when creating a CA.
     * This constructor uses defaults for the fields that are not specified.
     * */
    public CVCCAInfo(String subjectdn, String name, int status, int certificateprofileid, String encodedValidity, int signedby, Collection<Certificate> certificatechain, CAToken catoken) {
        this(subjectdn, name, status, new Date(), certificateprofileid,
                encodedValidity, null, // expire time
                CAInfo.CATYPE_CVC, signedby,
                certificatechain, // Certificate chain
                catoken, // CA token
                "", // Description
                -1, // Revocation reason
                null, // Revocation date
                24 * SimpleTime.MILLISECONDS_PER_HOUR, // CRL period
                0 * SimpleTime.MILLISECONDS_PER_HOUR, // CRL issue interval
                10 * SimpleTime.MILLISECONDS_PER_HOUR, // CRL overlap time
                10 * SimpleTime.MILLISECONDS_PER_HOUR, // Delta CRL period
                new ArrayList<Integer>(), // CRL publishers
                new ArrayList<Integer>(), // Key validators
                true, // Finish user
                new ArrayList<ExtendedCAServiceInfo>(), // Extended CA services
                new HashMap<ApprovalRequestType, Integer>(),
                true, // includeInHealthCheck 
                true, // isDoEnforceUniquePublicKeys
                true, // isDoEnforceUniqueDistinguishedName
                false, // isDoEnforceUniqueSubjectDNSerialnumber
                false, // useCertReqHistory
                true, // useUserStorage
                true // useCertificateStorage
            );
    }

	/**
	 * Constructor that should be used when creating CA and retrieving CA info.
	 * Please use the shorter form if you do not need to set all of the values.
	 */
	public CVCCAInfo(String subjectdn, String name, int status, Date updateTime, int certificateprofileid, 
			String encodedValidity, Date expiretime, int catype, int signedby, Collection<Certificate> certificatechain, 
			CAToken catoken, String description, int revocationReason, Date revocationDate,
			long crlperiod, long crlIssueInterval, long crlOverlapTime, long deltacrlperiod, 
			Collection<Integer> crlpublishers, Collection<Integer> keyValidators, 
			boolean finishuser,Collection<ExtendedCAServiceInfo> extendedcaserviceinfos, 
			Map<ApprovalRequestType, Integer> approvals,
			boolean includeInHealthCheck, boolean _doEnforceUniquePublicKeys,
			boolean _doEnforceUniqueDistinguishedName, boolean _doEnforceUniqueSubjectDNSerialnumber,
			boolean _useCertReqHistory, boolean _useUserStorage, boolean _useCertificateStorage) {
		this.subjectdn = CertTools.stringToBCDNString(StringTools.strip(subjectdn));
		this.caid = CertTools.stringToBCDNString(this.subjectdn).hashCode();
		this.name = name;
		this.status = status;
		this.updatetime = updateTime;
		setEncodedValidity(encodedValidity);
		this.expiretime = expiretime;
		this.catype = catype;
		this.signedby = signedby;
		setCertificateChain(certificatechain);
		this.catoken = catoken; 
		this.description = description;
		this.revocationReason = revocationReason;
		this.revocationDate = revocationDate;
		this.crlperiod = crlperiod;
		this.crlIssueInterval = crlIssueInterval;
		this.crlOverlapTime = crlOverlapTime;
		this.deltacrlperiod = deltacrlperiod;
		this.crlpublishers = crlpublishers;
		this.validators = keyValidators;
		this.finishuser = finishuser;                     
		this.certificateprofileid = certificateprofileid;
		this.extendedcaserviceinfos = extendedcaserviceinfos; 
		setApprovals(approvals);
		this.includeInHealthCheck = includeInHealthCheck;
		this.doEnforceUniquePublicKeys = _doEnforceUniquePublicKeys;
		this.doEnforceUniqueDistinguishedName = _doEnforceUniqueDistinguishedName;
		this.doEnforceUniqueSubjectDNSerialnumber = _doEnforceUniqueSubjectDNSerialnumber;
		this.useCertReqHistory = _useCertReqHistory;
        this.useUserStorage = _useUserStorage;
        this.useCertificateStorage = _useCertificateStorage;
	}

	/**
	 * Constructor that should be used when updating CA data.
     * Used by the web. Jsp and stuff like that.
	 */
	public CVCCAInfo(int caid, String encodedValidity, CAToken catoken, String description,
			long crlperiod, long crlIssueInterval, long crlOverlapTime, long deltacrlperiod, 
			Collection<Integer> crlpublishers, Collection<Integer> keyValidators,
			boolean finishuser, Collection<ExtendedCAServiceInfo> extendedcaserviceinfos, 
			Map<ApprovalRequestType, Integer> approvals,
			boolean includeInHealthCheck, boolean _doEnforceUniquePublicKeys,
			boolean _doEnforceUniqueDistinguishedName, boolean _doEnforceUniqueSubjectDNSerialnumber,
			boolean _useCertReqHistory, boolean _useUserStorage, boolean _useCertificateStorage) {        
		this.caid = caid;
		setEncodedValidity(encodedValidity);
		this.catoken = catoken;
		this.description = description;    
		this.crlperiod = crlperiod;
		this.crlIssueInterval = crlIssueInterval;
		this.crlOverlapTime = crlOverlapTime;
		this.deltacrlperiod = deltacrlperiod;
		this.crlpublishers = crlpublishers;
		this.validators = keyValidators;
		this.finishuser = finishuser;
		this.extendedcaserviceinfos = extendedcaserviceinfos; 
		setApprovals(approvals);
		this.includeInHealthCheck = includeInHealthCheck;
		this.doEnforceUniquePublicKeys = _doEnforceUniquePublicKeys;
		this.doEnforceUniqueDistinguishedName = _doEnforceUniqueDistinguishedName;
		this.doEnforceUniqueSubjectDNSerialnumber = _doEnforceUniqueSubjectDNSerialnumber;
		this.useCertReqHistory = _useCertReqHistory;
        this.useUserStorage = _useUserStorage;
        this.useCertificateStorage = _useCertificateStorage;
	}  
}
