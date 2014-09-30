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
package org.ejbca.core.protocol.ws.client.gen;

import java.util.GregorianCalendar;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.crl.RevokedCertInfo;

/**
 * Class used when checking the revocation status of a certificate.
 * 
 * Contains the following data:
 *   IssuerDN
 *   CertificateSN (hex)
 *   RevokationDate 
 *   Reason (One of the REVOKATION_REASON constants)
 *
 * @author Philip Vendil
 * @version $Id$
 */

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "revokeStatus", propOrder = {
    "certificateSN",
    "issuerDN",
    "reason",
    "revocationDate"
})
public class RevokeStatus {
	
    /** Constants defining different revocation reasons. */
    public static final int NOT_REVOKED                            = RevokedCertInfo.NOT_REVOKED;
    public static final int REVOKATION_REASON_UNSPECIFIED          = RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;
    public static final int REVOKATION_REASON_KEYCOMPROMISE        = RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE;
    public static final int REVOKATION_REASON_CACOMPROMISE         = RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE;
    public static final int REVOKATION_REASON_AFFILIATIONCHANGED   = RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED;
    public static final int REVOKATION_REASON_SUPERSEDED           = RevokedCertInfo.REVOCATION_REASON_SUPERSEDED;
    public static final int REVOKATION_REASON_CESSATIONOFOPERATION = RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION;
    public static final int REVOKATION_REASON_CERTIFICATEHOLD      = RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD;
    public static final int REVOKATION_REASON_REMOVEFROMCRL        = RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL;
    public static final int REVOKATION_REASON_PRIVILEGESWITHDRAWN  = RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN;
    public static final int REVOKATION_REASON_AACOMPROMISE         = RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE;
    
	private String               issuerDN;
    private String               certificateSN;
    @XmlSchemaType(name = "dateTime")
    private XMLGregorianCalendar revocationDate;
    private int                  reason;
	
    
    /** Default Web Service Constuctor */
	public RevokeStatus(){}
	
	public RevokeStatus(RevokedCertInfo info, String issuerDN) throws DatatypeConfigurationException{
		certificateSN = info.getUserCertificate().toString(16);
		this.issuerDN = issuerDN;
		GregorianCalendar cal = new GregorianCalendar ();
		cal.setTime(info.getRevocationDate());
		revocationDate = DatatypeFactory.newInstance ().newXMLGregorianCalendar(cal);
		reason = info.getReason();		
	}

	public RevokeStatus(CertificateStatus info, String issuerDN, String serno) throws DatatypeConfigurationException{
		certificateSN = serno;
		this.issuerDN = issuerDN;
		GregorianCalendar cal = new GregorianCalendar ();
		cal.setTime(info.revocationDate);
		revocationDate = DatatypeFactory.newInstance ().newXMLGregorianCalendar(cal);
		reason = info.revocationReason;		
	}

	/**
	 * @return Returns the reason.
	 */
	public int getReason() {
		return reason;
	}

	/**
	 * @param reason The reason to set.
	 */
	public void setReason(int reason) {
		this.reason = reason;
	}

	/**
	 * @return Returns the revocationDate.
	 */
	public XMLGregorianCalendar getRevocationDate() {
		return revocationDate;
	}

	/**
	 * @param revocationDate The revocationDate to set.
	 */
	public void setRevocationDate(XMLGregorianCalendar revocationDate) {
		this.revocationDate = revocationDate;
	}

	/**
	 * @return Returns the certificateSN in hex format.
	 */
	public String getCertificateSN() {
		return certificateSN;
	}

	/**
	 * @param certificateSN The certificateSN to set in hex format
	 */
	public void setCertificateSN(String certificateSN) {
		this.certificateSN = certificateSN;
	}

	/**
	 * @return Returns the issuerDN.
	 */
	public String getIssuerDN() {
		return issuerDN;
	}

	/**
	 * @param issuerDN The issuerDN to set.
	 */
	public void setIssuerDN(String issuerDN) {
		this.issuerDN = issuerDN;
	}
	


}
