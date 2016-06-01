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
package org.cesecore.certificates.certificate;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Date;

/**
 * Holds information about a certificate but not the certificate itself.
 *
 * @version $Id$
 */
public class CertificateInfo implements Serializable {

	private static final long serialVersionUID = -1973602951994928833L;
	
	private String fingerprint;
    private String cafingerprint;
    private String serno;
    private String issuerdn;
    private String subjectdn;
    private int status;
    private int type;
    private Date expiredate;
    private Date revocationdate;
    private int revocationreason;
    private String username;
	private String tag;
	private int certificateProfileId;
    private Integer endEntityProfileId;
    private Date updateTime;
    private String subjectKeyId;
    private String subjectAltName;
    
    public CertificateInfo(String fingerprint, String cafingerprint, String serno,  String issuerdn, String subjectdn, int status, int type, 
            long expiredate, long revocationdate, int revocationreason, String username, String tag, int certificateProfileId,
            Integer endEntityProfileId, long updateTime, String subjectKeyId, String subjectAltName) {
        this.fingerprint=fingerprint;
        this.cafingerprint=cafingerprint;
        this.serno=serno;
        this.issuerdn=issuerdn;
        this.subjectdn=subjectdn;
        this.status=status;
        this.type=type;
        this.expiredate=new Date(expiredate);
        this.revocationdate=new Date(revocationdate);
        this.revocationreason=revocationreason;
        this.username = username;
        this.tag = tag;
        this.certificateProfileId = certificateProfileId;
        this.endEntityProfileId = endEntityProfileId;
        this.updateTime = new Date(updateTime);
        this.subjectKeyId = subjectKeyId;
        this.subjectAltName = subjectAltName;
    }
    
    public String getFingerprint() {return fingerprint;}
    public void setFingerprint(String fp) {this.fingerprint=fp;}
    public String getCAFingerprint() {return cafingerprint;}
    public BigInteger getSerialNumber() {return new BigInteger(serno);}
    public String getSubjectDN() {return subjectdn;}
    public String getIssuerDN() {return issuerdn;}
    /** One of the CertificateConstants.CERT_ constants, for example CertificateConstants.CERT_ACTIVE */
    public int getStatus() { return status; }
    /** One of the CertificateConstants.CERT_ constants, for example CertificateConstants.CERT_ACTIVE */
    public void setStatus(int s) { this.status=s; }
    public int getType() { return type; }
    public Date getExpireDate() { return expiredate; }
    public Date getRevocationDate() { return revocationdate; }
    public void setRevocationDate(Date d) { this.revocationdate=d; }
    public int getRevocationReason() { return revocationreason; }
    public String getTag() {
		return tag;
	}

	public void setTag(String tag) {
		this.tag = tag;
	}

	public int getCertificateProfileId() {
		return certificateProfileId;
	}

	public int getEndEntityProfileIdOrZero() {
	    return endEntityProfileId==null ? 0 : endEntityProfileId;
	}

	public void setCertificateProfileId(int certificateProfileId) {
		this.certificateProfileId = certificateProfileId;
	}

	public Date getUpdateTime() {
		return updateTime;
	}

	public void setUpdateTime(Date updateTime) {
		this.updateTime = updateTime;
	}

    public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

    public String getSubjectKeyId() {
        return subjectKeyId;
    }
	
    public String getSubjectAltName() {
        return subjectAltName;
    }
}
