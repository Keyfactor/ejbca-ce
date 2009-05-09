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
 
package org.ejbca.core.model.ca.store;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Date;

import org.bouncycastle.util.encoders.Hex;
import org.ejbca.core.model.protect.Protectable;

/**
 * Holds information about a certificate but not the certificate itself.
 *
 * @version $Id$
 */
public class CertificateInfo implements Serializable, Protectable {

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
    private Date updateTime;
    
    public CertificateInfo(String fingerprint, String cafingerprint, String serno, 
            String issuerdn, String subjectdn, int status, int type, 
            long expiredate, long revocationdate, int revocationreason, String username, String tag, int certificateProfileId, long updateTime){
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
        this.updateTime = new Date(updateTime);
    }
    
    public String getFingerprint() {return fingerprint;}
    public void setFingerprint(String fp) {this.fingerprint=fp;}
    public String getCAFingerprint() {return cafingerprint;}
    public BigInteger getSerialNumber() {return new BigInteger(serno);}
    public String getSubjectDN() {return subjectdn;}
    public String getIssuerDN() {return issuerdn;}
    public int getStatus() { return status; }
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

    // 
    // Protectable
    //
    public int getHashVersion() {
    	return 1;
    }
    public String getDbKeyString() {
    	return fingerprint;
    }
    public String getEntryType() {
    	return "CERTIFICATEDATA";
    }
    public String getHash() throws NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException {
    	StringBuffer buf = new StringBuffer();
    	// Don't include cafingerprint and type in the hash, because it is not avaiable in all places where we need to create protection
    	buf.append(fingerprint).append(issuerdn).append(subjectdn).append(status).
    		append(serno).append(expiredate).append(revocationdate).append(revocationreason);
        MessageDigest digest = MessageDigest.getInstance("SHA-256", "BC");
        byte[] result = digest.digest(buf.toString().getBytes("UTF-8"));
        return new String(Hex.encode(result));
    }
    public String getHash(int version) throws NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException {
    	return getHash();
    }
    

}
