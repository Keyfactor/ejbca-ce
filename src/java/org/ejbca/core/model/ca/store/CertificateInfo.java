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
import java.math.BigInteger;
import java.util.Date;

/**
 * Holds information about a certificate but not the certiifcate itself.
 *
 * @version $Id: CertificateInfo.java,v 1.1 2006-01-17 20:31:52 anatom Exp $
 */
public class CertificateInfo implements Serializable {

    protected String fingerprint;
    protected String cafingerprint;
    protected String serno;
    protected String issuerdn;
    protected String subjectdn;
    protected int status;
    protected int type;
    protected Date expiredate;
    protected Date revocationdate;
    protected int revocationreason;
    
    public CertificateInfo(String fingerprint, String cafingerprint, String serno, 
            String issuerdn, String subjectdn, int status, int type, 
            long expiredate, long revocationdate, int revocationreason){
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
    }
    
    public String getFingerprint() {return fingerprint;}
    public String getCAFingerprint() {return cafingerprint;}
    public BigInteger getSerialNumber() {return new BigInteger(serno);}
    public String getSubjectDN() {return subjectdn;}
    public String getIssuerDN() {return issuerdn;}
    public int getStatus() { return status; }
    public int getType() { return type; }
    public Date getExpireDate() { return expiredate; }
    public Date getRevocationDate() { return revocationdate; }
    public int getRevocationReason() { return revocationreason; }
    
}
