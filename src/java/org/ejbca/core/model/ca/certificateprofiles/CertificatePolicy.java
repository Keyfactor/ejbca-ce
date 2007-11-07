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
/*
 * Copyright 2005-2006 MULTICERT S.A.
 * All rights reserved.
 */
package org.ejbca.core.model.ca.certificateprofiles;

import java.io.Serializable;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;


/** Class encapsulating the CertificatePolicy X509 certificate extensions. See rfc3280.
 * 
 * @author Nuno Ponte of MultiCert
 * @version $Id: CertificatePolicy.java,v 1.1 2007-11-07 13:25:45 anatom Exp $
 */
public class CertificatePolicy implements Serializable, Cloneable {
    private static final long serialVersionUID = -6384137742329979248L;

    /**
     * The special <code>anyPolicy</code> policy OID.
     */
    public static final String ANY_POLICY_OID = "2.5.29.32.0";
    
    private String policyID;
    /** CPS uri */
    private String uri;
    /** user notice text */
    private String notice;

    public CertificatePolicy() {
        super();
    }

    /**
     * 
     * @param policyID
     * @param notice user notice text
     * @param uri cps uri
     */
    public CertificatePolicy(String policyID, String notice, String uri) {
        this.policyID = policyID;
        this.notice = notice;
        this.uri = uri;
    }

    /**
     * @return the policyID
     */
    public String getPolicyID() {
        return this.policyID;
    }

    /**
     * @param policyID the policyID to set
     */
    public void setPolicyID(String policyID) {
        this.policyID = policyID;
    }

    
    /**
     * @return the uri
     */
    public String getCpsUri() {
        return this.uri;
    }

    
    /**
     * @param uri the uri to set
     */
    public void setCpsUri(String uri) {
        this.uri = uri;
    }

    /**
     * @return the usernotice
     */
    public String getUserNotice() {
        return this.notice;
    }

    
    /**
     * @param notice the usernotice to set
     */
    public void setUserNotice(String notice) {
        this.notice = notice;
    }
    
    /**
     * @see java.lang.Object#clone()
     */
    protected Object clone() {
        return new CertificatePolicy(this.policyID, this.notice, this.uri);
    }

    /**
     * @see java.lang.Object#toString()
     */
    public String toString() {
        StringBuffer strBuffer = new StringBuffer("CertificatePolicy(");

        strBuffer.append("policyID=");
        strBuffer.append(this.policyID);
        strBuffer.append(", userNotice=");
        strBuffer.append(this.notice);
        strBuffer.append(", cpsUri=");
        strBuffer.append(this.uri);
        strBuffer.append(")");

        return strBuffer.toString();
    }

    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object obj) {
        if((obj == null) || !(obj instanceof CertificatePolicy)) {
            return false;
        }
        CertificatePolicy policy = (CertificatePolicy) obj;

        // We want to let both null and "" be the same value here, i.e. an empty value
        // Simply because, especially in gui code, it is somewhat tricky to trust which is a non-existant value
        boolean policyeq = false;
        if (StringUtils.isEmpty(policy.getPolicyID()) && StringUtils.isEmpty(this.policyID)) {
        	policyeq = true;
        } else if (StringUtils.equals(policy.getPolicyID(), this.policyID)) {
        	policyeq = true;
        }
        boolean unoticeeq = false;
        if (StringUtils.isEmpty(policy.getUserNotice()) && StringUtils.isEmpty(this.notice)) {
        	unoticeeq = true;
        } else if (StringUtils.equals(policy.getUserNotice(), this.notice)) {
        	unoticeeq = true;
        }
        boolean urieq = false;
        if (StringUtils.isEmpty(policy.getCpsUri()) && StringUtils.isEmpty(this.uri)) {
        	urieq = true;
        } else if (StringUtils.equals(policy.getCpsUri(), this.uri)) {
        	urieq = true;
        }
        return policyeq && unoticeeq && urieq; 
    }

    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
        return this.toString().hashCode();
    }

}
