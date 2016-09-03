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
package org.cesecore.certificates.certificateprofile;

import java.io.Serializable;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.x509.PolicyQualifierId;


/** Class encapsulating the CertificatePolicy X509 certificate extensions. See rfc3280.
 * Contains an OID and optionally a policy qualifier. Several CertificatePolicy classes 
 * can be created with the same oid, for different qualifiers
 * 
 * @version $Id$
 */
public class CertificatePolicy implements Serializable, Cloneable {

	/** Warning changing this value will cause upgrades to fail, because
	 * it has been serialized in the database (in XML).
	 * DONT CHANGE THIS!
	 */
    private static final long serialVersionUID = -6384137742329979249L;

    // Policy qualifier Ids are taken from BC classes
    public static final String id_qt_cps = PolicyQualifierId.id_qt_cps.getId();
    public static final String id_qt_unotice = PolicyQualifierId.id_qt_unotice.getId();
    
    /**
     * The special <code>anyPolicy</code> policy OID.
     */
    public static final String ANY_POLICY_OID = "2.5.29.32.0";
    
    private String policyID;
    /** CPS uri */
    private String qualifierId;
    /** user notice text */
    private String qualifier;

    public CertificatePolicy() {
        super();
    }

    /**
     * 
     * @param policyID
     * @param qualifierId PolicyQualifierId.id_qt_cps, PolicyQualifierId.id_qt_unotice or null
     * @param qualifier cps URI or user notice text depending on qualifierId, or null if qualifierId is null
     */
    public CertificatePolicy(final String policyID, final String qualifierId, final String qualifier) {
        this.policyID = policyID;
        this.qualifierId = qualifierId;
        this.qualifier = qualifier;
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
    public void setPolicyID(final String policyID) {
        this.policyID = policyID;
    }

    
    /**
     * @return the qualifier string
     */
    public String getQualifier() {
        return this.qualifier;
    }

    
    /**
     * @param uri the uri to set
     */
    public void setQualifier(final String qualifier) {
        this.qualifier = qualifier;
    }

    /**
     * @return the QualifierId
     */
    public String getQualifierId() {
        return this.qualifierId;
    }

    
    /**
     * @param qualifierId the QualifierId to set
     */
    public void setQualifierId(final String qualifierId) {
        this.qualifierId = qualifierId;
    }
    
    /**
     * @see java.lang.Object#clone()
     */
    protected Object clone() throws CloneNotSupportedException { // NOPMD by tomas on 1/7/11 1:04 PM
        return new CertificatePolicy(this.policyID, this.qualifierId, this.qualifier);
    }

    /**
     * @see java.lang.Object#toString()
     */
    public String toString() {
        final StringBuilder strBuilder = new StringBuilder(100);

        strBuilder.append("CertificatePolicy(policyID=");
        strBuilder.append(this.policyID);
        strBuilder.append(", qualifierId=");
        strBuilder.append(this.qualifierId);
        strBuilder.append(", qualifier=");
        strBuilder.append(this.qualifier);
        strBuilder.append(')');

        return strBuilder.toString();
    }

    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(final Object obj) {
        if((obj == null) || !(obj instanceof CertificatePolicy)) {
            return false;
        }
        final CertificatePolicy policy = (CertificatePolicy) obj;

        // We want to let both null and "" be the same value here, i.e. an empty value
        // Simply because, especially in gui code, it is somewhat tricky to trust which is a non-existant value
        boolean policyeq = false;
        if (StringUtils.isEmpty(policy.getPolicyID()) && StringUtils.isEmpty(this.policyID)) {
        	policyeq = true;
        } else if (StringUtils.equals(policy.getPolicyID(), this.policyID)) {
        	policyeq = true;
        }
        boolean qualifierideq = false;
        if (StringUtils.isEmpty(policy.getQualifierId()) && StringUtils.isEmpty(this.qualifierId)) {
        	qualifierideq = true;
        } else if (StringUtils.equals(policy.getQualifierId(), this.qualifierId)) {
        	qualifierideq = true;
        }
        boolean qualifier = false;
        if (StringUtils.isEmpty(policy.getQualifier()) && StringUtils.isEmpty(this.qualifier)) {
        	qualifier = true;
        } else if (StringUtils.equals(policy.getQualifier(), this.qualifier)) {
        	qualifier = true;
        }
        return policyeq && qualifierideq && qualifier; 
    }

    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
        return this.toString().hashCode();
    }

}
