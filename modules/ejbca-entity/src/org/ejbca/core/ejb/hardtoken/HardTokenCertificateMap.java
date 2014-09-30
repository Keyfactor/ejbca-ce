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

package org.ejbca.core.ejb.hardtoken;

import java.io.Serializable;
import java.util.List;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;

/**
 * Representation of certificates placed on a token.
 * 
 * @version $Id$
 */
@Entity
@Table(name="HardTokenCertificateMap")
public class HardTokenCertificateMap extends ProtectedData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(HardTokenCertificateMap.class);

	private String certificateFingerprint;
	private String tokenSN;
	private int rowVersion = 0;
	private String rowProtection;

	/**
	 * Entity holding data of a certificate to hard token relation.
	 */
	public HardTokenCertificateMap(String certificateFingerprint, String tokenSN) {
		setCertificateFingerprint(certificateFingerprint);
		setTokenSN(tokenSN);
		log.debug("Created HardTokenCertificateMap for token SN: "+ tokenSN );
	}
	
	public HardTokenCertificateMap() { }

	//@Id @Column
	public String getCertificateFingerprint() { return certificateFingerprint; }
	public void setCertificateFingerprint(String certificateFingerprint) { this.certificateFingerprint = certificateFingerprint; }

	//@Column
	public String getTokenSN() { return tokenSN; }
	public void setTokenSN(String tokenSN) { this.tokenSN = tokenSN; }

	//@Version @Column
	public int getRowVersion() { return rowVersion; }
	public void setRowVersion(int rowVersion) { this.rowVersion = rowVersion; }

	//@Column @Lob
	@Override
	public String getRowProtection() { return rowProtection; }
	@Override
	public void setRowProtection(String rowProtection) { this.rowProtection = rowProtection; }

    //
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    protected String getProtectString(final int version) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder();
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getCertificateFingerprint()).append(getTokenSN());
        return build.toString();
    }

    @Transient
    @Override
    protected int getProtectVersion() {
        return 1;
    }

    @PrePersist
    @PreUpdate
    @Override
    protected void protectData() {
        super.protectData();
    }

    @PostLoad
    @Override
    protected void verifyData() {
        super.verifyData();
    }

    @Override
    @Transient
    protected String getRowId() {
        return getCertificateFingerprint();
    }

    //
    // End Database integrity protection methods
    //

	//
	// Search functions. 
	//

	/** @return the found entity instance or null if the entity does not exist */
	public static HardTokenCertificateMap findByCertificateFingerprint(EntityManager entityManager, String certificateFingerprint) {
		return entityManager.find(HardTokenCertificateMap.class, certificateFingerprint);
	}

	/** @return return the query results as a List. */
	@SuppressWarnings("unchecked")
    public static List<HardTokenCertificateMap> findByTokenSN(EntityManager entityManager, String tokenSN) {
		Query query = entityManager.createQuery("SELECT a FROM HardTokenCertificateMap a WHERE a.tokenSN=:tokenSN");
		query.setParameter("tokenSN", tokenSN);
		return query.getResultList();
	}
}
