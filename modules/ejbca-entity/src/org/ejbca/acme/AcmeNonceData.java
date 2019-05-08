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

package org.ejbca.acme;

import java.io.Serializable;

import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;
import javax.persistence.Version;

import org.cesecore.dbprotection.DatabaseProtectionException;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;

/**
 * Storage representation of a used up ACME protocol Replay-Nonce.
 *
 * @version $Id$
 */
@Entity
@Table(name = "AcmeNonceData")
public class AcmeNonceData extends ProtectedData implements Serializable {
    private static final long serialVersionUID = 1L;

    private String nonce;
    private long timeExpires;
    private int rowVersion = 0;
    private String rowProtection;

    public AcmeNonceData() {}

    public AcmeNonceData(final String nonce, final long timeExpires) {
        this.setNonce(nonce);
        this.setTimeExpires(timeExpires);
    }

    // @Column
    public String getNonce() { return nonce; }
    public void setNonce(String nonce) { this.nonce = nonce; }

    // @Column
    public long getTimeExpires() { return timeExpires; }
    public void setTimeExpires(long timeExpires) { this.timeExpires = timeExpires; }

    // @Column
    @Version
    public int getRowVersion() { return rowVersion; }
    public void setRowVersion(int rowVersion) { this.rowVersion = rowVersion; }

    // @Column
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
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking so we will not include that in the database protection
        return new ProtectionStringBuilder().append(getNonce()).append(getTimeExpires()).toString();
    }

    @Transient
    @Override
    protected int getProtectVersion() {
        return 1;
    }

    @PrePersist
    @PreUpdate
    @Override
    protected void protectData() throws DatabaseProtectionException {
        super.protectData();
    }

    @PostLoad
    @Override
    protected void verifyData() throws DatabaseProtectionException {
        super.verifyData();
    }

    @Override
    @Transient
    protected String getRowId() {
        return getNonce();
    }

    //
    // End Database integrity protection methods
    //
}
