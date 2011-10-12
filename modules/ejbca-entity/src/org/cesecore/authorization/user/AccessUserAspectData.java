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

package org.cesecore.authorization.user;

import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;

/**
 * Represents an aspect of an external user. It can be set to match one administrator's <i>DN</i> or an entire organization by matching against
 * <i>O</i>.
 * 
 * Based on EJBCA version:
 *      AdminEntityData.java 11168 2011-01-12 15:05:15Z jeklund from EJBCA
 * Based on cesecore version:
 *      AccessUserAspectData.java 944 2011-07-15 16:22:06Z mikek
 * 
 * @version $Id$
 */
@Entity
@Table(name = "AccessUserAspectData")
public class AccessUserAspectData extends ProtectedData implements AccessUserAspect, Comparable<AccessUserAspectData> {

    private static final long serialVersionUID = 5560742096462018744L;
    private int primaryKey;
    private X500PrincipalAccessMatchValue matchWith;
    private AccessMatchType matchType;
    private String matchValue;
    private Integer caId;
    private int rowVersion = 0;
    private String rowProtection;

    public AccessUserAspectData(final String roleName, final int caId, final X500PrincipalAccessMatchValue matchWith, final AccessMatchType matchType,
            final String matchValue) {

        this.primaryKey = generatePrimaryKey(roleName, caId, matchWith, matchType, matchValue);
        this.matchWith = matchWith;
        this.matchType = matchType;
        this.matchValue = matchValue;
        this.caId = caId;

    }

    /**
     * Private to stop default instantiation.
     */
    @SuppressWarnings("unused")
    private AccessUserAspectData() {

    }

    //@Id @Column
    public int getPrimaryKey() {
        return primaryKey;
    }

    public void setPrimaryKey(int primaryKey) {
        this.primaryKey = primaryKey;
    }

    @Override
    public int getMatchWith() {
        return matchWith.getNumericValue();
    }

    @Override
    @Transient
    public X500PrincipalAccessMatchValue getMatchWithByValue() {
        return matchWith;
    }

    @Override
    public void setMatchWith(Integer matchWith) {
        this.matchWith = X500PrincipalAccessMatchValue.matchFromDatabase(matchWith);
    }
    
    @Override
    public void setMatchWithAsValue(X500PrincipalAccessMatchValue matchWith) {
        this.matchWith = matchWith;
    }

    @Override
    public int getMatchType() {
    	if (matchType == null) {
    		return AccessMatchType.TYPE_NONE.getNumericValue();
    	}
        return matchType.getNumericValue();
    }

    @Override
    public void setMatchType(Integer matchType) {
        this.matchType = AccessMatchType.matchFromDatabase(matchType);
    }
    
    @Override
    public void setMatchTypeAsValue(AccessMatchType matchType) {
        this.matchType = matchType;
    }
    
    @Override
    @Transient
    public AccessMatchType getMatchTypeAsType() {
        return matchType;
    }

    @Override
    public String getMatchValue() {
        return matchValue;
    }


    @Override
    public void setMatchValue(String matchValue) {
        this.matchValue = matchValue;
    }

    @Override
    public Integer getCaId() {
        return caId;
    }


    @Override
    public void setCaId(Integer caId) {
        this.caId = caId;
    }

    public int getRowVersion() {
        return rowVersion;
    }

    public void setRowVersion(final int rowVersion) {
        this.rowVersion = rowVersion;
    }

    public String getRowProtection() {
        return rowProtection;
    }

    public void setRowProtection(final String rowProtection) {
        this.rowProtection = rowProtection;
    }

    public static int generatePrimaryKey(final String roleName, final int caId, final X500PrincipalAccessMatchValue matchWith,
            final AccessMatchType matchType, final String matchValue) {
        final int roleNameHash = roleName == null ? 0 : roleName.hashCode();
        final int matchValueHash = matchValue == null ? 0 : matchValue.hashCode();
        return roleNameHash ^ caId ^ matchWith.getNumericValue() ^ matchValueHash ^ matchType.getNumericValue();
    }

    @Override
    @Transient
    public X500PrincipalAccessMatchValue getPriority() {
        return matchWith;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((caId == null) ? 0 : caId.hashCode());
        result = prime * result + ((matchType == null) ? 0 : matchType.hashCode());
        result = prime * result + ((matchValue == null) ? 0 : matchValue.hashCode());
        result = prime * result + ((matchWith == null) ? 0 : matchWith.hashCode());
        result = prime * result + primaryKey;
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        AccessUserAspectData other = (AccessUserAspectData) obj;
        if (caId == null) {
            if (other.caId != null) {
                return false;
            }
        } else if (!caId.equals(other.caId)) {
            return false;
        }
        if (matchType != other.matchType) {
            return false;
        }
        if (matchValue == null) {
            if (other.matchValue != null) {
                return false;
            }
        } else if (!matchValue.equals(other.matchValue)) {
            return false;
        }
        if (matchWith != other.matchWith) {
            return false;
        }
        if (primaryKey != other.primaryKey) {
            return false;
        }
        return true;
    }

	//
	// Start Database integrity protection methods
	//
	
	@Transient
	@Override
	protected String getProtectString(final int version) {
		final ProtectionStringBuilder build = new ProtectionStringBuilder();
		// What is important to protect here is the data that we define
		// rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
		build.append(getPrimaryKey()).append(getMatchWith()).append(getMatchType()).append(getMatchValue()).append(getCaId());
		return build.toString();
	}

	@Transient
	@Override
	protected int getProtectVersion() {
		return 1;
	}

	@PrePersist
	@PreUpdate
	@Transient
	@Override
	protected void protectData() {
		super.protectData();
	}
	
	@PostLoad
	@Transient
	@Override
	protected void verifyData() {
		super.verifyData();
	}

	@Override 
    @Transient
	protected String getRowId() {
		return String.valueOf(getPrimaryKey());		
	}
	//
	// End Database integrity protection methods
	//

    @Override
    public int compareTo(AccessUserAspectData o) {
        return matchValue.compareTo(o.matchValue);
    }


}
