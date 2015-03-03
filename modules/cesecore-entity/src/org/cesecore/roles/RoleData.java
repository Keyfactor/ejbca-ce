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
package org.cesecore.roles;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;

/**
 * Represents a role, and is based in the AdminGroup concept from EJBCA.
 * 
 * @version $Id$
 * 
 */
@Entity
@Table(name = "RoleData")
public class RoleData extends ProtectedData implements Serializable, Comparable<RoleData> {

    public static final String DEFAULT_ROLE_NAME = "DEFAULT";

    private static final long serialVersionUID = -160810489638829430L;
    private Integer primaryKey;
    private Map<Integer, AccessRuleData> accessRules;
    private Map<Integer, AccessUserAspectData> accessUsers;
    private String roleName;
    private int rowVersion = 0;
    private String rowProtection;

    public RoleData() {

    }

    public RoleData(final Integer primaryKey, final String roleName) {
        this.primaryKey = primaryKey;
        this.roleName = roleName;
        accessUsers = new HashMap<Integer, AccessUserAspectData>();
        accessRules = new HashMap<Integer, AccessRuleData>();
    }

    // @Id @Column
    public Integer getPrimaryKey() {
        return primaryKey;
    }

    public void setPrimaryKey(Integer primaryKey) {
        this.primaryKey = primaryKey;
    }

    // @Column
    public String getRoleName() {
        return roleName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }

    // @Version @Column
    public int getRowVersion() {
        return rowVersion;
    }

    public void setRowVersion(final int rowVersion) {
        this.rowVersion = rowVersion;
    }

    // @Column @Lob
    @Override
    public String getRowProtection() {
        return rowProtection;
    }

    @Override
    public void setRowProtection(final String rowProtection) {
        this.rowProtection = rowProtection;
    }

    /*
     * If we use lazy fetching we have to take care so that the Entity is managed until we fetch the values. Set works better with eager fetching for
     * Hibernate.
     */
    // @OneToMany(cascade = { CascadeType.ALL }, fetch = FetchType.EAGER) @JoinColumn(name = "RoleData_accessUsers")
    public Map<Integer, AccessUserAspectData> getAccessUsers() {
        return accessUsers;
    }

    public void setAccessUsers(Map<Integer, AccessUserAspectData> accessUsers) {
        this.accessUsers = accessUsers;
    }

    /*
     * If we use lazy fetching we have to take care so that the Entity is managed until we fetch the values. Set works better with eager fetching for
     * Hibernate.
     */
    // @OneToMany(cascade = { CascadeType.ALL }, fetch = FetchType.EAGER) @JoinColumn(name = "RoleData_accessRules")
    public Map<Integer, AccessRuleData> getAccessRules() {
        return accessRules;
    }

    public void setAccessRules(Map<Integer, AccessRuleData> accessRules) {
        this.accessRules = accessRules;
    }
    
    /**
     * Utility method that makes a tree search of this Role's rules and checks for a positive match. 
     * @param rule the rule to check
     * @return true if this Role has access to the given rule. 
     */
    @Transient
    public boolean hasAccessToRule(final String rule) {
        if(!rule.startsWith("/")) {
            throw new IllegalArgumentException("Rule must start with a \"/\"");
        }
        //return recurseRules(rule, accessRules.values(), false);
        boolean result = false;
        for(AccessRuleData accessRuleData : accessRules.values()) {
            String currentRule = accessRuleData.getAccessRuleName();
            if(rule.startsWith(currentRule) && (rule.length() == currentRule.length() || rule.charAt(currentRule.length()) == '/')) {
                if(accessRuleData.getInternalState().equals(AccessRuleState.RULE_ACCEPT) && accessRuleData.getRecursive()) {
                    result = true;
                } else if(accessRuleData.getInternalState().equals(AccessRuleState.RULE_DECLINE)) {
                    result = false;
                    break;
                }
            }
        }
        return result;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((accessRules == null) ? 0 : accessRules.hashCode());
        result = prime * result + ((accessUsers == null) ? 0 : accessUsers.hashCode());
        result = prime * result + ((primaryKey == null) ? 0 : primaryKey.hashCode());
        result = prime * result + ((roleName == null) ? 0 : roleName.hashCode());
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
        RoleData other = (RoleData) obj;
        if (accessRules == null) {
            if (other.accessRules != null) {
                return false;
            }
        } else if (!accessRules.equals(other.accessRules)) {
            return false;
        }
        if (accessUsers == null) {
            if (other.accessUsers != null) {
                return false;
            }
        } else if (!accessUsers.equals(other.accessUsers)) {
            return false;
        }
        if (primaryKey == null) {
            if (other.primaryKey != null) {
                return false;
            }
        } else if (!primaryKey.equals(other.primaryKey)) {
            return false;
        }
        if (roleName == null) {
            if (other.roleName != null) {
                return false;
            }
        } else if (!roleName.equals(other.roleName)) {
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
        // What is important to protect here is the data that we define, id, name and certificate profile data
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getPrimaryKey()).append(getRoleName());
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
        return String.valueOf(getPrimaryKey());
    }

    //
    // End Database integrity protection methods
    //

    @Override
    public int compareTo(RoleData o) {
        return roleName.compareToIgnoreCase(o.roleName);
    }



}
