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

import java.util.HashMap;
import java.util.LinkedHashMap;

import org.apache.commons.lang.StringUtils;
import org.cesecore.internal.UpgradeableDataHashMap;

/**
 * A Role contains access rules and meta data about the Role (id, nameSpace, roleName).
 * 
 * @version $Id$
 */
public class Role extends UpgradeableDataHashMap implements Comparable<Role> {
    
    private static final long serialVersionUID = 1L;
    //private static final Logger log = Logger.getLogger(Role.class);

    public static final float LATEST_VERSION = 1;
    public static final int ROLE_ID_UNASSIGNED = 0;
    public static final Boolean STATE_ALLOW = Boolean.TRUE;
    public static final Boolean STATE_DENY = Boolean.FALSE;

    private static final String KEY_ACCESS_RULES = "accessRules";
    
    private int roleId;
    private String roleName;
    private String nameSpace;

    public Role(final String nameSpace, final String roleName) {
        this.roleId = ROLE_ID_UNASSIGNED;
        setNameSpace(nameSpace);
        this.roleName = roleName;
    }

    public Role(final String nameSpace, final String roleName, final HashMap<String, Boolean> accessRules) {
        this.roleId = ROLE_ID_UNASSIGNED;
        setNameSpace(nameSpace);
        this.roleName = roleName;
        getAccessRules().putAll(accessRules);
    }

    /** Constructor used during load from database */
    public Role(final int roleId, final String nameSpace, final String roleName, final LinkedHashMap<Object, Object> dataMap) {
        this.roleId = roleId;
        setNameSpace(nameSpace);
        this.roleName = roleName;
        loadData(dataMap);
    }

    public int getRoleId() { return roleId; }
    public void setRoleId(final int roleId) { this.roleId = roleId; }

    public String getNameSpace() {
        return nameSpace;
    }
    public void setNameSpace(final String nameSpace) {
        this.nameSpace = StringUtils.isEmpty(nameSpace) ? "" : nameSpace.trim();
    }

    public String getRoleName() {
        return roleName;
    }
    public void setRoleName(final String roleName) {
        this.roleName = StringUtils.isEmpty(roleName) ? "" : roleName.trim();
    }

    public String getRoleNameFull() {
        return (nameSpace.isEmpty() ? "" : nameSpace + " ") + roleName;
    }

    public static String getRoleNameFullAsCacheName(final String nameSpace, final String roleName) {
        return (nameSpace==null || nameSpace.isEmpty() ? ";" : nameSpace + ";") + roleName;
    }

    @Override
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    @Override
    public void upgrade() {
        // TODO
    }

    @Override
    public int compareTo(Role role) {
        return getRoleNameFull().compareTo(role.getRoleNameFull());
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((nameSpace == null) ? 0 : nameSpace.hashCode());
        result = prime * result + roleId;
        result = prime * result + ((roleName == null) ? 0 : roleName.hashCode());
        final LinkedHashMap<String, Boolean> accessRules = getAccessRules();
        result = prime * result + ((accessRules == null) ? 0 : accessRules.hashCode());
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
        if (!(obj instanceof Role)) {
            return false;
        }
        Role other = (Role) obj;
        if (nameSpace == null) {
            if (other.nameSpace != null) {
                return false;
            }
        } else if (!nameSpace.equals(other.nameSpace)) {
            return false;
        }
        final LinkedHashMap<String, Boolean> accessRules = getAccessRules();
        final LinkedHashMap<String, Boolean> accessRulesOther = other.getAccessRules();
        if (accessRules == null) {
            if (accessRulesOther != null) {
                return false;
            }
        } else if (!accessRules.equals(accessRulesOther)) {
            return false;
        }
        if (roleId != other.roleId) {
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

    /**
     * Access rules are stored as map with pairs of "/resource/subresource/subsubresource" and STATE_ALLOW/STATE_DENY.
     * 
     * Resource definitions are always recursive ("/resource/" with STATE_ALLOW implies "/resource/subresource/" with STATE_ALLOW etc.)
     */
    public LinkedHashMap<String, Boolean> getAccessRules() {
        @SuppressWarnings("unchecked")
        LinkedHashMap<String, Boolean> ret = (LinkedHashMap<String, Boolean> ) data.get(KEY_ACCESS_RULES);
        if (ret==null) {
            ret = new LinkedHashMap<>();
            data.put(KEY_ACCESS_RULES, ret); // Make it "managed" in case caller want to modify it
        }
        return ret;
    }

    /** @return true if this Role has access to the given resource */
    public boolean hasAccessToResource(final String resource) {
        return AccessRulesHelper.hasAccessToResource(getAccessRules(), resource);
    }

    /** Normalize access rules tree (make sure rules always end with a '/') */
    public void normalizeAccessRules() {
        AccessRulesHelper.normalizeResources(getAccessRules());
    }
    
    /** Remove redundant rules. Assumes normalized form. */
    public void minimizeAccessRules() {
        AccessRulesHelper.minimizeAccessRules(getAccessRules());
    }

    /** Sort access rules by name. Assumes normalized form. */
    public void sortAccessRules() {
        AccessRulesHelper.sortAccessRules(getAccessRules());
    }
}
