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

import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.commons.lang.StringUtils;
import org.cesecore.dbprotection.DatabaseProtectionException;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;

/**
 * Represents a role.
 * 
 * @version $Id$
 */
@Entity
@Table(name = "RoleData")
public class RoleData extends ProtectedData implements Serializable {

    private static final long serialVersionUID = 1L;
    private int id;
    private String nameSpaceColumn;
    private String roleName;
    private String rawData;
    private int rowVersion = 0;
    private String rowProtection;

    public RoleData() {
    }

    public RoleData(final Role role) {
        setRole(role);
    }

    // @Id @Column
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    //@Column(name="nameSpace")
    @Deprecated
    /** @deprecated (Only for database mapping) {@link #getNameSpaceNeverNull()} */
    public String getNameSpaceColumn() { return nameSpaceColumn; }
    @Deprecated
    /** @deprecated (Only for database mapping) {@link #setNameSpaceNeverNull(String)} */
    public void setNameSpaceColumn(String nameSpaceColumn) { this.nameSpaceColumn = nameSpaceColumn; }

    // Ensure that we treat empty string as null for consistent behavior with Oracle
    @Transient
    public String getNameSpace() {
        return StringUtils.defaultIfEmpty(getNameSpaceColumn(), "");
    }

    // Ensure that we treat empty string as null for consistent behavior with Oracle
    @Transient
    public void setNameSpace(final String nameSpace) {
        setNameSpaceColumn(StringUtils.defaultIfEmpty(nameSpace, null));
    }

    // @Column
    public String getRoleName() { return roleName; }
    public void setRoleName(String roleName) { this.roleName = roleName; }


    // @Column
    /** Should not be invoked directly. Use getDataMap() instead. */
    public String getRawData() { return rawData; }
    /** Should not be invoked directly. Use setDataMap(..) instead. */
    public void setRawData(String rawData) { this.rawData = rawData; }

    @Transient
    @SuppressWarnings("unchecked")
    public LinkedHashMap<Object, Object> getDataMap() {
        try (final XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(getRawData().getBytes(StandardCharsets.UTF_8)));) {
            // Handle Base64 encoded string values
            return new Base64GetHashMap((Map<?, ?>)decoder.readObject());
        }
    }

    @Transient
    public void setDataMap(final LinkedHashMap<Object, Object> dataMap) {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final XMLEncoder encoder = new XMLEncoder(baos);){
            // We must base64 encode string for UTF safety
            encoder.writeObject(new Base64PutHashMap(dataMap));
        }
        setRawData(new String(baos.toByteArray(), StandardCharsets.UTF_8));
    }

    @Transient
    public Role getRole() {
        return new Role(getId(), getNameSpace(), getRoleName(), getDataMap());
    }

    @Transient
    public void setRole(final Role role) {
        setId(role.getRoleId());
        setNameSpace(role.getNameSpace());
        setRoleName(role.getRoleName());
        setDataMap(role.getRawData());
    }

    // @Version @Column
    public int getRowVersion() { return rowVersion; }
    public void setRowVersion(final int rowVersion) { this.rowVersion = rowVersion; }

    // @Column @Lob
    @Override
    public String getRowProtection() { return rowProtection; }
    @Override
    public void setRowProtection(final String rowProtection) { this.rowProtection = rowProtection; }

    //
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    protected String getProtectString(final int version) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder();
        // What is important to protect here is the data that we define, id, name and certificate profile data
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getId()).append(getNameSpace()).append(getRoleName()).append(getRawData()).append(getRawData());
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
        return String.valueOf(getId());
    }

    //
    // End Database integrity protection methods
    //
    
    @Override
    public String toString() {
        return roleName;
    }
    
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + id;
        result = prime * result + ((nameSpaceColumn == null) ? 0 : nameSpaceColumn.hashCode());
        result = prime * result + ((roleName == null) ? 0 : roleName.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        RoleData other = (RoleData) obj;
        if (id != other.id)
            return false;
        if (nameSpaceColumn == null) {
            if (other.nameSpaceColumn != null)
                return false;
        } else if (!nameSpaceColumn.equals(other.nameSpaceColumn))
            return false;
        if (roleName == null) {
            if (other.roleName != null)
                return false;
        } else if (!roleName.equals(other.roleName))
            return false;
        return true;
    }
}
