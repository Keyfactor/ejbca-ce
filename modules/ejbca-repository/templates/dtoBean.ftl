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

package ${packageName}.dto;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
<#if production>
import org.cesecore.dbprotection.DatabaseProtectionException;
import org.cesecore.dbprotection.ProtectedDataImpl;
import org.cesecore.dbprotection.ProtectedDataIntegrityImpl;
import org.cesecore.dbprotection.ProtectionStringBuilder;
</#if>

import java.io.Serializable;
import java.util.Objects;

@Entity
@Table(name = "${name?cap_first}")
public final class ${name?cap_first}Bean implements Serializable, EntityManagerBean {
<#if production>

    private static ProtectedDataImpl protectedDataImpl;

    static {
        protectedDataImpl = new ProtectedDataIntegrityImpl();
        protectedDataImpl.setTableName("${name?cap_first}");
    }

    public static ProtectedDataImpl getProtectedDataImpl() {
        return protectedDataImpl;
    }

    public static void setProtectedDataImpl(final ProtectedDataImpl protectedDataImpl) {
        ${name?cap_first}Bean.protectedDataImpl = protectedDataImpl;
    }
</#if>

<#list fields as field>
    private ${field.javaType} ${field.javaName};
</#list>
<#if xmlName??>
    private String ${xmlName};
</#if>
    private Integer rowVersion;
    private String rowProtection;

    public ${name?cap_first}Bean() {
        rowVersion = 0;
    }

<#list fields as field>
    <#if field.javaName==idName>
    @Id
    </#if>
    public ${field.javaType} get${field.javaName?cap_first}() {
       return this.${field.javaName};
    }

    public void set${field.javaName?cap_first}(${field.javaType} ${field.javaName}) {
       this.${field.javaName} = ${field.javaName};
    }

</#list>
<#if xmlName??>
    public String get${xmlName?cap_first}() {
       return ${xmlName};
    }

    public void set${xmlName?cap_first}(String ${xmlName}) {
       this.${xmlName} = ${xmlName};
    }

</#if>
    public int getRowVersion() {
        return this.rowVersion;
    }

    public void setRowVersion(final int rowVersion) {
        this.rowVersion = rowVersion;
    }

    public String getRowProtection() {
        return this.rowProtection;
    }

    public void setRowProtection(final String rowProtection) {
        this.rowProtection = rowProtection;
    }

    @Transient
    @Override
    public int getProtectVersion() {
        return 1;
    }

    @Transient
    @Override
    public String getProtectString(final int version) {
<#if production>
        ProtectionStringBuilder builder = new ProtectionStringBuilder();
    <#list fields as field>
        builder.append(get${field.javaName?cap_first}());
    </#list>
        return builder.toString();
<#else>
        return null;
</#if>
    }

<#if production>
    @PrePersist
    @PreUpdate
    protected void protectData() throws DatabaseProtectionException {
        final var unProtectedData = getProtectString(getProtectVersion());
        final var protectedData = protectedDataImpl.getProtectedData(rowVersion, unProtectedData);
        if (protectedData != null) {
            setRowProtection(protectedData);
        }
    }
<#else>
    @PrePersist
    @PreUpdate
    protected void protectData() {
    }
</#if>

<#if production>
    @PostLoad
    protected void verifyData() throws DatabaseProtectionException {
        try {
            final var unProtectedData = getProtectString(getProtectVersion());
            protectedDataImpl.verifyData(unProtectedData, rowProtection, "PublisherDataBean", String.valueOf(${idName}));
        } catch (final DatabaseProtectionException e) {
            protectedDataImpl.onDataVerificationError(e);
        }
    }
<#else>
    @PostLoad
    protected void verifyData() {
    }
</#if>

    @Override
    public String toString() {
       StringBuilder stringBuilder = new StringBuilder();
<#list fields as field>
       stringBuilder.append("${field.javaName}: " + ${field.javaName} + "\n");
</#list>
<#if xmlName??>
       stringBuilder.append("${xmlName}: \n");
       stringBuilder.append(${xmlName});
</#if>
       stringBuilder.append("rowVersion: " + rowVersion + "\n");
       stringBuilder.append("rowProtection: " + rowProtection + "\n");
       return stringBuilder.toString();
    }

    @Override
    public boolean equals(Object o) {
       if (this == o) {
          return true;
       }
       if (o == null || getClass() != o.getClass()) {
          return false;
       }
       ${name?cap_first}Bean ${name}Bean = (${name?cap_first}Bean) o;
       return
    <#list fields as field>
          Objects.equals(${field.javaName}, ${name}Bean.${field.javaName}) &&
    </#list>
<#if xmlName??>
          Objects.equals(${xmlName}, ${name}Bean.${xmlName}) &&
</#if>
          Objects.equals(rowVersion, ${name}Bean.rowVersion) &&
          Objects.equals(rowProtection, ${name}Bean.rowProtection);
    }

    @Override
    public int hashCode() {
       return Objects.hash(
    <#list fields as field>
                 ${field.javaName},
    </#list>
<#if xmlName??>
                 ${xmlName},
</#if>
                 rowVersion,
                 rowProtection);
    }

}
