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

import org.cesecore.util.CompareUtil;
<#if indexNames?size !=0>
import java.util.Objects;
</#if>
<#if xmlName??>
import java.util.Map;

public record ${name?cap_first}Dto(
<#list fields as field>
    <#if field.javaEnum??>
                       ${field.javaEnum} ${field.javaName},
    <#else>
                       ${field.javaType} ${field.javaName},
    </#if>
</#list>
                       Map<Object, Object> ${xmlName}) implements Dto<${idType}>, Comparable<${name?cap_first}Dto> {
<#else>

public record ${name?cap_first}Dto(
<#list fields as field>
    <#if field.javaEnum??>
                       ${field.javaEnum} ${field.javaName}<#if field?is_last>) implements Dto<${idType}>, Comparable<${name?cap_first}Dto> {<#else>,</#if>
    <#else>
                       ${field.javaType} ${field.javaName}<#if field?is_last>) implements Dto<${idType}>, Comparable<${name?cap_first}Dto> {<#else>,</#if>
    </#if>
</#list>
</#if>

    @Override
    public ${idType} id() {
        return ${idName};
    }

<#if indexNames?size !=0>
    public int cacheKey() {
        return Objects.hash(indexValues());
    }

    @Override
    public String[] indexNames() {
        return new String[] { <#list indexNames as indexName>"${indexName}"<#if !indexName?is_last>, </#if></#list> };
    }

    @Override
    public Object[] indexValues() {
        return new Object[] { <#list indexNames as indexName>${indexName}<#if !indexName?is_last>, </#if></#list> };
    }

</#if>

    public ${name?cap_first}DtoBuilder toBuilder() {
        return new ${name?cap_first}DtoBuilder(this);
    }

<#if idName != "id">
    public ${name?cap_first}Dto withId(final ${idType} id) {
        return with${idName?cap_first}(id);
    }

</#if>
<#list fields as field>
    <#if field.javaEnum??>
    public ${field.javaEnum} get${field.javaName?cap_first}() {
    <#else>
    public ${field.javaType} get${field.javaName?cap_first}() {
    </#if>
        return this.${field.javaName};
    }

</#list>
<#if xmlName??>
    public Map<Object, Object> get${xmlName?cap_first}() {
    return ${xmlName}();
    }

</#if>
<#list fields as field>
    <#if field.javaEnum??>
    public ${name?cap_first}Dto with${field.javaName?cap_first}(final ${field.javaEnum} ${field.javaName}) {
    <#else>
    public ${name?cap_first}Dto with${field.javaName?cap_first}(final ${field.javaType} ${field.javaName}) {
    </#if>
        return new ${name?cap_first}Dto(
<#if xmlName??>
<#list fields as f>
                ${f.javaName},
</#list>
                ${xmlName});
<#else>
<#list fields as f>
                ${f.javaName}<#if f?is_last>);<#else>,</#if>
</#list>
</#if>
    }

</#list>
<#if xmlName??>
    public ${name?cap_first}Dto with${xmlName?cap_first}(final Map<Object, Object> ${xmlName}) {
        return new ${name?cap_first}Dto(
<#list fields as field>
            ${field.javaName},
</#list>
            ${xmlName});
    }

</#if>
    @Override
    public int compareTo(final ${name?cap_first}Dto ${name}) {
        int c;
<#list fields as field>
        c = CompareUtil.compare(this.${field.javaName}, ${name}.${field.javaName}());
        if (c != 0) {
            return c;
        }
</#list>
        return 0;
    }

}
