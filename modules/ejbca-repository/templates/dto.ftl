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

<#if xmlName??>
import java.util.Map;
</#if>
import org.cesecore.repository.dto.Dto;

public interface ${name?cap_first} extends Dto<${idType}>, Comparable<${name?cap_first}> {

<#list fields as field>
<#if field.javaEnum??>
    ${field.javaEnum} ${field.javaName}();
<#else>
    ${field.javaType} ${field.javaName}();
</#if>
</#list>
<#if xmlName??>
    Map<Object, Object> ${xmlName}();
</#if>

    ${name?cap_first}Bean toBean();
    ${name?cap_first}Builder toBuilder();
<#list fields as field>
    <#if field.javaEnum??>
    ${name?cap_first} with${field.javaName?cap_first}(final ${field.javaEnum} ${field.javaName});
    <#else>
    ${name?cap_first} with${field.javaName?cap_first}(final ${field.javaType} ${field.javaName});
    </#if>
</#list>
<#if xmlName??>
    ${name?cap_first} with${xmlName?cap_first}(final Map<Object, Object> ${xmlName});
</#if>

}
