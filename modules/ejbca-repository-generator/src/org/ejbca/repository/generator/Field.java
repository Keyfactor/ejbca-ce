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

package org.ejbca.repository.generator;

import java.io.Serializable;
import java.util.Objects;

public class Field implements Serializable {

    private static final long serialVersionUID = 1L;

    private String javaType;
    private String javaName;
    private String javaEnum;
    private String sqlType;
    private String sqlName;

    public Field() {
    }

    public Field(String javaType, String javaName, String javaEnum, String sqlType, String sqlName) {
        this.javaType = javaType;
        this.javaName = javaName;
        this.javaEnum = javaEnum;
        this.sqlType = sqlType;
        this.sqlName = sqlName;
    }

    public String getJavaType() {
        return javaType;
    }

    public void setJavaType(String javaType) {
        this.javaType = javaType;
    }

    public String getJavaName() {
        return javaName;
    }

    public void setJavaName(String javaName) {
        this.javaName = javaName;
    }

    public String getJavaEnum() {
        return javaEnum;
    }

    public void setJavaEnum(String javaEnum) {
        this.javaEnum = javaEnum;
    }

    public String getSqlType() {
        return sqlType;
    }

    public void setSqlType(String sqlType) {
        this.sqlType = sqlType;
    }

    public String getSqlName() {
        return sqlName;
    }

    public void setSqlName(String sqlName) {
        this.sqlName = sqlName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass().equals(o.getClass())) {
            return false;
        }
        Field field = (Field) o;
        return Objects.equals(javaType, field.javaType) &&
                Objects.equals(javaName, field.javaName) &&
                Objects.equals(javaEnum, field.javaEnum) &&
                Objects.equals(sqlType, field.sqlType) &&
                Objects.equals(sqlName, field.sqlType);
    }

    @Override
    public int hashCode() {
        return toString().hashCode();
    }

    @Override
    public String toString() {
        return JsonUtil.toJson(this);
    }

}
