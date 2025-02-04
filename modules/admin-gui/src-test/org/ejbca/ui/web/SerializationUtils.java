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
package org.ejbca.ui.web;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Optional;

import com.google.common.reflect.ClassPath.ClassInfo;

import org.apache.commons.lang3.ClassUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;

import jakarta.ejb.EJB;
import jakarta.faces.annotation.ManagedProperty;

public class SerializationUtils {

    public static Optional<Pair<Field, Class<?>>> findFirstUnserializableMember(Class<?> clazz) {
        for (Field field : clazz.getDeclaredFields()) {
            // skip static, transient and dependency injected fields
            if (Modifier.isStatic(field.getModifiers()) || Modifier.isTransient(field.getModifiers()))
                continue;
            if (field.isAnnotationPresent(EJB.class))
                continue;
            if (field.isAnnotationPresent(ManagedProperty.class))
                continue;
    
            // for collection types, check their contained type
            Class<?> type = field.getType();
            if (java.util.Map.class.isAssignableFrom(type) || java.util.Set.class.isAssignableFrom(type)
                    || java.util.List.class.isAssignableFrom(type) || java.util.Collection.class.isAssignableFrom(type)) {
                type = field.getGenericType().getClass();
                continue;
            }
    
            java.awt.datatransfer.StringSelection classNameSelection = new java.awt.datatransfer.StringSelection(clazz.getCanonicalName());
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(classNameSelection, classNameSelection);
            if (!SerializationUtils.isSerializable(type))
                return Optional.of(Pair.of(field, type));
        }
        return Optional.empty();
    }

    public static boolean isSerializable(Class<?> clazz) {
        if (clazz.isPrimitive())
            return true;
        else if (clazz.isEnum())
            return true;
        else if (clazz.isArray())
            return isSerializable(clazz.getComponentType());

        // these classes are marked as serializable, but they really aren't.
        // Generally because they contain AuthenticationTokens
        else if (CAInterfaceBean.class.isAssignableFrom(clazz))
            return false;
        else if (AuthenticationToken.class.isAssignableFrom(clazz))
            return false;

        // check the immediate superclass and check if it's assignable from Serializable
        if (clazz.getSuperclass() != null && Serializable.class.isAssignableFrom(clazz.getSuperclass()))
            return true;

        // does this class implement Serializable?
        boolean isSerializable = false;
        for (var iface : ClassUtils.getAllInterfaces(clazz)) {
            if (Serializable.class.isAssignableFrom(iface)) {
                isSerializable = true;
            }
        }
        
        return isSerializable;
    }

    static boolean isOurClass(ClassInfo c) {
        return c.getPackageName().startsWith("org.ejbca") || c.getPackageName().startsWith("org.cesecore");
    }

    static boolean isOurClass(Class<?> c) {
        return c.getPackageName().startsWith("org.ejbca") || c.getPackageName().startsWith("org.cesecore");
    }

}
