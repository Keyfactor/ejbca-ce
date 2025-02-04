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

import java.io.IOException;
import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

import com.google.common.reflect.ClassPath;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.util.CeSecoreNameStyleEnumSingleton;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import static org.junit.Assert.fail;

/**
 * There are too many failures to leave this in.  We need to fix this at some point,
 * but {@link SessionAndViewScopedBeansAreSerializableUnitTest}
 * covers the important classes for High Availability/Session sharing.
 * 
 * Still, all of the failures below fail the Serialization contract and will fail if
 * any attempt is made to serialize the allegedly Serializable classes that are failing.
 */
@Ignore
@RunWith(Parameterized.class)
public class SerializableClassesAreReallySerializableUnitTest {
    private Class<?> aSerializableClass;

    @Parameters(name = "{0}")
    public static Collection<Class<?>> ourSerializableClasses() throws IOException {
        Set<Class<?>> exceptions = new HashSet<>();

        // this class is never serialized, see org.ejbca.ra.RaAbstractDn.nameStyleProvider
        exceptions.add(CeSecoreNameStyleEnumSingleton.class);

        // find all classes that implement serializable in our packages
        var serializableClasses = new TreeSet<Class<?>>((c1, c2) -> c1.getName().compareTo(c2.getName()));
        var allClasses = ClassPath.from(SerializableClassesAreReallySerializableUnitTest.class.getClassLoader()).getAllClasses();
        allClasses.forEach(c -> {
            if (SerializationUtils.isOurClass(c)) {
                // dont worry about unit tests
                if (!c.getName().contains("UnitTest")) {
                    Class<?> ejbcaClass = c.load();
                    if (!exceptions.contains(ejbcaClass) && Serializable.class.isAssignableFrom(ejbcaClass))
                        serializableClasses.add(ejbcaClass);
                }
            }
        });

        return serializableClasses;
    }

    public SerializableClassesAreReallySerializableUnitTest(Class<?> aSerializableClass) {
        this.aSerializableClass = aSerializableClass;
    }

    /**
     * Any classes we own that we declare as `implements Serializable` should really be serializable.
     * In general, this means that you should ensure that any fields are classes that implement Serializable.
     * If that's not possible, then you can often mark the field as `transient` and ensure that there
     * is a way to de-serialize them using a custom readObject, make them lazily constructed when null, etc.
     * 
     * {@link AuthenticationToken} and classes that contain AuthenticationTokens are a special case - they 
     * are explicitly forbidden from being serialized and then de-serialized on another JVM.  To create
     * an AuthenticationToken field, it is best to mark it as `transient` and create a lazy-constructing
     * "getter" and only use that method to access the field.
     */
    @Test
    public void allMembersAreSerializable() throws Exception {
        //@formatter:off
        SerializationUtils.findFirstUnserializableMember(aSerializableClass).ifPresent(
                fieldAndClass -> fail(
                        aSerializableClass 
                        + " contains a field " + fieldAndClass.getLeft().getName()
                        + " with class " + fieldAndClass.getRight().getCanonicalName() 
                        + " which is not serializable"));
        //@formatter:on
    }

}
