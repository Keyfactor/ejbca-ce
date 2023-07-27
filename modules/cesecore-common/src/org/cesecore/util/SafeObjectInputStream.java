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

package org.cesecore.util;

import org.apache.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * <p>Safe deserialisation of objects. Contains functionality for whitelisting package prefixes, individual classes
 * as well as limiting the number of objects which can be deserialised.
 *
 * <p>This class should always be used when deserialising untrusted data.
 *
 * <p>Example usage:
 * <pre>
 * try (final SafeObjectInputStream safeObjectInputStream = SafeObjectInputStream.acceptingSafeClasses().build(untrustedData)) {
 *     safeObjectInputStream.readObject();
 * }
 * </pre>
 *
 * @see <a href="https://wiki.sei.cmu.edu/confluence/display/java/SER12-J.+Prevent+deserialization+of+untrusted+data">SEI CERT Oracle Coding Standard for Java SER12-J</a>
 */
public final class SafeObjectInputStream extends ObjectInputStream {
    private final static Logger log = Logger.getLogger(SafeObjectInputStream.class);
    private final List<Class<?>> allowedClasses;
    private final List<String> allowedPackagePrefixes;
    private final int maxNumberOfObjects;
    private final AtomicInteger objectCount = new AtomicInteger();

    public static class Builder {
        private List<Class<?>> allowedClasses = new ArrayList<>();
        private List<String> allowedPackagePrefixes = new ArrayList<>();
        private int maxNumberOfObjects = Integer.MAX_VALUE;

        public Builder allowClass(final Class<?> clazz) {
            allowedClasses.add(clazz);
            return this;
        }

        public Builder allowPackage(final String packageName) {
            allowedPackagePrefixes.add(packageName);
            return this;
        }

        public Builder allowingNumberOfObjects(final int maxNumberOfObjects) {
            this.maxNumberOfObjects = maxNumberOfObjects;
            return this;
        }

        public SafeObjectInputStream build(final InputStream inputStream) throws IOException {
            return new SafeObjectInputStream(this, inputStream);
        }
    }

    /**
     * Create a builder for {@link SafeObjectInputStream}, not accepting deserialization of
     * any class, except primitives and their object counterparts. Additional classes and
     * packages must be whitelisted explicitly.
     *
     * @return a builder object.
     */
    public static Builder acceptingNothing() {
        return new Builder();
    }

    /**
     * Create a builder for {@link SafeObjectInputStream}, accepting all classes from the
     * JDK, CeSeCore, EJBCA and SignServer.
     *
     * @return a builder object.
     */
    public static Builder acceptingSafeClasses() {
        return new Builder()
                .allowPackage("java")
                .allowPackage("org.cesecore")
                .allowPackage("org.ejbca")
                .allowPackage("org.signserver")
                .allowPackage("com.keyfactor");
    }

    private SafeObjectInputStream(final Builder builder, final InputStream inputStream) throws IOException {
        super(inputStream);
        enableResolveObject(true);
        this.allowedPackagePrefixes = builder.allowedPackagePrefixes;
        this.allowedClasses = builder.allowedClasses;
        this.maxNumberOfObjects = builder.maxNumberOfObjects;
    }

    @Override
    protected Object resolveObject(final Object object) throws IOException {
        if (objectCount.incrementAndGet() > maxNumberOfObjects) {
            throw new SecurityException("Attempt to deserialize too many objects from stream. The limit is "
                    + maxNumberOfObjects + " objects.");
        }
        return super.resolveObject(object);
    }

    @Override
    protected Class<?> resolveClass(final ObjectStreamClass objectStreamClass) throws IOException, ClassNotFoundException {
        final Class<?> resolvedClass = super.resolveClass(objectStreamClass);
        final Class<?> classType = getClassType(resolvedClass);
        if (log.isDebugEnabled()) {
            log.debug("Trying to deserialize class '" + classType.getName() + "'.");
        }
        if (classType.isPrimitive()) {
            return resolvedClass;
        }
        if (classType.equals(String.class) ||
                classType.equals(Boolean.class) ||
                classType.equals(Character.class) ||
                classType.equals(Float.class) ||
                classType.equals(Long.class) ||
                classType.equals(Integer.class) ||
                classType.equals(Double.class) ||
                classType.equals(Void.class)) {
            return resolvedClass;
        }
        if (allowedClasses.stream().anyMatch(clazz -> classType.equals(clazz))) {
            return resolvedClass;
        }
        if (allowedPackagePrefixes.stream().anyMatch(packagePrefix -> classType.getName().startsWith(packagePrefix))) {
            return resolvedClass;
        }
        throw new SecurityException("Prevented unauthorized deserialization of class '" + classType.getName() + "'.");
    }

    private Class<?> getClassType(Class<?> resolvedClass) {
        while (resolvedClass.isArray()) {
            resolvedClass = resolvedClass.getComponentType();
        }
        return resolvedClass;
    }
}
