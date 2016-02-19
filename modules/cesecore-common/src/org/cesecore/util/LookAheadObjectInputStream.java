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
package org.cesecore.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.io.Serializable;
import java.util.Collection;
import java.util.Comparator;
import java.util.Set;
import java.util.TreeSet;

/** Can be used instead of ObjectInputStream to safely deserialize(readObject) unverified serialized java object. 
 * 
 * Simple usage:
 * LookAheadObjectInputStream lookAheadObjectInputStream = new LookAheadObjectInputStream(new ByteArrayInputStream(someByteArray);
 * Collection<Class<? extends Serializable>> acceptedClasses = new ArrayList<Class<? extends Serializable>>(3);
            acceptedClasses.add(X509Certificate.class);
            lookAheadObjectInputStream.setAcceptedClasses(acceptedClasses);
 * lookAheadObjectInputStream.setMaxObjects(1);
 * X509Certificate certificate = (X509Certificate) lookAheadObjectInputStream.readObject(); //If serialized object is not of the type X509Certificate SecurityException will be thrown
 * 
 * @see LookAheadObjectInputStreamTest for more examples
 * 
 * @version $Id: LookAheadObjectInputStream.java 22806 2016-02-19 18:58:27Z marko $
 */
public class LookAheadObjectInputStream extends ObjectInputStream {

    static class ClassNameComparator implements Comparator<Class<?>>{
        @Override
        public int compare(Class<?> o1, Class<?> o2) {
            return o1.getName().compareTo(o2.getName());
        }
    }
    private Set<Class<?>> acceptedClasses = new TreeSet<Class<?>>(new ClassNameComparator());
    
    private boolean enabledSubclassing = false;
    private int maxObjects = 1;
    private boolean enabledMaxObjects = true;
    private int objCount = 0;

    public LookAheadObjectInputStream(InputStream inputStream) throws IOException {
        super(inputStream);
        enableResolveObject(true);
    }

    /**
     * @return set of accepted classes etc. Classes that are allowed to be read from this ObjectInputStream. This set can be modified with:
     *  @see LookAheadObjectInputStream#setAcceptedClassNames(Set<Class<?>> acceptedClassNames)
     */
    public Collection<Class<?>> getAcceptedClasses() {
        return acceptedClasses;
    }

    /**
     * @return true if class should be accepted if it extends super class directly or indirectly
     *          that is listed in accepted class names, false otherwise.
     */
    public boolean isEnabledSubclassing() {
        return enabledSubclassing;
    }

    /**
     * @param enabledSubclassing
     *      True if class should be accepted if it extends super class directly or indirectly
     *      that is listed in accepted class names, false otherwise.
     */
    public void setEnabledSubclassing(boolean enabledSubclassing) {
        this.enabledSubclassing = enabledSubclassing;
    }

    /**
     * Set accepted classes that can be deserialized using this LookAheadObjectInputStream.
     * Primitive types (boolean, char, int,...), their wrappers (Boolean, Character, Integer,...) and String class
     * are always accepted. All other classes have to be specified with setAcceptedClassName*
     * @param acceptedClasses
     *      Collection of class names that will be accepted for deserializing readObject. Default: null
     */
    public void setAcceptedClasses(Collection<Class<? extends Serializable>> acceptedClasses) {
        this.acceptedClasses = new TreeSet<Class<?>>(new ClassNameComparator());
        this.acceptedClasses.addAll(acceptedClasses);
    }

    /**
     * Get maximum amount of objects that can be read with this LookAheadObjectInputStream.
     * @return 
     *      maximum amount of objects that can be read. Default: 1
     */
    public int getMaxObjects() {
        return maxObjects;
    }

    /**
     * Set maximum amount of objects that can be read with this LookAheadObjectInputStream.
     * This method will also reset internal counter for read objects.
     * @param 
     *      maxObjects maximum amount of objects that can be read. Default: 1
     */
    public void setMaxObjects(int maxObjects) {
        objCount = 0;
        this.maxObjects = maxObjects;
    }

    /**
     * Overriding resolveObject to limit amount of objects that could be read
     */
    @Override
    protected Object resolveObject(Object obj) throws IOException {
        if (enabledMaxObjects && ++objCount > maxObjects) {
            throw new SecurityException("Attempt to deserialize too many objects from stream. Limit is " + maxObjects);
        }
        Object object = super.resolveObject(obj);
        return object;
    }

    /**
     * Overrides resolveClass to check Class type of serialized object before deserializing readObject.
     * @throws SecurityException if serialized object is not one of following:
     *      1) a String
     *      2) a java primitive data type or its corresponding class wrapper
     *      3) in the list of accepted classes
     *      4) extends class from the list of accepted classes (if enabledSubclassing==true) 
     */
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        Class<?> resolvedClass = super.resolveClass(desc); //can be an array
        Class<?> resolvedClassType = resolvedClass.isArray() ? resolvedClass.getComponentType() : resolvedClass;
        if (resolvedClassType.equals(String.class) || resolvedClassType.isPrimitive() || Boolean.class.isAssignableFrom(resolvedClassType)
                || Number.class.isAssignableFrom(resolvedClassType) || Character.class.isAssignableFrom(resolvedClassType)) {
            return resolvedClass;
        } else if (acceptedClasses != null && !acceptedClasses.isEmpty()) {
            if (acceptedClasses.contains(resolvedClassType)) {
                return resolvedClass;
            } else if (enabledSubclassing) {
                Class<?> superclass = resolvedClassType.getSuperclass();
                while (superclass != null) {
                    if (acceptedClasses.contains(superclass)) {
                        return resolvedClass;
                    }
                    superclass = superclass.getSuperclass();
                }
            }
        }
        throw new SecurityException("Unauthorized deserialization attempt for type: " + desc);
    }

    /**
     * @return true if checking for max objects is enabled, false otherwise
     */
    public boolean isEnabledMaxObjects() {
        return enabledMaxObjects;
    }

    /** Enable or disable checking for max objects that can be read.
     *  This method will also reset internal counter for read objects.
     * @param enabledMaxObjects true or false
     */
    public void setEnabledMaxObjects(boolean enabledMaxObjects) {
        objCount = 0;
        this.enabledMaxObjects = enabledMaxObjects;
    }

}
