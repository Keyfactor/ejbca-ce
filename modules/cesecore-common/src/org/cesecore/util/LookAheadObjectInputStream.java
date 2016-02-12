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
import java.util.Arrays;
import java.util.Collection;

/** Can be used instead of ObjectInputStream to safely deserialize(readObject) unverified serialized java object. 
 * 
 * Simple usage:
 * LookAheadObjectInputStream lookAheadObjectInputStream = new LookAheadObjectInputStream(new ByteArrayInputStream(someByteArray);
 * lookAheadObjectInputStream.setAcceptedClassNames(Arrays.asList(X509Certificate.class.getName()));
 * lookAheadObjectInputStream.setMaxObjects(1);
 * X509Certificate certificate = (X509Certificate) lookAheadObjectInputStream.readObject(); //If serialized object is not of the type X509Certificate SecurityException will be thrown
 * 
 * @see LookAheadObjectInputStreamTest for more examples
 */
public class LookAheadObjectInputStream extends ObjectInputStream {

    private Collection<String> acceptedClassNames;
    private int maxObjects = 1;
    private boolean enabledMaxObjects = true;
    private int objCount = 0;

    public LookAheadObjectInputStream(InputStream inputStream) throws IOException {
        super(inputStream);
        enableResolveObject(true);
    }

    public Collection<String> getAcceptedClassNames() {
        return acceptedClassNames;
    }

    /**
     * Set accepted class names that can be deserialized using this LookAheadObjectInputStream.
     * Primitive types (boolean, char, int,...), their wrappers (Boolean, Character, Integer,...) and String class
     * are always accepted. All other classes have to be specified with setAcceptedClassName*
     * @param acceptedClassNames
     *      Collection of class names that will be accepted for deserializing readObject. Default: null
     */
    public void setAcceptedClassNames(Collection<String> acceptedClassNames) {
        this.acceptedClassNames = acceptedClassNames;
    }

    /**
     * Set accepted class name that can be deserialized using this LookAheadObjectInputStream.
     * @param acceptedClassName
     *      class name that will be accepted for deserialization. Default: null
     * @see LookAheadObjectInputStream#setAcceptedClassNames(Collection<String> acceptedClassNames)
     */
    public void setAcceptedClassName(String acceptedClassName) {
        setAcceptedClassNames(Arrays.asList(acceptedClassName));
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
        if (enabledMaxObjects && ++objCount > maxObjects){
            throw new SecurityException("Attempt to deserialize too many objects from stream. Limit is " + maxObjects);
        }
        Object object = super.resolveObject(obj);
        return object;
    }

    /**
     * Overriding resolveClass to check Class type of serialized object before deserializing readObject.
     */
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        Class<?> resolvedClass = super.resolveClass(desc); //can be an array
        Class<?> resolvedClassType = resolvedClass.isArray() ? resolvedClass.getComponentType() : resolvedClass;
        if (resolvedClassType.equals(String.class) ||
            resolvedClassType.isPrimitive() ||
            Boolean.class.isAssignableFrom(resolvedClassType) ||
            Number.class.isAssignableFrom(resolvedClassType) ||
            Character.class.isAssignableFrom(resolvedClassType) ||
            acceptedClassNames != null && acceptedClassNames.contains(resolvedClassType.getName())) {
            return resolvedClass;
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
