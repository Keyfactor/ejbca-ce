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
package org.cesecore.keybind;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Arrays;

import org.cesecore.util.Base64;

/**
 * Holds information about implementation specific properties of an InternalKeyBinding.
 * 
 * @version $Id$
 */
public class InternalKeyBindingProperty<T extends Serializable> implements Serializable, Cloneable {

    private static final long serialVersionUID = 1L;

    private String name;
    private T defaultValue;
    private T value;
    private T[] possibleValues;

    /** Constructor required by Serializable */
    public InternalKeyBindingProperty() {
    }

    /** Constructor. Note the T must implement toString() . */
    public InternalKeyBindingProperty(final String name, final T defaultValue, final T... possibleValues) {
        this.name = name;
        this.defaultValue = defaultValue;
        this.value = defaultValue;
        if (possibleValues.length == 0) {
            this.possibleValues = null;
        } else {
            this.possibleValues = possibleValues;
        }
    }

    /**
     * Returns a value of type T from a string. Limited to the basic java types {@link Integer}, {@link String}, {@link Boolean}, {@link Float},
     * {@link Long}
     * 
     * @param value the value to translate
     * @return and Object instantiated as T, or null if value was not of a usable class or was invalid for T
     */
    public Serializable valueOf(String value) {
        if (defaultValue instanceof String) {
            return value;
        } else if (defaultValue instanceof Integer) {
            try {
                return Integer.valueOf(value);
            } catch (NumberFormatException e) {
                return null;
            }
        } else if (defaultValue instanceof Long) {
            try {
                return Long.valueOf(value);
            } catch (NumberFormatException e) {
                return null;
            }
        } else if (defaultValue instanceof Boolean) {
            if (value.equals(Boolean.TRUE.toString()) || value.equals(Boolean.FALSE.toString())) {
                return Boolean.valueOf(value);
            }
        } else if (defaultValue instanceof Float) {
            try {
                return Float.valueOf(value);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    public String getName() {
        return name;
    }

    public Class<? extends Serializable> getType() {
        return defaultValue.getClass();
    }

    public T getDefaultValue() {
        return defaultValue;
    }

    public T getValue() {
        return value;
    }

    public T[] getPossibleValues() {
        return possibleValues;
    }

    public boolean isMultiValued() {
        return possibleValues != null;
    }

    public void setValue(T object) {
        if (object == null) {
            this.value = defaultValue;
        } else {
            if (possibleValues != null) {
                for (final T possibleValue : possibleValues) {
                    if (possibleValue.equals(object)) {
                        this.value = (T) object;
                        return;
                    }
                }
                throw new RuntimeException(object + " is not one of " + Arrays.toString(possibleValues));
            } else {
                this.value = (T) object;
            }
        }
    }

    public String getEncodedValue() {
        return getAsEncodedValue(getValue());
    }

    @SuppressWarnings("unchecked")
    public String getAsEncodedValue(Serializable possibleValue) {
        return new String(Base64.encode(getAsByteArray((T) possibleValue), false));
    }

    @SuppressWarnings("unchecked")
    public void setEncodedValue(String encodedValue) {
        setValue((T) getAsObject(Base64.decode(encodedValue.getBytes())));
    }

    @SuppressWarnings("unchecked")
    public void setValueGeneric(Serializable object) {
        if (object == null) {
            this.value = defaultValue;
        } else {
            this.value = (T) object;
        }
    }

    /** @return deep cloned version of this object */
    @SuppressWarnings("unchecked")
    @Override
    public InternalKeyBindingProperty<T> clone() {
        return (InternalKeyBindingProperty<T>) getAsObject(getAsByteArray(this));
    }

    private byte[] getAsByteArray(Serializable o) {
        try {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(o);
            oos.close();
            return baos.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private Serializable getAsObject(byte[] bytes) {
        try {
            final ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
            final Object o = ois.readObject();
            ois.close();
            return (Serializable) o;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
