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
package org.cesecore.util.ui;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.cesecore.util.Base64;

/**
 * Allows creation of dynamic properties for display in the UI. 
 * 
 * @version $Id$
 */
public class DynamicUiProperty<T extends Serializable> implements Serializable, Cloneable {

    private static final long serialVersionUID = 1L;
    //private static final Logger log = Logger.getLogger(DynamicUiProperty.class);

    private String name;
    private T defaultValue;
    private List<T> values = new ArrayList<>();
    private Collection<T> possibleValues;
    private DynamicUiPropertyCallback propertyCallback = DynamicUiPropertyCallback.NONE;
    /**
     * Denotes whether this property can have multiple values. 
     */
    private boolean hasMultipleValues = false;

    /** Constructor required by Serializable */
    public DynamicUiProperty() {
    }

    /**
     * Constructor. Note the T must implement toString().
     * 
     * @param name The name of this property, for display in the UI
     * @param defaultValue the default value, if any.
     * @param possibleValues a Collection of possible values. If set to null no validation will be performed, if set to an empty list then values 
     *        are presumed to be set at runtime. 
     */
    public DynamicUiProperty(final String name, final T defaultValue, final Collection<T> possibleValues) {
        this.name = name;
        this.defaultValue = defaultValue;
        this.values.add(defaultValue);
        this.possibleValues = possibleValues;
    }
    
    public DynamicUiProperty(final String name, final T defaultValue) {
        this.name = name;
        this.defaultValue = defaultValue;
        this.values.add(defaultValue);
        this.possibleValues = null;
    }

    /**
     * Copy constructor for DynamicUiProperty objects
     * @param original the original property
     */
    public DynamicUiProperty(final DynamicUiProperty<T> original) {
        this.name = original.getName();
        this.defaultValue = original.getDefaultValue();
        this.setHasMultipleValues(original.getHasMultipleValues());
        if(!original.hasMultipleValues) {
            setValue(original.getValue()); 
        } else {
            setValues(original.getValues());
        }
        this.possibleValues = original.getPossibleValues();
        this.propertyCallback = original.getPropertyCallback();
    }
    
    /**
     * Returns a value of type T from a string. Limited to the basic java types {@link Integer}, {@link String}, {@link Boolean}, {@link Float},
     * {@link Long}
     * 
     * @param value the value to translate
     * @return and Object instantiated as T, or null if value was not of a usable class or was invalid for T
     */
    public Serializable valueOf(String value) {
        if (defaultValue instanceof MultiLineString) {
            return new MultiLineString(value);
        } else if (defaultValue instanceof String) {
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
    
    public List<T> getValues() {
        if(!hasMultipleValues) {
            throw new IllegalStateException("Attempted to draw multiple values from a dynamic property with a single value.");
        }
        return values;
    }

    public T getValue() {
        if(hasMultipleValues) {
            throw new IllegalStateException("Attempted to draw single value from a dynamic property with multiple value.");
        }
        return values.get(0);
    }

    public Collection<T> getPossibleValues() {
        return possibleValues;
    }
    
    @SuppressWarnings("unchecked")
    public void setPossibleValues(Collection<? extends Serializable> collection) {
        this.possibleValues = (Collection<T>) collection;
    }


    public boolean isMultiValued() {
        return possibleValues != null;
    }

    public void setValue(T object) {
        if(hasMultipleValues) {
            throw new IllegalStateException("Attempted to set multiple values from a dynamic property with single value.");
        }
        if (object == null) {
            values.clear();
            values.add(defaultValue);
        } else {
            if (possibleValues != null) {
                for (final T possibleValue : possibleValues) {
                    if (possibleValue.equals(object)) {
                        values.clear();
                        values.add((T) object);
                        return;
                    }
                }
                throw new IllegalArgumentException(object + " is not in the list of approved objects.");
            } else {
                values.clear();
                values.add((T) object);
            }
        }
    }
    
    public void setValues(List<T> objects) {
        if(!hasMultipleValues) {
            throw new IllegalStateException("Attempted to set single value from a dynamic property with multiple values.");
        }
        if (objects == null || objects.isEmpty()) {
            this.values.set(0, defaultValue);
        } else {
            if (possibleValues != null && !possibleValues.isEmpty()) {
                this.values.clear();
                OBJECT_LOOP: for (final T object : objects) {
                    for (final T possibleValue : possibleValues) {
                        if (possibleValue.equals(object)) {
                            this.values.add((T) object);
                            continue OBJECT_LOOP;
                        }
                    }
                    throw new IllegalArgumentException(object + " is not in the list of approved objects.");
                }

            } else {
                this.values = objects;
            }
        }
    }

    public String getEncodedValue() {
        return getAsEncodedValue(getValue());
    }
    
    public List<String> getEncodedValues() {
        return getAsEncodedValues(getValues());
    }

    @SuppressWarnings("unchecked")
    public String getAsEncodedValue(Serializable possibleValue) {
        return new String(Base64.encode(getAsByteArray((T) possibleValue), false));
    }
    
    @SuppressWarnings("unchecked")
    private List<String> getAsEncodedValues(List<T> list) {
        List<String> encodedValues = new ArrayList<>();
        for(Serializable possibleValue : list)
        {
            encodedValues.add(new String(Base64.encode(getAsByteArray((T) possibleValue), false)));
        }
        return encodedValues;
    }

    @SuppressWarnings("unchecked")
    public void setEncodedValue(String encodedValue) {
        setValue((T) getAsObject(Base64.decode(encodedValue.getBytes())));
    }
    
    @SuppressWarnings("unchecked")
    public void setEncodedValues(List<String> encodedValues) {
        List<T> decodedValues = new ArrayList<>();
        for (String encodedValue : encodedValues) {
            decodedValues.add((T) getAsObject(Base64.decode(encodedValue.getBytes())));
        }
        setValues(decodedValues);
    }

    @SuppressWarnings("unchecked")
    public void setValueGeneric(Serializable object) {
        if (object == null) {
            this.values.clear();
            this.values.add(defaultValue);
        } else {
            this.values.clear();
            this.values.add((T) object);
        }
    }
    
    @SuppressWarnings("unchecked")
    public void setValuesGeneric(List<? extends Serializable> list) {
        if (list == null || list.isEmpty()) {
            this.values.clear();
            this.values.add(defaultValue);
        } else {
            this.values.clear();
            for (Serializable object : list) {
                this.values.add((T) object);
            }
        }
    }

    /** @return deep cloned version of this object */
    @SuppressWarnings("unchecked")
    @Override
    public DynamicUiProperty<T> clone() {
        return (DynamicUiProperty<T>) getAsObject(getAsByteArray(this));
    }

    private byte[] getAsByteArray(Serializable o) {
        try {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(o);
            oos.close();
            return baos.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private Serializable getAsObject(byte[] bytes) {
        try {
            final ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
            final Object o = ois.readObject();
            ois.close();
            return (Serializable) o;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public DynamicUiPropertyCallback getPropertyCallback() {
        return propertyCallback;
    }

    public void setPropertyCallback(DynamicUiPropertyCallback propertyCallback) {
        this.propertyCallback = propertyCallback;
    }

    /**
     * @return true if this property can have multiple values. 
     */
    public boolean getHasMultipleValues() {
        return hasMultipleValues;
    }

    public void setHasMultipleValues(boolean hasMultipleValues) {
        this.hasMultipleValues = hasMultipleValues;
    }
}
