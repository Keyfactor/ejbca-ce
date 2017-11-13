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
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.commons.lang.SerializationUtils;
import org.apache.commons.lang.StringUtils;
import org.cesecore.util.Base64;

/**
 * Allows creation of dynamic properties for display in the UI.
 *
 * @version $Id$
 */
public class DynamicUiProperty<T extends Serializable> implements Serializable, Cloneable {

    private static final long serialVersionUID = 1L;

    private String name;
    private T defaultValue;
    private List<T> values = new ArrayList<>();
    private Collection<T> possibleValues;
    private DynamicUiPropertyCallback propertyCallback = DynamicUiPropertyCallback.NONE;
    private Class<? extends Serializable> type;
    private DynamicUiPropertyValidator<T> validator = null;

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
        if (defaultValue != null) {
            this.type = defaultValue.getClass();
        }
    }

    public DynamicUiProperty(final String name, final T defaultValue) {
        this.name = name;
        this.defaultValue = defaultValue;
        this.values.add(defaultValue);
        this.possibleValues = null;
        if (defaultValue != null) {
            this.type = defaultValue.getClass();
        }
    }

    /**
     * Copy constructor for DynamicUiProperty objects
     * @param original the original property
     */
    @SuppressWarnings("unchecked")
    public DynamicUiProperty(final DynamicUiProperty<T> original) {
        this.name = original.getName();
        this.defaultValue = original.getDefaultValue();
        this.setHasMultipleValues(original.getHasMultipleValues());
        try {
            if (!original.hasMultipleValues) {
                setValue((T) SerializationUtils.clone(original.getValue()));
            } else {
                List<T> clonedValues = new ArrayList<>();
                for (T value : original.getValues()) {
                    clonedValues.add((T) SerializationUtils.clone(value));
                }
                setValues(clonedValues);
            }
        } catch (PropertyValidationException e) {
            throw new IllegalArgumentException("Invalid value was intercepted in copy constructor, which should not happen.", e);
        }
        this.possibleValues = original.getPossibleValues();
        this.propertyCallback = original.getPropertyCallback();
        this.type = original.getType();
        this.validator = original.validator;
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

    /**
     *
     * @return string representation of the value (for example the string '1' for the Int value 1. Value is retrieved inside as getValue().
     */
    public String getValueAsString() {
        Serializable value = getValue();
        String ret = "";
        if (value instanceof MultiLineString) {
            ret = ((MultiLineString) value).getValue();
        } else if (value instanceof String) {
            ret = (String) value;
        } else if (value instanceof Integer) {
            try {
                ret = ((Integer)value).toString();
            } catch (NumberFormatException e) {}
        } else if (value instanceof Long) {
            try {
                ret = ((Long)value).toString();
            } catch (NumberFormatException e) {}
        } else if (value instanceof Boolean) {
            ret = ((Boolean) value).toString();
        } else if (value instanceof Float) {
            try {
                ret = ((Float)value).toString();
            } catch (NumberFormatException e) { }
        } else if (value instanceof RadioButton) {
            ret = ((RadioButton)value).getLabel();
        }
        return ret;
    }

    public String getName() {
        return name;
    }

    /**
     *
     * @return the type class of this property, based on the default value. If the default was null, then the type has to be set explicitly.
     */
    public Class<? extends Serializable> getType() {
        return type;
    }

    public void setType(final Class<? extends Serializable> type) {
        this.type = type;
    }

    public T getDefaultValue() {
        return defaultValue;
    }

    public void setDefaultValue(T defaultValue) {
        this.defaultValue = defaultValue;
    }

    public List<T> getValues() {
        if (!hasMultipleValues) {
            throw new IllegalStateException("Attempted to draw multiple values from a dynamic property with a single value.");
        }
        return values;
    }

    public T getValue() {
        if (hasMultipleValues) {
            throw new IllegalStateException("Attempted to draw single value from a dynamic property with multiple value.");
        }
        return values.get(0);
    }

    public List<String> getPossibleValuesAsStrings() {
        List<String> pvs = new ArrayList<String>();

        if(StringUtils.equals(type.getSimpleName(), RadioButton.class.getSimpleName())) {
            for(T pv : getPossibleValues()) {
                RadioButton rb = (RadioButton) pv;
                pvs.add(rb.getLabel());
            }
        } else {
            for(T pv : getPossibleValues()) {
                pvs.add(pv.toString());
            }
        }
        return pvs;
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

    /**
     *
     * @param object a value for this property
     * @throws PropertyValidationException if the value failed validation
     */
    public void setValue(T object) throws PropertyValidationException {
        if (hasMultipleValues) {
            throw new IllegalStateException("Attempted to set multiple values from a dynamic property with single value.");
        }
        if (object == null) {
            this.values = new ArrayList<>(Arrays.asList(defaultValue));
        } else {
            if(validator != null) {
                validator.validate(object);
            }
            if (possibleValues != null) {
                for (final T possibleValue : possibleValues) {
                    if (possibleValue.equals(object)) {
                        this.values = new ArrayList<>(Arrays.asList(object));
                        return;
                    }
                }
                throw new IllegalArgumentException(object + " is not in the list of approved objects.");
            } else {
                this.values = new ArrayList<>(Arrays.asList(object));
            }
        }
    }

    /**
     *
     * @param objects a list of values to set
     * @throws PropertyValidationException if any one of the values didn't pass validation
     */
    public void setValues(List<T> objects) throws PropertyValidationException {
        if (!hasMultipleValues) {
            throw new IllegalStateException("Attempted to set single value from a dynamic property with multiple values.");
        }
        if (objects == null || objects.isEmpty()) {
            this.values = new ArrayList<>(Arrays.asList(defaultValue));
        } else {
            if (possibleValues != null && !possibleValues.isEmpty()) {
                final List<T> values = new ArrayList<>();
                OBJECT_LOOP: for (final T object : objects) {
                    if(validator != null) {
                        validator.validate(object);
                    }
                    for (final T possibleValue : possibleValues) {
                        if (possibleValue.equals(object)) {
                            values.add(object);
                            continue OBJECT_LOOP;
                        }
                    }
                    throw new IllegalArgumentException(object + " is not in the list of approved objects.");
                }
                this.values = values;
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

    public String getAsEncodedValue(final Serializable possibleValue) {
        return new String(Base64.encode(getAsByteArray(possibleValue), false));
    }

    private List<String> getAsEncodedValues(final List<T> list) {
        final List<String> encodedValues = new ArrayList<>();
        for (final Serializable possibleValue : list) {
            encodedValues.add(new String(Base64.encode(getAsByteArray(possibleValue), false)));
        }
        return encodedValues;
    }

    @SuppressWarnings("unchecked")
    public void setEncodedValue(String encodedValue) {
        try {
            setValue((T) getAsObject(Base64.decode(encodedValue.getBytes())));
        } catch (PropertyValidationException e) {
            throw new IllegalArgumentException("Invalid value was intercepted from an encoded source, which should not happen.", e);
        }
    }

    @SuppressWarnings("unchecked")
    /**
     *
     * @param encodedValues a list of encoded values
     * @throws PropertyValidationException if any one of the values doesn't pass validation
     */
    public void setEncodedValues(List<String> encodedValues) throws PropertyValidationException {
        List<T> decodedValues = new ArrayList<>();
        for (String encodedValue : encodedValues) {
            decodedValues.add((T) getAsObject(Base64.decode(encodedValue.getBytes())));
        }
        setValues(decodedValues);
    }

    @SuppressWarnings("unchecked")
    /**
     * @param object the value to set
     *
     */
    public void setValueGeneric(Serializable object) {
        if (object == null) {
            this.values = new ArrayList<>(Arrays.asList(defaultValue));
        } else {
            if(validator != null) {
                try {
                    validator.validate((T) object);
                } catch (PropertyValidationException e) {
                    throw new IllegalStateException("Generic setter is normally only used internally, so an incorrect value should not be passed.", e);
                }
            }
            this.values = new ArrayList<>(Arrays.asList((T) object));
        }
    }

    @SuppressWarnings("unchecked")
    /**
     *
     * @param list a list of objects
     *
     */
    public void setValuesGeneric(List<? extends Serializable> list) {
        if (list == null || list.isEmpty()) {
            this.values = new ArrayList<>(Arrays.asList(defaultValue));
        } else {
            final List<T> values = new ArrayList<>();
            for (final Serializable object : list) {
                if(validator != null) {
                    try {
                        validator.validate((T) object);
                    } catch (PropertyValidationException e) {
                        throw new IllegalStateException("Generic setter is normally only used internally, so an incorrect value should not be passed.", e);
                    }
                }
                values.add((T) object);
            }
            this.values = values;
        }
    }

    /** @return deep cloned version of this object */
    @SuppressWarnings("unchecked")
    @Override
    public DynamicUiProperty<T> clone() {
        return (DynamicUiProperty<T>) getAsObject(getAsByteArray(this));
    }

    private byte[] getAsByteArray(final Serializable o) {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final ObjectOutputStream oos = new ObjectOutputStream(baos);) {
            oos.writeObject(o);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return baos.toByteArray();
    }

    public static Serializable getAsObject(String encodedValue) {
        return getAsObject(Base64.decode(encodedValue.getBytes()));
    }

    private static Serializable getAsObject(final byte[] bytes) {
        try (final ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));) {
            return (Serializable) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
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

    /** Returns the current value, like getValue, but has a workaround for JSF bug with ui:repeat and rendered. See ECA-5342 */
    @SuppressWarnings("unchecked")
    public T getJsfBooleanValue() {
        if (hasMultipleValues || type != Boolean.class) {
            // In this case, JSF made a spurious call and will throw away the return value, but it must be of expected type (boolean)
            return (T)Boolean.FALSE;
        } else {
            return getValue();
        }
    }

    /** Sets the value, by calling setValue. Needed for the getJsfBooleanValue workaround
     * @throws PropertyValidationException if the value failed validation
     */
    public void setJsfBooleanValue(final T newValue) throws PropertyValidationException {
        setValue(newValue);
    }

    public void setValidator(DynamicUiPropertyValidator<T> validator) {
        this.validator = validator;
    }

    public String getValidatorType() {
        if (validator != null) {
            return validator.getValidatorType();
        } else {
            return "dummyValidator";
        }
    }
}
