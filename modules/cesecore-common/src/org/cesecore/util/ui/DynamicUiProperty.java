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
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
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

    /** Literal for list separator. */
    public static final String LIST_SEPARATOR = ";";

    /** Literal for no rendering. */
    public static final String RENDER_NONE = "none";

    /** Literal for rendering hint for labels. */
    public static final String RENDER_LABEL = "label";

    /** Literal for rendering hint for text fields. */
    public static final String RENDER_TEXTFIELD = "textfield";

    /** Literal for rendering hint for text areas. */
    public static final String RENDER_TEXTAREA = "textarea";

    /** Literal for rendering hint for check boxes. */
    public static final String RENDER_CHECKBOX = "checkbox";

    /** Literal for rendering hint for buttons. */
    public static final String RENDER_BUTTON = "button";

    /** Literal for rendering hint for text fields. */
    public static final String RENDER_SELECT_ONE = "selectone";

    /** Literal for rendering hint for text fields. */
    public static final String RENDER_SELECT_MANY = "selectmany";

    /** Literal for rendering hint for file chooser. */
    public static final String RENDER_FILE_CHOOSER = "filechooser";

    /** The name (key) of the property. */
    private String name;

    /** Default value or null. */
    private T defaultValue;

    /** Property values (or value at index 0). */
    private List<T> values = (List<T>) Collections.synchronizedList(new ArrayList<T>());

    /** Value range or null. */
    private Collection<T> possibleValues;

    /** If the UI widget is supposed to be filled with a value. */
    private boolean required = false;

    /** If the UI widget is supposed to be disabled. */
    private boolean disabled = false;

    /** If the value has to be stored in the domain object properties. */
    private boolean transientValue = false;

    /** If a domain object property is stored as semi-colon separated string instead of {@link java.util.List}. */
    private boolean saveListAsString = false;

    /** Hint for widget rendering. */;
    private String renderingHint;

    /** True if I18N labels has to be rendered. */
    private boolean labeled = false;

    /** List of I18N keys / labels if available. */
    private Map<?,String> labels = new LinkedHashMap<Object,String>();

    /** Flag to indicate that the property is displayed as label in the label column only (there will be no validation if available, etc.).*/
    private boolean labelOnly = false;

    /** Action callback. */
    private DynamicUiActionCallback actionCallback;

    /** Property callback (default: NONE). */
    private DynamicUiPropertyCallback propertyCallback = DynamicUiPropertyCallback.NONE;

    /** Property type. */
    private Class<? extends Serializable> type;

    /** Field validator (will be applied if not null). */
    private DynamicUiPropertyValidator<T> validator = null;

    /** Reference to the holder object (implements coupling to components). */
    private DynamicUiModel dynamicUiModel;

    /** Denotes whether this property can have multiple values. */
    private boolean hasMultipleValues = false;

    /**
     * Constructor required by java.lang.Serializable.
     */
    public DynamicUiProperty() {
    }

    /**
     * Constructs a dynamic UI property rendered as a simple label in the UI.
     *
     * @param name the name of this property, for display in the UI
     */
    @SuppressWarnings("unchecked")
    public DynamicUiProperty(final String name) {
        this.name = name;
        this.type = String.class;
        this.defaultValue = (T) name;
        synchronized (values) {
            this.values.add((T) name);
        }
        this.possibleValues = null;
        setLabelOnly(true);
        setTransientValue(true);
    }

    /**
     * Constructor. Note the T must implement toString().
     *
     * @param name the name of this property, for display in the UI.
     * @param defaultValue the default value, if any.
     */
    public DynamicUiProperty(final String name, final T defaultValue) {
        this.name = name;
        this.defaultValue = defaultValue;
        synchronized (values) {
            this.values.add(defaultValue);
        }
        this.possibleValues = null;
        if (defaultValue != null) {
            this.type = defaultValue.getClass();
        }
    }

    /**
     * Constructor. Note the T must implement toString().
     *
     * @param type Class type (as workaround for forgotten parameter type at runtime).
     * @param name the name of this property, for display in the UI.
     * @param defaultValue the default value, if any.
     */
    @SuppressWarnings("unchecked")
    public DynamicUiProperty(final Class<T> type, final String name, final T defaultValue) {
        this.name = name;
        this.defaultValue = defaultValue;
        synchronized (values) {
            if (String.class.equals(type) && defaultValue != null && ((String) defaultValue).contains(LIST_SEPARATOR)) {
                for (String value : StringUtils.split((String) defaultValue, LIST_SEPARATOR)) {
                    this.values.add((T) value);
                }
            } else {
                this.values.add(defaultValue);
            }  
        }    
        this.possibleValues = null;
        this.type = type;
        if (File.class.getName().equals(getType().getName())) {
            setRenderingHint(RENDER_FILE_CHOOSER);
        }
    }

    /**
     * Constructor. Note the T must implement toString().
     *
     * @param name the name of this property, for display in the UI.
     * @param defaultValue the default value, if any.
     * @param possibleValues a Collection of possible values. If set to null no validation will be performed, if set to an empty list then values
     *        are presumed to be set at runtime.
     */
    public DynamicUiProperty(final String name, final T defaultValue, final Collection<T> possibleValues) {
        this(name, defaultValue);
        this.possibleValues = possibleValues;
    }

    /**
     * Constructor. Note the T must implement toString().
     *
     * @param type Class type (as workaround for forgotten parameter type at runtime).
     * @param name The name of this property, for display in the UI
     * @param defaultValue the default value, if any.
     * @param possibleValues a Collection of possible values. If set to null no validation will be performed, if set to an empty list then values
     *        are presumed to be set at runtime.
     */
    public DynamicUiProperty(final Class<T> type, final String name, final T defaultValue, final Collection<T> possibleValues) {
        this(type, name, defaultValue);
        this.possibleValues = possibleValues;
    }

    /**
     * Copy constructor for DynamicUiProperty objects
     * @param original the original property
     */
    @SuppressWarnings("unchecked")
    public DynamicUiProperty(final DynamicUiProperty<T> original) {
        this.name = original.getName();
        this.type = original.getType();
        this.required = original.isRequired();
        this.renderingHint = original.getRenderingHint();
        this.labelOnly = original.isLabelOnly();
        this.labeled = original.isI18NLabeled();
        this.defaultValue = original.getDefaultValue();
        this.setHasMultipleValues(original.getHasMultipleValues());
        try {
            if (!original.getHasMultipleValues()) {
                setValue((T) SerializationUtils.clone(original.getValue()));
            } else {
                final List<T> clonedValues = new ArrayList<>();
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
        this.actionCallback = original.getActionCallback();
        this.validator = original.validator;
        this.disabled = original.isDisabled();
        this.dynamicUiModel = original.getDynamicUiModel();
        this.transientValue = original.isTransientValue();
    }

    /**
     * Sets the dynamic UI model reference.
     *
     * @param dynamicUiModel the dynamic UI model reference.
     */
    public void setDynamicUiModel(final DynamicUiModel dynamicUiModel) {
        this.dynamicUiModel = dynamicUiModel;
    }

    /**
     * Gets the dynamic UI model reference.
     *
     * @return the dynamic UI model reference.
     */
    public DynamicUiModel getDynamicUiModel() {
        return dynamicUiModel;
    }

    /**
     * Returns a value of type T from a string. Limited to the basic java types {@link Integer}, {@link String}, {@link Boolean}, {@link Float},
     * {@link Long}
     *
     * @param value the value to translate
     * @return and Object instantiated as T, or null if value was not of a usable class or was invalid for T
     */
    public Serializable valueOf(String value) {
        // ECA-6320 Re-factor: New implementation uses constructor with type parameter (not only Generic Operator because this information is lost at runtime!).
        // The defaultValue of the old implementation MUST NOT be null, the one of the new can be!
        if (defaultValue instanceof MultiLineString) {
            return new MultiLineString(value);
        } else if (defaultValue instanceof String) {
            return value;
        } else if (defaultValue instanceof Boolean) {
            if (value.equals(Boolean.TRUE.toString()) || value.equals(Boolean.FALSE.toString())) {
                return Boolean.valueOf(value);
            }
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
        } else if (defaultValue instanceof BigInteger) {
            try {
                return new BigInteger(value);
            } catch (NumberFormatException e) {
                return null;
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
     * Gets a string representation of the value (for example the string '1' for the Integer with value 1. Value is retrieved inside as getValue()).
     * @return string the string representation.
     */
    public String getValueAsString() {
        Serializable value = getValue();
        String result = StringUtils.EMPTY;
        if (value instanceof MultiLineString) {
            result = ((MultiLineString) value).getValue();
        } else if (value instanceof String) {
            result = (String) value;
        } else if (value instanceof RadioButton) {
            result = ((RadioButton)value).getLabel();
        } else if (value instanceof Object) {
            result = ((Object) value).toString();
        }
        return result;
    }

    /**
     * Gets the name (or key) of the property.
     * @return the name.
     */
    public String getName() {
        return name;
    }

    /**
     * Gets if the UI widget is supposed to be filled with a value.
     * @return true if is required.
     */
    public boolean isRequired() {
        return required;
    }

    /**
     * Sets if the UI widget is supposed to be filled with a value.
     * @param required true if required.
     */
    public void setRequired(boolean required) {
        this.required = required;
    }

    /**
     * Gets if the UI widget is supposed to be disabled.
     * @return true if disabled.
     */
    public boolean isDisabled() {
        return disabled;
    }

    /**
     * Sets if the UI widget is supposed to be disabled.
     * @param disabled true if disabled.
     */
    public void setDisabled(boolean disabled) {
        this.disabled = disabled;
    }

    /**
     * Gets weather the value has to be stored in the domain objects properties.
     * @return true if transient.
     */
    public boolean isTransientValue() {
        return transientValue;
    }

    /**
     * Sets weather the value has to be stored in the domain objects properties.
     * @param transientValue true if transient.
     */
    public void setTransientValue(boolean transientValue) {
        this.transientValue = transientValue;
    }

    /**
     * Is set to true if I18N labels has to be rendered (mainly used in facelets).
     * @return true if I18N labels has to be rendered.
     */
    public boolean isI18NLabeled() {
        return labeled;
    }

    /**
     * Gets if only the label has to be rendered.
     * @return if the entry has to be rendered as label only (first column only).
     */
    public boolean isLabelOnly() {
        return labelOnly;
    }

    /**
     * Sets if only the label has to be rendered.
     * @param labelOnly true if the entry has to be rendered as label only (first column only)
     */
    public void setLabelOnly(boolean labelOnly) {
        this.labelOnly = labelOnly;
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

    /**
     * Gets the given value of type <T>.
     * @return the value.
     */
    public T getDefaultValue() {
        return defaultValue;
    }

    /**
     * Sets the given value of type <T>.
     * @param defaultValue the value.
     */
    public void setDefaultValue(T defaultValue) {
        this.defaultValue = defaultValue;
    }

    /**
     * Gets the list of current values.
     * @return the list.
     */
    public List<T> getValues() {
        if (!hasMultipleValues) {
            throw new IllegalStateException("Attempted to draw multiple values from a dynamic property with a single value for " + getName());
        }
        return values;
    }

    /**
     * Gets the current value.
     * @return the value.
     */
    public T getValue() {
        if (hasMultipleValues) {
            throw new IllegalStateException("Attempted to draw single value from a dynamic property with multiple value for " + getName());
        }
        return values.get(0);
    }

    public List<String> getPossibleValuesAsStrings() {
        final List<String> strings = new ArrayList<String>();
        for (final T possibleValue : getPossibleValues()) {
            strings.add(possibleValue.toString());
        }
        return strings;
    }

    public List<String> getValuesAsStrings() {
        final List<String> strings = new ArrayList<String>();
        for (final T value : getValues()) {
            strings.add(value.toString());
        }
        return strings;
    }

    /**
     * Gets a list of all possible values.
     * @return the list.
     */
    public Collection<T> getPossibleValues() {
        return possibleValues;
    }

    /**
     * Sets the list of possible values.
     * @param collection the collection of values.
     */
    @SuppressWarnings("unchecked")
    public void setPossibleValues(Collection<? extends Serializable> collection) {
        this.possibleValues = (Collection<T>) collection;
    }

    /**
     * Sets the current value of type <T>.
     * @param object a value for this property.
     * @throws PropertyValidationException if the validation of the value failed.
     */
    public void setValue(T object) throws PropertyValidationException {
        if (hasMultipleValues) {
            throw new IllegalStateException("Attempted to set multiple values from a dynamic property with single value.");
        }
        synchronized (values) {
            if (object == null) {
                this.values.clear();
                this.values.add(defaultValue);
            } else {
                if (validator != null) {
                    validator.validate(object);
                }
                if (possibleValues != null && !possibleValues.contains(object)) {
                    throw new IllegalArgumentException(object + " (class=" + object.getClass().getSimpleName()
                            + ") is not in the list of approved objects (class=" + possibleValues.getClass().getSimpleName() + "<"
                            + possibleValues.getClass().getSimpleName() + ">): " + possibleValues);
                }
                this.values.clear();
                this.values.add(object);
            }
        }
        if (dynamicUiModel != null) {
            dynamicUiModel.setProperty(name, this.values.get(0));
        }
    }

    /**
     * Sets the list of current values of type <T>.
     * @param objects a list of values to set.
     * @throws PropertyValidationException if any one of the values didn't pass validation.
     */
    public void setValues(List<T> objects) throws PropertyValidationException {
        if (!hasMultipleValues) {
            throw new IllegalStateException("Attempted to set single value from a dynamic property with multiple values.");
        }
        synchronized (values) {
            if (CollectionUtils.isEmpty(objects)) {
                this.values.clear();
                this.values.add(defaultValue);
            } else {
                if (!CollectionUtils.isEmpty(possibleValues)) {
                    final List<T> values = new ArrayList<T>();
                    for (final T object : objects) {
                        if (validator != null) {
                            validator.validate(object);
                        }
                        if (possibleValues.contains(object)) {
                            values.add(object);
                        } else {
                            throw new IllegalArgumentException(object + " (class=" + object.getClass().getSimpleName()
                                    + ") is not in the list of approved objects (class=" + possibleValues.getClass().getSimpleName() + "<"
                                    + possibleValues.getClass().getSimpleName() + ">): " + possibleValues);
                        }
                    }
                    this.values = values;
                } else {
                    this.values = objects;
                }
            }
        }
        if (dynamicUiModel != null) {
            dynamicUiModel.setProperty(name, StringUtils.join(this.values, LIST_SEPARATOR));
        }
    }

    /**
     * Gets the current value of type <T> as base 64 encoded string.
     * @return the base 64 encoded string.
     */
    public String getEncodedValue() {
        return getAsEncodedValue(getValue());
    }

    /**
     * Gets the list of current values of type <T> as list of base 64 encoded strings.
     * @return the list.
     */
    public List<String> getEncodedValues() {
        return getAsEncodedValues(getValues());
    }

    /**
     * Gets the base 64 encoded string of the value.
     * @param value the value.
     * @return the base 64 encoded string.
     */
    public String getAsEncodedValue(final Serializable value) {
        return new String(Base64.encode(getAsByteArray(value), false));
    }

    /**
     * Gets the list of base 64 encoded strings of the values.
     * @param list the list of values.
     * @return the list of base 64 encoded strings.
     */
    private List<String> getAsEncodedValues(final List<T> list) {
        final List<String> result = new ArrayList<>();
        for (final Serializable value : list) {
            result.add(new String(Base64.encode(getAsByteArray(value), false)));
        }
        return result;
    }

    /**
     * Sets the current value of type <T> by the given base 64 encoded string.
     * @param encodedValue the base 64 encoded value.
     */
    @SuppressWarnings("unchecked")
    public void setEncodedValue(final String encodedValue) {
        try {
            setValue((T) getAsObject(Base64.decode(encodedValue.getBytes())));
        } catch (PropertyValidationException e) {
            throw new IllegalArgumentException("Invalid value was intercepted from an encoded source, which should not happen.", e);
        }
    }

    /**
     * Sets the list of values of type <T> by the given list of base 64 encoded strings.
     * @param encodedValues a list of encoded values.
     * @throws PropertyValidationException if any one of the values doesn't pass validation.
     */
    @SuppressWarnings("unchecked")
    public void setEncodedValues(final List<String> encodedValues) throws PropertyValidationException {
        List<T> decodedValues = new ArrayList<>();
        for (String encodedValue : encodedValues) {
            decodedValues.add((T) getAsObject(Base64.decode(encodedValue.getBytes())));
        }
        setValues(decodedValues);
    }

    /**
     * Sets the current value of type <T>.
     * @param object the value.
     */
    @SuppressWarnings("unchecked")
    public void setValueGeneric(final Serializable object) {
        synchronized (values) {
            if (object == null) {
                this.values.clear();
                this.values.add(defaultValue);
            } else {
                if (validator != null) {
                    try {
                        validator.validate((T) object);
                    } catch (PropertyValidationException e) {
                        throw new IllegalStateException(
                                "Generic setter is normally only used internally, so an incorrect value should not be passed.", e);
                    }
                }
                this.values.clear();
                this.values.add((T) object);
            }
        }
    }

    /**
     * Sets the current value of type <T>.
     * @param object the value.
     */
    @SuppressWarnings("unchecked")
    public void setValueGenericIncludeNull(final Serializable object) {
        synchronized (values) {
            if (object == null) {
                this.values.clear();
                this.values.add((T) object);
            } else {
                if (validator != null) {
                    try {
                        validator.validate((T) object);
                    } catch (PropertyValidationException e) {
                        throw new IllegalStateException(
                                "Generic setter is normally only used internally, so an incorrect value should not be passed.", e);
                    }
                }
                this.values.clear();
                this.values.add((T) object);
            }
        }
    }

    /**
     * Sets the list of current values of type <T>.
     * @param list the list of values.
     *
     */
    @SuppressWarnings("unchecked")
    public void setValuesGeneric(final List<? extends Serializable> list) {
        synchronized (values) {
            if (CollectionUtils.isEmpty(list)) {

                this.values.clear();
                this.values.add(defaultValue);
            } else {
                final List<T> values = (List<T>) Collections.synchronizedList(new ArrayList<T>());
                for (final Serializable object : list) {
                    if (validator != null) {
                        try {
                            validator.validate((T) object);
                        } catch (PropertyValidationException e) {
                            throw new IllegalStateException(
                                    "Generic setter is normally only used internally, so an incorrect value should not be passed.", e);
                        }
                    }
                    values.add((T) object);
                }
                this.values = values;
            }
        }
    }

    /**
     * Creates a deep clone of this instance.
     * @return the new instance.
     */
    @SuppressWarnings("unchecked")
    @Override
    public DynamicUiProperty<T> clone() {
        return (DynamicUiProperty<T>) getAsObject(getAsByteArray(this));
    }

    /**
     * Gets the object a byte array stream.
     * @param o the object
     * @return the byte array.
     */
    private byte[] getAsByteArray(final Serializable o) {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final ObjectOutputStream oos = new ObjectOutputStream(baos);) {
            oos.writeObject(o);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return baos.toByteArray();
    }

    public static Serializable getAsObject(final String encodedValue) {
        return getAsObject(Base64.decode(encodedValue.getBytes()));
    }

    private static Serializable getAsObject(final byte[] bytes) {
        try (final ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));) {
            return (Serializable) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Gets the action callback.
     * @return the callback.
     */
    public DynamicUiActionCallback getActionCallback() {
        return actionCallback;
    }

    /**
     * Sets the action callback.
     * @param actionCallback the callback.
     */
    public void setActionCallback(final DynamicUiActionCallback actionCallback) {
        this.actionCallback = actionCallback;
    }

    /**
     * Gets the property call back.
     * @return the call back.
     */
    public DynamicUiPropertyCallback getPropertyCallback() {
        return propertyCallback;
    }

    /**
     * Sets the property call back.
     * @param propertyCallback the call back.
     */
    public void setPropertyCallback(final DynamicUiPropertyCallback propertyCallback) {
        this.propertyCallback = propertyCallback;
    }

    /**
     * Gets if the property is allowed to consist of multiple values
     * @return true if this property can have multiple values.
     */
    public boolean getHasMultipleValues() {
        return hasMultipleValues;
    }

    /**
     * Sets if the property is allowed to consist of multiple values (i.e. list, or LIST_SEPARATOR separated string).
     * @param hasMultipleValues true if the property may have multiple values.
     */
    public void setHasMultipleValues(final boolean hasMultipleValues) {
        this.hasMultipleValues = hasMultipleValues;
    }

    public boolean isMultiValued() {
        return possibleValues != null;
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

    /**
     * Sets the value, by calling setValue. Needed for the getJsfBooleanValue workaround.
     * @param newValue the new value of type <T>.
     * @throws PropertyValidationException if the value failed validation.
     */
    public void setJsfBooleanValue(final T newValue) throws PropertyValidationException {
        setValue(newValue);
    }

    /**
     * Sets the validator instance.
     * @param validator the validator.
     */
    public void setValidator(final DynamicUiPropertyValidator<T> validator) {
        this.validator = validator;
    }

    /**
     * Gets the validator type.
     * @return the validator type or "dummyValidator" if the validator is null.
     */
    public String getValidatorType() {
        if (validator != null) {
            return validator.getValidatorType();
        } else {
            return "dummyValidator";
        }
    }

    /**
     * Gets the map of I18N key / value pairs.
     * @return the list.
     */
    public Map<?,String> getLabels() {
        return labels;
    }

    /**
     * Sets the map of I18N key / value pairs.
     * @param labels the map.
     */
    public void setLabels(final Map<?,String> labels) {
        labeled = MapUtils.isNotEmpty(labels);
        this.labels = labels;
    }

    /**
     * Returns true if the property type is java.lang.Boolean (this method is used because of the lack of 'instanceof' operator in JSF EL).
     * @return true if the property type is java.lang.Boolean.
     */
    public boolean isBooleanType() {
        return Boolean.class.getName().equals(getType().getName());
    }

    /**
     * Returns true if the property type is java.lang.Integer (this method is used because of the lack of 'instanceof' operator in JSF EL).
     * @return true if the property type is java.lang.Integer.
     */
    public boolean isIntegerType() {
        return Integer.class.getName().equals(getType().getName());
    }

    /**
     * Returns true if the property type is java.lang.BigInteger (this method is used because of the lack of 'instanceof' operator in JSF EL).
     * @return true if the property type is java.lang.BigInteger.
     */
    public boolean isBigIntegerType() {
        return BigInteger.class.getName().equals(getType().getName());
    }

    /**
     * Returns true if the property type is java.lang.Long (this method is used because of the lack of 'instanceof' operator in JSF EL).
     * @return true if the property type is java.lang.Long.
     */
    public boolean isLongType() {
        return Long.class.getName().equals(getType().getName());
    }

    /**
     * Returns true if the property type is java.lang.FLoat (this method is used because of the lack of 'instanceof' operator in JSF EL).
     * @return true if the property type is java.lang.Float.
     */
    public boolean isFloatType() {
        return Float.class.getName().equals(getType().getName());
    }

    /**
     * Returns true if the property type is java.lang.String(this method is used because of the lack of 'instanceof' operator in JSF EL).
     * @return true if the property type is java.lang.String.
     */
    public boolean isStringType() {
        return String.class.getName().equals(getType().getName());
    }

    /**
     * Returns true if the property type is java.util.HashMap (this method is used because of the lack of 'instanceof' operator in JSF EL).
     * @return true if the property type is java.util.HashMap.
     */
    public boolean isMapType() {
        return TreeMap.class.getName().equals(getType().getName());
    }

    /**
     * Returns true if the property type is java.io.File (this method is used because of the lack of 'instanceof' operator in JSF EL).
     * @return true if the property type is java.io.File.
     */
    public boolean isFileType() {
        return File.class.getName().equals(getType().getName());
    }

    /**
     * Returns true if a check box should be rendered.
     * @return true or false.
     */
    public boolean isRenderCheckBox() {
        return isBooleanType();
    }

    /**
     * Temp. method to store java.util.List as LIST_SEPARATOR separated List of Strings (use for PublicKeyBlacklistKeyValidator only at the time).
     * @return true if the list of Strings has to be stored as string.
     */
    public boolean isSaveListAsString() {
        return saveListAsString;
    }

    /**
     * Temp. method to store java.util.List as LIST_SEPARATOR separated List of Strings (use for PublicKeyBlacklistKeyValidator only at the time).
     * @param saveListAsString true if the list of Strings has to be stored as string.
     */
    public void setSaveListAsString(boolean saveListAsString) {
        this.saveListAsString = saveListAsString;
    }

    /**
     * Sets the rendering hint ((see {@link #RENDER_NONE}, {@link #RENDER_LABEL}, {@link #RENDER_CHECKBOX}, {@link #RENDER_TEXTFIELD},
     * {@link #RENDER_SELECT_ONE} or {@link #RENDER_SELECT_MANY})).
     * @param renderingHint the rendering hint.
     */
    public void setRenderingHint(final String renderingHint) {
        this.renderingHint = renderingHint;
    }

    /**
     * Gets the rendering hint ((see {@link #RENDER_NONE}, {@link #RENDER_LABEL}, {@link #RENDER_CHECKBOX}, {@link #RENDER_TEXTFIELD},
     * {@link #RENDER_SELECT_ONE} or {@link #RENDER_SELECT_MANY})).
     * @return the rendering hint.
     */
    public String getRenderingHint() {
        // User explicit set rendering hint.
        if (renderingHint != null) {
            return renderingHint;
        }
        if (isLabelOnly()) {
            return RENDER_NONE;
        }
        String result = RENDER_TEXTFIELD;
        // Multiple values always use drop-down boxes.
        if (getHasMultipleValues()) {
            result =  RENDER_SELECT_MANY;
        } else {
            if (!Boolean.class.equals(getType())) {
                // NOOP
            } else {
                result = RENDER_CHECKBOX;
            }
        }
        return result;
    }

    @Override
    public String toString() {
        return "DynamicUiProperty [name=" + name + ", required=" + required + ", defaultValue=" + defaultValue + ", values=" + values
                + ", possibleValues=" + possibleValues + ", renderingHint=" + renderingHint + ", labeled=" + labeled + ", labels=" + labels
                + ", labelOnly=" + labelOnly + ", type=" + type + ", hasMultipleValues=" + hasMultipleValues + "]";
    }

    /** Delegation method for {@link DynamicUIModel#addDynamicUiComponent}. */
    public void addDynamicUiComponent(final DynamicUiComponent component) {
        getDynamicUiModel().addDynamicUiComponent(name, component);
    }

    /**
     * Update the view components attributes here!
     */
    public void updateViewComponents() {
        for (DynamicUiComponent component : getDynamicUiModel().getViewComponents(name)) {
            component.setDisabled(getDynamicUiModel().isDisabled() || isDisabled());
        }
    }
}