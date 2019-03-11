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
package org.ejbca.ui.psm.jsf;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.util.Arrays;

import javax.faces.component.UIComponent;
import javax.faces.component.UIInput;
import javax.faces.event.AbortProcessingException;
import javax.faces.event.ValueChangeEvent;
import javax.faces.event.ValueChangeListener;

import org.apache.log4j.Logger;
import org.apache.myfaces.custom.fileupload.UploadedFile;
import org.cesecore.util.ExternalProcessException;
import org.cesecore.util.ExternalProcessTools;
import org.cesecore.util.ui.DynamicUiModel;
import org.cesecore.util.ui.DynamicUiProperty;

/**
 * This MyFaces ValueChangeListener implementation for {@link DynamicUiModel} sets the dynamic UI property 
 * values associated with the dynamic UI model.
 * 
 * @version $Id$
 */
public class JsfDynamicUiValueChangeListener implements Serializable, ValueChangeListener {

    private static final long serialVersionUID = -1L;

    /** Class logger. */
    private static final Logger log = Logger.getLogger(JsfDynamicUiValueChangeListener.class);

    /** DynamicUIProperty reference. */
    private DynamicUiProperty<?> dynamicUiProperty;

    /**
     * Default constructor.
     */
    public JsfDynamicUiValueChangeListener() {
    }

    /** 
     * Constructor with DynamicUiProperty reference.
     */
    public JsfDynamicUiValueChangeListener(DynamicUiProperty<?> dynamicUiProperty) {
        this.dynamicUiProperty = dynamicUiProperty;
    }

    @Override
    public void processValueChange(final ValueChangeEvent event) throws AbortProcessingException {
        final UIComponent eventSource = event.getComponent();
        if (eventSource.isRendered() && eventSource instanceof UIInput) {
            if (dynamicUiProperty.getHasMultipleValues()) {
                multipleValueChanged(eventSource, dynamicUiProperty);
            } else {
                singleValueChanged(eventSource, dynamicUiProperty);
            }
        }
    }

    /**
     * Implements the value changed event for single value properties.
     * @param eventSource the event source.
     * @param property the dynamic UI property.
     */
    protected void singleValueChanged(final UIComponent eventSource, final DynamicUiProperty<? extends Serializable> property) {
        final Object value = ((UIInput) eventSource).getValue();
        if (log.isDebugEnabled()) {
            log.debug("Registered UIComponent " + eventSource + " for dynamic UI property " + property.getName() + " single value changed from "
                    + property.getValue() + " to " + value + ".");
        }
        if (!property.isFileType()) {
            property.setValueGenericIncludeNull((Serializable) value);
        } else {
            if (value instanceof UploadedFile) {
                final String fileName = ((UploadedFile) value).getName();
                try {
                    final File file = ExternalProcessTools.writeTemporaryFileToDisk(fileName, /* use .tmp as file extension */ null,
                            ((UploadedFile) value).getBytes());
                    property.setValueGenericIncludeNull(file);
                } catch (ExternalProcessException | IOException e) {
                    if (log.isTraceEnabled()) {
                    	log.trace("Could not delete temp. file " + fileName + ": " + e.getMessage(), e);
                    }
                }
            }
        }
    }

    /**
     * Implements the value changed event for multiple value properties (used for string list boxes only).
     * @param eventSource the event source.
     * @param property the dynamic UI property.
     */
    protected void multipleValueChanged(final UIComponent eventSource, final DynamicUiProperty<? extends Serializable> property) {
        final String[] values = (String[]) ((UIInput) eventSource).getValue();
        if (log.isDebugEnabled()) {
            log.debug("Registered UIComponent " + eventSource + " for dynamic UI property " + property.getName() + " single value changed from "
                    + property.getValues() + " to " + values + ".");
        }
        property.setValuesGeneric(Arrays.asList(values));
    }
}