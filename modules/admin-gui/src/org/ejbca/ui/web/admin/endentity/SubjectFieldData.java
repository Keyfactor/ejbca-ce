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
package org.ejbca.ui.web.admin.endentity;

import org.ejbca.ui.web.admin.rainterface.UserView;

public abstract class SubjectFieldData {
    
    private String label;
    private boolean modifiable;
    private boolean required;
    private String fieldValue;

    protected SubjectFieldData(String label, boolean modifiable, boolean required, String value) {
        super();
        this.label = label;
        this.modifiable = modifiable;
        this.required = required;
        this.fieldValue = value;
    }

    public String getLabel() {
        return label;
    }
    public void setLabel(String label) {
        this.label = label;
    }
    public boolean isModifiable() {
        return modifiable;
    }
    public void setModifiable(boolean modifiable) {
        this.modifiable = modifiable;
    }
    public boolean isRequired() {
        return required;
    }
    public void setRequired(boolean required) {
        this.required = required;
    }

    public String getFieldValue() {
        return fieldValue;
    }

    public void setFieldValue(String fieldValue) {
        this.fieldValue = fieldValue;
    }
    
    protected abstract String getFieldValueToSave(final UserView userView, int[] fieldData) throws EndEntityException;
    
    protected abstract void validateFieldValue(final String fieldValueToSave, final int[] fieldData) throws EndEntityException;


}
