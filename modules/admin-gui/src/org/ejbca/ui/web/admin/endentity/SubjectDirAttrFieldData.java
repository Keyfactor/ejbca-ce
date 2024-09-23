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

import org.apache.commons.lang3.StringUtils;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.ui.web.admin.rainterface.UserView;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

import com.keyfactor.util.certificate.DnComponents;

/**
 * Class holding and validating data for subject directory attributes of End Entity
 */
public class SubjectDirAttrFieldData extends SubjectFieldData {

    private String[] options;

    private SubjectDirAttrFieldData(Builder builder) {
        super(builder.label, builder.modifiable, builder.required, builder.fieldValue);
        this.options = builder.options;
    }

    public static class Builder {
        private String label;
        private boolean modifiable;
        private boolean required;
        private String[] options;
        private String fieldValue;

        public Builder(String label, boolean modifiable, boolean required) {
            this.label = label;
            this.modifiable = modifiable;
            this.required = required;
        }

        public Builder withOptions(String[] options) {
            this.options = options;
            return this;
        }

        public Builder withFieldValue(String fieldValue) {
            this.fieldValue = fieldValue;
            return this;
        }

        public SubjectDirAttrFieldData build() {
            return new SubjectDirAttrFieldData(this);
        }
    }

    public String[] getOptions() {
        return options;
    }

    public void setOptions(String[] options) {
        this.options = options;
    }

    @Override
    protected String getFieldValueToSave(UserView userView, int[] fieldData) throws EndEntityException {
        if(StringUtils.isNotBlank(getFieldValue())) {
            validateFieldValue(getFieldValue(), fieldData); // Do a validation before adding EE
        }
        return getFieldValue().trim();
    }

    @Override
    protected void validateFieldValue(String fieldValueToSave, int[] fieldData) throws EndEntityException {
        if (EndEntityProfile.isFieldOfType(fieldData[EndEntityProfile.FIELDTYPE], DnComponents.GENDER)) {
            validateGender(fieldValueToSave);
        }
        if (EndEntityProfile.isFieldOfType(fieldData[EndEntityProfile.FIELDTYPE], DnComponents.DATEOFBIRTH)) {
            validateDOB(fieldValueToSave);
        }
    }

    private void validateGender(String fieldValue) throws EndEntityException {
        if (!AddEndEntityUtil.isValidGender(fieldValue)) {
            throw new EndEntityException(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("ONLYMORFINGENDERFIELD") + " " + getLabel());
        }
    }
    
    private void validateDOB(String fieldValueToSave) throws EndEntityException {
        if (!AddEndEntityUtil.isValidDateOfBirth(fieldValueToSave)) {
            throw new EndEntityException(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("INVALIDDATEOFBIRTH") + " " + getLabel());
        }
    }

}
