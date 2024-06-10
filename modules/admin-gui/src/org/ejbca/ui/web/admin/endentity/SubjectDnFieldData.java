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
import org.apache.commons.lang3.tuple.MutablePair;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.ui.web.admin.rainterface.UserView;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;
import org.ietf.ldap.LDAPDN;

import com.keyfactor.util.certificate.DnComponents;

/**
 * Class holding and validating data for subject dn attributes of End Entity
 */
public class SubjectDnFieldData extends SubjectFieldData {

    private MutablePair<Boolean, Boolean> isEmailAndUsesEmailFieldData;
    private String[] options;
    private String regex; 

    public MutablePair<Boolean, Boolean> getIsEmailAndUsesEmailFieldData() {
        return isEmailAndUsesEmailFieldData;
    }

    public void setIsEmailAndUsesEmailFieldData(MutablePair<Boolean, Boolean> isEmailAndUsesEmailFieldData) {
        this.isEmailAndUsesEmailFieldData = isEmailAndUsesEmailFieldData;
    }

    public String[] getOptions() {
        return options;
    }

    public void setOptions(String[] options) {
        this.options = options;
    }

    public String getRegex() {
        return regex;
    }

    public void setRegex(String regex) {
        this.regex = regex;
    }

    private SubjectDnFieldData(Builder builder) {
        super(builder.label, builder.modifiable, builder.required, builder.value);
        this.isEmailAndUsesEmailFieldData = builder.isEmailAndUsesEmailFieldData;
        this.options = builder.options;
        this.regex = builder.regex;
    }

    public static class Builder {
        private String label;
        private boolean modifiable;
        private boolean required;
        private MutablePair<Boolean, Boolean> isEmailAndUsesEmailFieldData;
        private String[] options;
        private String value;
        private String regex;

        public Builder(String label, boolean modifiable, boolean required) {
            this.label = label;
            this.modifiable = modifiable;
            this.required = required;
        }

        public Builder withIsEmailAndUsesEmailFieldData(MutablePair<Boolean, Boolean> isEmailAndUsesEmailFieldData) {
            this.isEmailAndUsesEmailFieldData = isEmailAndUsesEmailFieldData;
            return this;
        }

        public Builder withOptions(String[] options) {
            this.options = options;
            return this;
        }

        public Builder withValue(String value) {
            this.value = value;
            return this;
        }

        public Builder withRegex(String regex) {
            this.regex = regex;
            return this;
        }

        public SubjectDnFieldData build() {
            return new SubjectDnFieldData(this);
        }
    }

    @Override
    protected String getFieldValueToSave(UserView userView, int[] fieldData) throws EndEntityException {
        String fieldValueToSave = StringUtils.EMPTY;
        fieldValueToSave = LDAPDN.escapeRDN(DNFieldExtractor.getFieldComponent(DnComponents.profileIdToDnId(fieldData[EndEntityProfile.FIELDTYPE]),
                DNFieldExtractor.TYPE_SUBJECTDN) + fieldValueToSave);
        return fieldValueToSave.trim();
    }

    @Override
    protected void validateFieldValue(String fieldValueToSave, int[] fieldData) throws EndEntityException {
        if (!isEmailAndUsesEmailFieldData.left && isModifiable() && StringUtils.isNotBlank(fieldValueToSave) && !AddEndEntityUtil.isValidDNField(fieldValueToSave)) {
            throw new EndEntityException(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("ONLYCHARACTERS") + " " + getLabel());
        }

    }

}
