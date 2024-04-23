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
package org.ejbca.ui.web.admin.endentityprofiles;

import org.apache.commons.lang3.StringUtils;
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

    private boolean isEmail;
    private String[] options;
    private String regex;

    public boolean isEmail() {
        return isEmail;
    }

    public void setEmail(boolean isEmail) {
        this.isEmail = isEmail;
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
        this.isEmail = builder.isEmail;
        this.options = builder.options;
        this.regex = builder.regex;
    }

    public static class Builder {
        private String label;
        private boolean modifiable;
        private boolean required;
        private boolean isEmail;
        private String[] options;
        private String value;
        private String regex;

        public Builder(String label, boolean modifiable, boolean required) {
            this.label = label;
            this.modifiable = modifiable;
            this.required = required;
        } 

        public Builder withIsEmail(boolean isEmail) {
            this.isEmail = isEmail;
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
    protected String getFieldValueToSave(UserView userView, int[] fieldData) {
        String fieldValueToSave = StringUtils.EMPTY;

        fieldValueToSave = LDAPDN.escapeRDN(DNFieldExtractor.getFieldComponent(DnComponents.profileIdToDnId(fieldData[EndEntityProfile.FIELDTYPE]),
                DNFieldExtractor.TYPE_SUBJECTDN) + fieldValueToSave);
        return fieldValueToSave.trim();
    }

    @Override
    protected void validateFieldValue(String fieldValueToSave, int[] fieldData) throws AddEndEntityException {
        if (!isEmail && isModifiable() && StringUtils.isNotBlank(fieldValueToSave) && (!AddEndEntityUtil.validateDNField(fieldValueToSave))) {
                throw new AddEndEntityException(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("ONLYCHARACTERS") + " " + getLabel());
        }
        
    }
}
