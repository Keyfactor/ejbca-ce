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

import com.keyfactor.util.certificate.DnComponents;

/**
 * Class holding and validating data for subject alternative name attributes of End Entity
 */
public class SubjectAltNameFieldData extends SubjectFieldData {

    private boolean isRfc822Name;
    private boolean useDataFromRFC822NameField;
    private boolean renderUseDataFromRFC822NameField;
    private boolean isUpn;
    private boolean copyDataFromCN;
    private boolean isDnsName;
    private String rfcName;
    private String rfcDomain;
    private String[] options;
    private String upnName;
    private String upnDomain;
    private String regex;
    private String rfc822NameString;

    public boolean isRfc822Name() {
        return isRfc822Name;
    }

    public void setRfc822Name(boolean isRfc822Name) {
        this.isRfc822Name = isRfc822Name;
    }

    public boolean isUseDataFromRFC822NameField() {
        return useDataFromRFC822NameField;
    }

    public void setUseDataFromRFC822NameField(boolean useDataFromRFC822NameField) {
        this.useDataFromRFC822NameField = useDataFromRFC822NameField;
    }

    public boolean isUpn() {
        return isUpn;
    }

    public void setUpn(boolean isUpn) {
        this.isUpn = isUpn;
    }

    public boolean isCopyDataFromCN() {
        return copyDataFromCN;
    }

    public void setCopyDataFromCN(boolean copyDataFromCN) {
        this.copyDataFromCN = copyDataFromCN;
    }

    public boolean isDnsName() {
        return isDnsName;
    }

    public void setDnsName(boolean isDnsName) {
        this.isDnsName = isDnsName;
    }

    public String getRfcName() {
        return rfcName;
    }

    public void setRfcName(String rfcName) {
        this.rfcName = rfcName;
    }

    public String getRfcDomain() {
        return rfcDomain;
    }

    public void setRfcDomain(String rfcDomain) {
        this.rfcDomain = rfcDomain;
    }

    public String[] getOptions() {
        return options;
    }

    public void setOptions(String[] options) {
        this.options = options;
    }

    public String getUpnName() {
        return upnName;
    }

    public void setUpnName(String upnName) {
        this.upnName = upnName;
    }

    public String getUpnDomain() {
        return upnDomain;
    }

    public void setUpnDomain(String upnDomain) {
        this.upnDomain = upnDomain;
    }

    public String getRegex() {
        return regex;
    }

    public void setRegex(String regex) {
        this.regex = regex;
    }

    // Private constructor to enforce usage of the builder
    private SubjectAltNameFieldData(String label, boolean modifiable, boolean required, String value) {
        super(label, modifiable, required, value);
    }

    public static class Builder {
        private SubjectAltNameFieldData fieldData;

        public Builder(final String label, final boolean modifiable, final boolean required, final String value) {
            fieldData = new SubjectAltNameFieldData(label, modifiable, required, value);
        }

        public Builder withRFC822Name(boolean isRFC822Name) {
            fieldData.isRfc822Name = isRFC822Name;
            return this;
        }

        public Builder withUseDataFromRFC822NameField(boolean useDataFromRFC822NameField) {
            fieldData.useDataFromRFC822NameField = useDataFromRFC822NameField;
            return this;
        }

        public Builder withUpn(boolean isUpn) {
            fieldData.isUpn = isUpn;
            return this;
        }

        public Builder withCopyDataFromCN(boolean copyDataFromCN) {
            fieldData.copyDataFromCN = copyDataFromCN;
            return this;
        }

        public Builder withDNSName(boolean isDnsName) {
            fieldData.isDnsName = isDnsName;
            return this;
        }

        public Builder withRfcName(String rfcName) {
            fieldData.rfcName = rfcName;
            return this;
        }

        public Builder withRfcDomain(String rfcDomain) {
            fieldData.rfcDomain = rfcDomain;
            return this;
        }

        public Builder withOptions(String[] options) {
            fieldData.options = options;
            return this;
        }

        public Builder withUpnName(String upnName) {
            fieldData.upnName = upnName;
            return this;
        }

        public Builder withUpnDomain(String upnDomain) {
            fieldData.upnDomain = upnDomain;
            return this;
        }

        public Builder withRegex(String regex) {
            fieldData.regex = regex;
            return this;
        }

        public Builder withRfc822NameString(String rfc822NameString) {
            fieldData.rfc822NameString = rfc822NameString;
            return this;
        }

        public Builder withRenderUseDataFromRFC822NameField(boolean renderUseDataFromRFC822NameField) {
            fieldData.renderUseDataFromRFC822NameField = renderUseDataFromRFC822NameField;
            return this;
        }

        public SubjectAltNameFieldData build() {
            return fieldData;
        }
    }
    
    public boolean isRenderRegex() {
        return StringUtils.isNotBlank(regex);
    }

    public void setRfc822NameString(String rfc822NameString) {
        this.rfc822NameString = rfc822NameString;
    }

    public boolean isRfc822NameStringHaveAtSign() {
        return rfc822NameString != null && rfc822NameString.contains("@");
    }

    public boolean isRenderUseDataFromRFC822NameField() {
        return renderUseDataFromRFC822NameField;
    }

    public void setRenderUseDataFromRFC822NameField(boolean renderUseDataFromRFC822NameField) {
        this.renderUseDataFromRFC822NameField = renderUseDataFromRFC822NameField;
    }

    @Override
    protected String getFieldValueToSave(UserView userView, int[] fieldData) throws AddEndEntityException {

        String fieldValueToSave = StringUtils.EMPTY;

        if (isRfc822Name) {
            if (useDataFromRFC822NameField && isRequired()) {

                final String emailFromProfile = userView.getEmail();
                if (StringUtils.isBlank(emailFromProfile)) {
                    throw new AddEndEntityException("RFC822Name field required but not set in profile.");
                }
                return userView.getEmail();
            } else if (StringUtils.isNotBlank(rfcName) && StringUtils.isNotBlank(rfcDomain)) {
                fieldValueToSave = rfcName + "@" + rfcDomain;
            }
        } else {
            if (isUpn) {
                if (StringUtils.isNotBlank(upnName) && StringUtils.isNotBlank(upnDomain)) {
                    fieldValueToSave = upnName + "@" + upnDomain;
                    
                } else if (StringUtils.isNotBlank(upnDomain)) {
                    fieldValueToSave = "@" + upnDomain;
                }
            } else {
                if (StringUtils.isNotBlank(getFieldValue())) {
                    fieldValueToSave = getFieldValue().trim();
                }
            }

        }
        
        if(StringUtils.isNotBlank(fieldValueToSave)) {
            validateFieldValue(fieldValueToSave, fieldData);
            fieldValueToSave = constructFinalValueToSave(fieldData, fieldValueToSave);
        }
        
        return fieldValueToSave;
    }

    @Override
    protected void validateFieldValue(final String fieldValueToSave, final int[] fieldData) throws AddEndEntityException {
        
        if (EndEntityProfile.isFieldOfType(fieldData[EndEntityProfile.FIELDTYPE], DnComponents.IPADDRESS)) {
            validateIPAddrValue(fieldValueToSave);
        }
        
        if (!isRfc822Name() && isUpn && StringUtils.isNotBlank(upnName) && !AddEndEntityUtil.validateDNField(upnName)) {
            throw new AddEndEntityException(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("ONLYCHARACTERS") + " " + getLabel());
        }
        
        if (isModifiable() && !isUpn && !AddEndEntityUtil.validateDNField(fieldValueToSave)) {
            throw new AddEndEntityException(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("ONLYCHARACTERS") + " " + getLabel());
        }
    }

    private String constructFinalValueToSave(int[] fieldData, String fieldValueToSave) {
        fieldValueToSave = org.ietf.ldap.LDAPDN
                .escapeRDN(DNFieldExtractor.getFieldComponent(DnComponents.profileIdToDnId(fieldData[EndEntityProfile.FIELDTYPE]),
                        DNFieldExtractor.TYPE_SUBJECTALTNAME) + fieldValueToSave);
        return fieldValueToSave;
    }
    
    private void validateIPAddrValue(final String ipAddress) throws AddEndEntityException {
        if (!AddEndEntityUtil.validateIPv4(ipAddress) && !AddEndEntityUtil.validateIPv6(ipAddress)) {
            throw new AddEndEntityException(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("INVALIDIPADDRESS") + " " + getLabel());
        }
    }
}
