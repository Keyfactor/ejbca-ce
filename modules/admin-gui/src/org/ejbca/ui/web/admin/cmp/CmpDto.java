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
package org.ejbca.ui.web.admin.cmp;

public class CmpDto {

    private String alias;
    private String CMPDefaultCA;
    private String responseProtection;
    private boolean raMode;
    private String authenticationModule;
    private String authenticationParameters;
    private String extractUsernameComponent;
    private boolean vendorMode;
    private String vendorCaIds;
    private String responseCaPubsCA;
    private boolean responseCaPubsIssuingCA;
    private String responseExtraCertsCA;
    private boolean allowRAVerifyPOPO;
    private String raNameGenScheme;
    private String raNameGenParams;
    private String raNameGenPrefix;
    private String raNameGenPostfix;
    private String raPwdGenParams;
    private boolean allowRACustomSerno;
    private String raEEProfile;
    private String raCertProfile;
    private String raCAName;
    private String raCertPath;
    private boolean omitVerificationsInEEC;
    private boolean kurAllowAutomaticUpdate;
    private boolean allowServerGeneratedKeys;
    private boolean kurAllowSameKey;
    @Deprecated
    private String certReqHandlerClass;
    private boolean useExtendedValidation;

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public String getCMPDefaultCA() {
        return CMPDefaultCA;
    }

    public void setCMPDefaultCA(String CMPDefaultCA) {
        this.CMPDefaultCA = CMPDefaultCA;
    }

    public String getResponseProtection() {
        return responseProtection;
    }

    public void setResponseProtection(String responseProtection) {
        this.responseProtection = responseProtection;
    }

    public void setRaMode(boolean raMode) {
        this.raMode = raMode;
    }

    public String getAuthenticationModule() {
        return authenticationModule;
    }

    public void setAuthenticationModule(String authenticationModule) {
        this.authenticationModule = authenticationModule;
    }

    public String getAuthenticationParameters() {
        return authenticationParameters;
    }

    public void setAuthenticationParameters(String authenticationParameters) {
        this.authenticationParameters = authenticationParameters;
    }

    public String getExtractUsernameComponent() {
        return extractUsernameComponent;
    }

    public void setExtractUsernameComponent(String extractUsernameComponent) {
        this.extractUsernameComponent = extractUsernameComponent;
    }

    public boolean isVendorMode() {
        return vendorMode;
    }

    public void setVendorMode(boolean vendorMode) {
        this.vendorMode = vendorMode;
    }

    public String getVendorCaIds() {
        return vendorCaIds;
    }

    public void setVendorCaIds(String vendorCaIds) {
        this.vendorCaIds = vendorCaIds;
    }

    public String getResponseCaPubsCA() {
        return responseCaPubsCA;
    }

    public void setResponseCaPubsCA(String responseCaPubsCA) {
        this.responseCaPubsCA = responseCaPubsCA;
    }

    public boolean isResponseCaPubsIssuingCA() {
        return responseCaPubsIssuingCA;
    }

    public void setResponseCaPubsIssuingCA(boolean responseCaPubsIssuingCA) {
        this.responseCaPubsIssuingCA = responseCaPubsIssuingCA;
    }

    public String getResponseExtraCertsCA() {
        return responseExtraCertsCA;
    }

    public void setResponseExtraCertsCA(String responseExtraCertsCA) {
        this.responseExtraCertsCA = responseExtraCertsCA;
    }

    public boolean isAllowRAVerifyPOPO() {
        return allowRAVerifyPOPO;
    }

    public void setAllowRAVerifyPOPO(boolean allowRAVerifyPOPO) {
        this.allowRAVerifyPOPO = allowRAVerifyPOPO;
    }

    public boolean isRaMode() {
        return raMode;
    }

    public String getRaNameGenScheme() {
        return raNameGenScheme;
    }

    public void setRaNameGenScheme(String raNameGenScheme) {
        this.raNameGenScheme = raNameGenScheme;
    }

    public String getRaNameGenParams() {
        return raNameGenParams;
    }

    public void setRaNameGenParams(String raNameGenParams) {
        this.raNameGenParams = raNameGenParams;
    }

    public String getRaNameGenPrefix() {
        return raNameGenPrefix;
    }

    public void setRaNameGenPrefix(String raNameGenPrefix) {
        this.raNameGenPrefix = raNameGenPrefix;
    }

    public String getRaNameGenPostfix() {
        return raNameGenPostfix;
    }

    public void setRaNameGenPostfix(String raNameGenPostfix) {
        this.raNameGenPostfix = raNameGenPostfix;
    }

    public String getRaPwdGenParams() {
        return raPwdGenParams;
    }

    public void setRaPwdGenParams(String raPwdGenParams) {
        this.raPwdGenParams = raPwdGenParams;
    }

    public boolean isAllowRACustomSerno() {
        return allowRACustomSerno;
    }

    public void setAllowRACustomSerno(boolean allowRACustomSerno) {
        this.allowRACustomSerno = allowRACustomSerno;
    }

    public String getRaEEProfile() {
        return raEEProfile;
    }

    public void setRaEEProfile(String raEEProfile) {
        this.raEEProfile = raEEProfile;
    }

    public String getRaCertProfile() {
        return raCertProfile;
    }

    public void setRaCertProfile(String raCertProfile) {
        this.raCertProfile = raCertProfile;
    }

    public String getRaCAName() {
        return raCAName;
    }

    public void setRaCAName(String raCAName) {
        this.raCAName = raCAName;
    }

    public String getRaCertPath() {
        return raCertPath;
    }

    public void setRaCertPath(String raCertPath) {
        this.raCertPath = raCertPath;
    }

    public boolean isOmitVerificationsInEEC() {
        return omitVerificationsInEEC;
    }

    public void setOmitVerificationsInEEC(boolean omitVerificationsInEEC) {
        this.omitVerificationsInEEC = omitVerificationsInEEC;
    }

    public boolean isKurAllowAutomaticUpdate() {
        return kurAllowAutomaticUpdate;
    }

    public void setKurAllowAutomaticUpdate(boolean kurAllowAutomaticUpdate) {
        this.kurAllowAutomaticUpdate = kurAllowAutomaticUpdate;
    }

    public boolean isAllowServerGeneratedKeys() {
        return allowServerGeneratedKeys;
    }

    public void setAllowServerGeneratedKeys(boolean allowServerGeneratedKeys) {
        this.allowServerGeneratedKeys = allowServerGeneratedKeys;
    }

    public boolean isKurAllowSameKey() {
        return kurAllowSameKey;
    }

    public void setKurAllowSameKey(boolean kurAllowSameKey) {
        this.kurAllowSameKey = kurAllowSameKey;
    }

    @Deprecated
    public String getCertReqHandlerClass() {
        return certReqHandlerClass;
    }

    @Deprecated
    public void setCertReqHandlerClass(String certReqHandlerClass) {
        this.certReqHandlerClass = certReqHandlerClass;
    }

    public boolean isUseExtendedValidation() {
        return useExtendedValidation;
    }

    public void setUseExtendedValidation(boolean useExtendedValidation) {
        this.useExtendedValidation = useExtendedValidation;
    }
}
