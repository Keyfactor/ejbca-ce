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
package org.ejbca.ui.web.admin.configuration;

import com.keyfactor.util.StringTools;
import org.cesecore.config.MSAutoEnrollmentSettingsTemplate;
import org.ejbca.config.MSAutoEnrollmentConfiguration;

import java.util.ArrayList;
import java.util.List;

public class AutoEnrollmentDTO {

    private String alias;
    private String msaeForestRoot;
    private String msaeDomain;
    private String policyName;
    private String servicePrincipalName;
    private byte[] keyTabFileBytes;
    private byte[] krb5ConfFileBytes;
    private String krb5ConfFilename;
    private String keyTabFilename;
    private boolean isUseSSL;
    private boolean followLdapReferral;
    private int adConnectionPort;
    private int ldapReadTimeout;
    private int ldapConnectTimeout;
    private String adLoginDN;
    private String adLoginPassword;
    private Integer authKeyBinding;
    private String caName;
    private List<MSAutoEnrollmentSettingsTemplate> mappedMsTemplates = new ArrayList<>();

    public AutoEnrollmentDTO() {
    }

    public AutoEnrollmentDTO(final String alias, final MSAutoEnrollmentConfiguration autoEnrollmentConfiguration) {
        if (autoEnrollmentConfiguration != null) {
            this.alias = alias;
            msaeForestRoot = autoEnrollmentConfiguration.getMsaeForestRoot(alias);
            msaeDomain = autoEnrollmentConfiguration.getMsaeDomain(alias);
            policyName = autoEnrollmentConfiguration.getPolicyName(alias);
            servicePrincipalName = autoEnrollmentConfiguration.getSpn(alias);
            keyTabFileBytes = autoEnrollmentConfiguration.getMsaeKeyTabBytes(alias);
            keyTabFilename = autoEnrollmentConfiguration.getMsaeKeyTabFilename(alias);
            krb5ConfFileBytes = autoEnrollmentConfiguration.getMsaeKrb5ConfBytes(alias);
            krb5ConfFilename = autoEnrollmentConfiguration.getMsaeKrb5ConfFilename(alias);
            isUseSSL = autoEnrollmentConfiguration.isUseSSL(alias);
            followLdapReferral = autoEnrollmentConfiguration.isFollowLdapReferral(alias);
            adConnectionPort = autoEnrollmentConfiguration.getADConnectionPort(alias);
            ldapReadTimeout = autoEnrollmentConfiguration.getLdapReadTimeout(alias);
            ldapConnectTimeout = autoEnrollmentConfiguration.getLdapConnectTimeout(alias);
            adLoginDN = autoEnrollmentConfiguration.getAdLoginDN(alias);
            adLoginPassword = MSAutoEnrollmentSettingsManagedBean.HIDDEN_PWD;
            authKeyBinding = autoEnrollmentConfiguration.getAuthKeyBinding(alias);
            caName = autoEnrollmentConfiguration.getCaName(alias);
            mappedMsTemplates = autoEnrollmentConfiguration.getMsTemplateSettings(alias);
        }
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public String getMsaeForestRoot() {
        return msaeForestRoot;
    }

    public void setMsaeForestRoot(String msaeForestRoot) {
        this.msaeForestRoot = msaeForestRoot;
    }

    public String getMsaeDomain() {
        return msaeDomain;
    }

    public void setMsaeDomain(String msaeDomain) {
        this.msaeDomain = msaeDomain;
    }

    public String getPolicyName() {
        return policyName;
    }

    public void setPolicyName(String policyName) {
        this.policyName = policyName;
    }

    public String getServicePrincipalName() {
        return servicePrincipalName;
    }

    public void setServicePrincipalName(String servicePrincipalName) {
        this.servicePrincipalName = servicePrincipalName;
    }

    public byte[] getKeyTabFileBytes() {
        return keyTabFileBytes;
    }

    public void setKeyTabFileBytes(byte[] keyTabFileBytes) {
        this.keyTabFileBytes = keyTabFileBytes;
    }

    public byte[] getKrb5ConfFileBytes() {
        return krb5ConfFileBytes;
    }

    public void setKrb5ConfFileBytes(byte[] krb5ConfFileBytes) {
        this.krb5ConfFileBytes = krb5ConfFileBytes;
    }

    public String getKrb5ConfFilename() {
        return krb5ConfFilename;
    }

    public void setKrb5ConfFilename(String krb5ConfFilename) {
        this.krb5ConfFilename = StringTools.stripFilename(krb5ConfFilename);
    }

    public String getKeyTabFilename() {
        return keyTabFilename;
    }

    public void setKeyTabFilename(String keyTabFilename) {
        this.keyTabFilename = StringTools.stripFilename(keyTabFilename);
    }

    public boolean isUseSSL() {
        return isUseSSL;
    }

    public void setUseSSL(boolean useSSL) {
        isUseSSL = useSSL;
    }

    public boolean isFollowLdapReferral() {
        return followLdapReferral;
    }

    public void setFollowLdapReferral(boolean followLdapReferral) {
        this.followLdapReferral = followLdapReferral;
    }

    public int getAdConnectionPort() {
        return adConnectionPort;
    }

    public void setAdConnectionPort(int adConnectionPort) {
        this.adConnectionPort = adConnectionPort;
    }

    public int getLdapReadTimeout() {
        return ldapReadTimeout;
    }

    public void setLdapReadTimeout(int ldapReadTimeout) {
        this.ldapReadTimeout = ldapReadTimeout;
    }

    public int getLdapConnectTimeout() {
        return ldapConnectTimeout;
    }

    public void setLdapConnectTimeout(int ldapConnectTimeout) {
        this.ldapConnectTimeout = ldapConnectTimeout;
    }

    public String getAdLoginDN() {
        return adLoginDN;
    }

    public void setAdLoginDN(String adLoginDN) {
        this.adLoginDN = adLoginDN;
    }

    public String getAdLoginPassword() {
        return adLoginPassword;
    }

    public void setAdLoginPassword(String adLoginPassword) {
        this.adLoginPassword = adLoginPassword;
    }

    public Integer getAuthKeyBinding() {
        return authKeyBinding;
    }

    public void setAuthKeyBinding(Integer authKeyBinding) {
        this.authKeyBinding = authKeyBinding;
    }

    public String getCaName() {
        return caName;
    }

    public void setCaName(String caName) {
        this.caName = caName;
    }

    public List<MSAutoEnrollmentSettingsTemplate> getMappedMsTemplates() {
        return mappedMsTemplates;
    }

    public void setMappedMsTemplates(List<MSAutoEnrollmentSettingsTemplate> mappedMsTemplates) {
        this.mappedMsTemplates = mappedMsTemplates;
    }
}
