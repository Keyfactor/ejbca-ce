package org.ejbca.ui.web.admin.publisher;

import java.util.LinkedHashMap;
import java.util.Map;

public final class LdapPublisherMBData {
    
    public final Map<String, String> ldaptPublisherSecurityItems = new LinkedHashMap<>();

    private String ldapPublisherHostName;
    private String ldapPublisherPort;
    private String ldapPublisherSecurity;
    private String ldapPublisherBaseDN;
    private String ldapPublisherLoginDN;
    private String ldapPublisherLoginPWD;
    private String ldapPublisherConfirmPWD;
    private String ldapPublisherConnectionTimeout;
    private String ldapPublisherReadTimeout;
    private String ldapPublisherStoreTimeout;
    private boolean ldapPublisherCreateNonExistingUsers;
    private boolean ldapPublisherModifyExistingUsers;
    private boolean ldapPublisherModifyExistingAttributes;
    private boolean ldapPublisherAddNonExistingAttributes;
    private boolean ldapPublisherCreateImmidiateNodes;
    private boolean ldapPublisherAddMultipleCertificates;
    private boolean ldapPublisherRemoveRevokedCertificates;
    private boolean ldapPublisherRemoveUserOnCertRevoke;
    private boolean ldapPublisherSetUserPassword;
    private String ldapPublisherUserObjectClass;
    private String ldapPublisherCaObjectClass;
    private String ldapPublisherUserCertificateAttr;
    private String ldapPublisherCaCertificateAttr;
    private String ldapPublisherCrlAttribute;
    private String ldapPublisherDeltaCrlAttribute;
    private String ldapPublisherArlAttribute;
    private String[] ldapPublisherUseFieldsInDN;
    
    public String getLdapPublisherHostName() {
        return ldapPublisherHostName;
    }

    public void setLdapPublisherHostName(final String ldapPublisherHostName) {
        this.ldapPublisherHostName = ldapPublisherHostName;
    }

    public String getLdapPublisherPort() {
        return ldapPublisherPort;
    }

    public void setLdapPublisherPort(final String ldapPublisherPort) {
        this.ldapPublisherPort = ldapPublisherPort;
    }
    
    public Map<String, String> getLdapPublisherSecurityItems() {
        return this.ldaptPublisherSecurityItems;
    }

    public String getLdapPublisherSecurity() {
        return ldapPublisherSecurity;
    }

    public void setLdapPublisherSecurity(final String ldapPublisherSecurity) {
        this.ldapPublisherSecurity = ldapPublisherSecurity;
    }

    public String getLdapPublisherBaseDN() {
        return ldapPublisherBaseDN;
    }

    public void setLdapPublisherBaseDN(final String ldapPublisherBaseDN) {
        this.ldapPublisherBaseDN = ldapPublisherBaseDN;
    }

    public String getLdapPublisherLoginDN() {
        return ldapPublisherLoginDN;
    }

    public void setLdapPublisherLoginDN(final String ldapPublisherLoginDN) {
        this.ldapPublisherLoginDN = ldapPublisherLoginDN;
    }

    public String getLdapPublisherLoginPWD() {
        return ldapPublisherLoginPWD;
    }

    public void setLdapPublisherLoginPWD(final String ldapPublisherLoginPWD) {
        this.ldapPublisherLoginPWD = ldapPublisherLoginPWD;
    }

    public String getLdapPublisherConfirmPWD() {
        return ldapPublisherConfirmPWD;
    }

    public void setLdapPublisherConfirmPWD(final String ldapPublisherConfirmPWD) {
        this.ldapPublisherConfirmPWD = ldapPublisherConfirmPWD;
    }

    public String getLdapPublisherConnectionTimeout() {
        return ldapPublisherConnectionTimeout;
    }

    public void setLdapPublisherConnectionTimeout(final String ldapPublisherConnectionTimeout) {
        this.ldapPublisherConnectionTimeout = ldapPublisherConnectionTimeout;
    }

    public String getLdapPublisherReadTimeout() {
        return ldapPublisherReadTimeout;
    }

    public void setLdapPublisherReadTimeout(final String ldapPublisherReadTimeout) {
        this.ldapPublisherReadTimeout = ldapPublisherReadTimeout;
    }

    public String getLdapPublisherStoreTimeout() {
        return ldapPublisherStoreTimeout;
    }

    public void setLdapPublisherStoreTimeout(final String ldapPublisherStoreTimeout) {
        this.ldapPublisherStoreTimeout = ldapPublisherStoreTimeout;
    }

    public boolean isLdapPublisherCreateNonExistingUsers() {
        return ldapPublisherCreateNonExistingUsers;
    }

    public void setLdapPublisherCreateNonExistingUsers(final boolean ldapPublisherCreateNonExistingUsers) {
        this.ldapPublisherCreateNonExistingUsers = ldapPublisherCreateNonExistingUsers;
    }

    public boolean isLdapPublisherModifyExistingUsers() {
        return ldapPublisherModifyExistingUsers;
    }

    public void setLdapPublisherModifyExistingUsers(final boolean ldapPublisherModifyExistingUsers) {
        this.ldapPublisherModifyExistingUsers = ldapPublisherModifyExistingUsers;
    }

    public boolean isLdapPublisherModifyExistingAttributes() {
        return ldapPublisherModifyExistingAttributes;
    }

    public void setLdapPublisherModifyExistingAttributes(final boolean ldapPublisherModifyExistingAttributes) {
        this.ldapPublisherModifyExistingAttributes = ldapPublisherModifyExistingAttributes;
    }

    public boolean isLdapPublisherAddNonExistingAttributes() {
        return ldapPublisherAddNonExistingAttributes;
    }

    public void setLdapPublisherAddNonExistingAttributes(final boolean ldapPublisherAddNonExistingAttributes) {
        this.ldapPublisherAddNonExistingAttributes = ldapPublisherAddNonExistingAttributes;
    }

    public boolean isLdapPublisherCreateImmidiateNodes() {
        return ldapPublisherCreateImmidiateNodes;
    }

    public void setLdapPublisherCreateImmidiateNodes(final boolean ldapPublisherCreateImmidiateNodes) {
        this.ldapPublisherCreateImmidiateNodes = ldapPublisherCreateImmidiateNodes;
    }

    public boolean isLdapPublisherAddMultipleCertificates() {
        return ldapPublisherAddMultipleCertificates;
    }

    public void setLdapPublisherAddMultipleCertificates(final boolean ldapPublisherAddMultipleCertificates) {
        this.ldapPublisherAddMultipleCertificates = ldapPublisherAddMultipleCertificates;
    }

    public boolean isLdapPublisherRemoveRevokedCertificates() {
        return ldapPublisherRemoveRevokedCertificates;
    }

    public void setLdapPublisherRemoveRevokedCertificates(final boolean ldapPublisherRemoveRevokedCertificates) {
        this.ldapPublisherRemoveRevokedCertificates = ldapPublisherRemoveRevokedCertificates;
    }

    public boolean isLdapPublisherRemoveUserOnCertRevoke() {
        return ldapPublisherRemoveUserOnCertRevoke;
    }

    public void setLdapPublisherRemoveUserOnCertRevoke(final boolean ldapPublisherRemoveUserOnCertRevoke) {
        this.ldapPublisherRemoveUserOnCertRevoke = ldapPublisherRemoveUserOnCertRevoke;
    }

    public boolean isLdapPublisherSetUserPassword() {
        return ldapPublisherSetUserPassword;
    }

    public void setLdapPublisherSetUserPassword(final boolean ldapPublisherSetUserPassword) {
        this.ldapPublisherSetUserPassword = ldapPublisherSetUserPassword;
    }

    public String getLdapPublisherUserObjectClass() {
        return ldapPublisherUserObjectClass;
    }

    public void setLdapPublisherUserObjectClass(final String ldapPublisherUserObjectClass) {
        this.ldapPublisherUserObjectClass = ldapPublisherUserObjectClass;
    }

    public String getLdapPublisherCaObjectClass() {
        return ldapPublisherCaObjectClass;
    }

    public void setLdapPublisherCaObjectClass(final String ldapPublisherCaObjectClass) {
        this.ldapPublisherCaObjectClass = ldapPublisherCaObjectClass;
    }

    public String getLdapPublisherUserCertificateAttr() {
        return ldapPublisherUserCertificateAttr;
    }

    public void setLdapPublisherUserCertificateAttr(final String ldapPublisherUserCertificateAttr) {
        this.ldapPublisherUserCertificateAttr = ldapPublisherUserCertificateAttr;
    }

    public String getLdapPublisherCaCertificateAttr() {
        return ldapPublisherCaCertificateAttr;
    }

    public void setLdapPublisherCaCertificateAttr(final String ldapPublisherCaCertificateAttr) {
        this.ldapPublisherCaCertificateAttr = ldapPublisherCaCertificateAttr;
    }

    public String getLdapPublisherCrlAttribute() {
        return ldapPublisherCrlAttribute;
    }

    public void setLdapPublisherCrlAttribute(final String ldapPublisherCrlAttribute) {
        this.ldapPublisherCrlAttribute = ldapPublisherCrlAttribute;
    }

    public String getLdapPublisherDeltaCrlAttribute() {
        return ldapPublisherDeltaCrlAttribute;
    }

    public void setLdapPublisherDeltaCrlAttribute(final String ldapPublisherDeltaCrlAttribute) {
        this.ldapPublisherDeltaCrlAttribute = ldapPublisherDeltaCrlAttribute;
    }

    public String getLdapPublisherArlAttribute() {
        return ldapPublisherArlAttribute;
    }

    public void setLdapPublisherArlAttribute(final String ldapPublisherArlAttribute) {
        this.ldapPublisherArlAttribute = ldapPublisherArlAttribute;
    }

    public String[] getLdapPublisherUseFieldsInDN() {
        return ldapPublisherUseFieldsInDN;
    }

    public void setLdapPublisherUseFieldsInDN(final String[] ldapPublisherUseFieldsInDN) {
        this.ldapPublisherUseFieldsInDN = ldapPublisherUseFieldsInDN;
    }

    
}
