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
package org.ejbca.ui.web.admin.publisher;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.faces.event.AjaxBehaviorEvent;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.StringUtils;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.certificates.util.DnComponents;
import org.ejbca.core.model.ca.publisher.LdapPublisher;
import org.ejbca.core.model.ca.publisher.LdapPublisher.ConnectionSecurity;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

/**
 * Class keeping the logic and data for ldap publisher used by EditPublisher managed bean.
 * 
 * @version $Id$
 *
 */
public final class LdapPublisherMBData implements Serializable {
    
    private static final long serialVersionUID = 1L;
    public final Map<String, ConnectionSecurity> securityItems = new LinkedHashMap<>();
    public static final String PASSWORD_LDAPLOGINPASSWORDPLACEHOLDER = "placeholder";

    private String hostName;
    private String port;
    private ConnectionSecurity connectionSecurity;
    private String baseDN;
    private String loginDN;
    private String loginPWD;
    private String confirmPWD;
    private int connectionTimeout;
    private int readTimeout;
    private int storeTimeout;
    private boolean createNonExistingUsers;
    private boolean modifyExistingUsers;
    private boolean modifyExistingAttributes;
    private boolean addNonExistingAttributes;
    private boolean createImmidiateNodes;
    private boolean addMultipleCertificates;
    private boolean removeRevokedCertificates;
    private boolean removeUserOnCertRevoke;
    private boolean setUserPassword;
    private String userObjectClass;
    private String caObjectClass;
    private String userCertificateAttr;
    private String caCertificateAttr;
    private String crlAttribute;
    private String deltaCrlAttribute;
    private String arlAttribute;
    private ArrayList<Integer> useFieldInLdapDN;
    
    public LdapPublisherMBData(final LdapPublisher ldapPublisher) {
        initializeData(ldapPublisher);
    }
    
    public String getHostName() {
        return hostName;
    }

    public void setHostName(final String ldapPublisherHostName) {
        this.hostName = ldapPublisherHostName;
    }

    public String getPort() {
        return this.port;
    }

    public void portAjaxListener(AjaxBehaviorEvent event) {
        switch (this.connectionSecurity) {
        case SSL:
            setPort(LdapPublisher.DEFAULT_SSLPORT);
            return;
        default:
            setPort(LdapPublisher.DEFAULT_PORT);
            return;
        }
    }

    public void setPort(final String ldapPublisherPort) {
        this.port = ldapPublisherPort;
    }
    
    public Map<String, ConnectionSecurity> getSecurityItems() {
        return securityItems;
    }

    public ConnectionSecurity getConnectionSecurity() {
        return connectionSecurity;
    }

    public void setConnectionSecurity(final ConnectionSecurity ldapPublisherSecurity) {
        this.connectionSecurity = ldapPublisherSecurity;
    }

    public String getBaseDN() {
        return baseDN;
    }

    public void setBaseDN(final String ldapPublisherBaseDN) {
        this.baseDN = ldapPublisherBaseDN;
    }

    public String getLoginDN() {
        return loginDN;
    }

    public void setLoginDN(final String ldapPublisherLoginDN) {
        this.loginDN = ldapPublisherLoginDN;
    }

    public String getLoginPWD() {
        return loginPWD;
    }

    public void setLoginPWD(final String ldapPublisherLoginPWD) {
        this.loginPWD = ldapPublisherLoginPWD;
    }

    public String getConfirmPWD() {
        return confirmPWD;
    }

    public void setConfirmPWD(final String ldapPublisherConfirmPWD) {
        this.confirmPWD = ldapPublisherConfirmPWD;
    }

    public int getConnectionTimeout() {
        return connectionTimeout;
    }

    public void setConnectionTimeout(final int ldapPublisherConnectionTimeout) {
        this.connectionTimeout = ldapPublisherConnectionTimeout;
    }

    public int getReadTimeout() {
        return readTimeout;
    }

    public void setReadTimeout(final int ldapPublisherReadTimeout) {
        this.readTimeout = ldapPublisherReadTimeout;
    }

    public int getStoreTimeout() {
        return storeTimeout;
    }

    public void setStoreTimeout(final int ldapPublisherStoreTimeout) {
        this.storeTimeout = ldapPublisherStoreTimeout;
    }

    public boolean isCreateNonExistingUsers() {
        return createNonExistingUsers;
    }

    public void setCreateNonExistingUsers(final boolean ldapPublisherCreateNonExistingUsers) {
        this.createNonExistingUsers = ldapPublisherCreateNonExistingUsers;
    }

    public boolean isModifyExistingUsers() {
        return modifyExistingUsers;
    }

    public void setModifyExistingUsers(final boolean ldapPublisherModifyExistingUsers) {
        this.modifyExistingUsers = ldapPublisherModifyExistingUsers;
    }

    public boolean isModifyExistingAttributes() {
        return modifyExistingAttributes;
    }

    public void setModifyExistingAttributes(final boolean ldapPublisherModifyExistingAttributes) {
        this.modifyExistingAttributes = ldapPublisherModifyExistingAttributes;
    }

    public boolean isAddNonExistingAttributes() {
        return addNonExistingAttributes;
    }

    public void setAddNonExistingAttributes(final boolean ldapPublisherAddNonExistingAttributes) {
        this.addNonExistingAttributes = ldapPublisherAddNonExistingAttributes;
    }

    public boolean isCreateImmidiateNodes() {
        return createImmidiateNodes;
    }

    public void setCreateImmidiateNodes(final boolean ldapPublisherCreateImmidiateNodes) {
        this.createImmidiateNodes = ldapPublisherCreateImmidiateNodes;
    }

    public boolean isAddMultipleCertificates() {
        return addMultipleCertificates;
    }

    public void setAddMultipleCertificates(final boolean ldapPublisherAddMultipleCertificates) {
        this.addMultipleCertificates = ldapPublisherAddMultipleCertificates;
    }

    public boolean isRemoveRevokedCertificates() {
        return removeRevokedCertificates;
    }

    public void setRemoveRevokedCertificates(final boolean ldapPublisherRemoveRevokedCertificates) {
        this.removeRevokedCertificates = ldapPublisherRemoveRevokedCertificates;
    }

    public boolean isRemoveUserOnCertRevoke() {
        return removeUserOnCertRevoke;
    }

    public void setRemoveUserOnCertRevoke(final boolean ldapPublisherRemoveUserOnCertRevoke) {
        this.removeUserOnCertRevoke = ldapPublisherRemoveUserOnCertRevoke;
    }

    public boolean isSetUserPassword() {
        return setUserPassword;
    }

    public void setSetUserPassword(final boolean ldapPublisherSetUserPassword) {
        this.setUserPassword = ldapPublisherSetUserPassword;
    }

    public String getUserObjectClass() {
        return userObjectClass;
    }

    public void setUserObjectClass(final String ldapPublisherUserObjectClass) {
        this.userObjectClass = ldapPublisherUserObjectClass;
    }

    public String getCaObjectClass() {
        return caObjectClass;
    }

    public void setCaObjectClass(final String ldapPublisherCaObjectClass) {
        this.caObjectClass = ldapPublisherCaObjectClass;
    }

    public String getUserCertificateAttr() {
        return userCertificateAttr;
    }

    public void setUserCertificateAttr(final String ldapPublisherUserCertificateAttr) {
        this.userCertificateAttr = ldapPublisherUserCertificateAttr;
    }

    public String getCaCertificateAttr() {
        return caCertificateAttr;
    }

    public void setCaCertificateAttr(final String ldapPublisherCaCertificateAttr) {
        this.caCertificateAttr = ldapPublisherCaCertificateAttr;
    }

    public String getCrlAttribute() {
        return crlAttribute;
    }

    public void setCrlAttribute(final String ldapPublisherCrlAttribute) {
        this.crlAttribute = ldapPublisherCrlAttribute;
    }

    public String getDeltaCrlAttribute() {
        return deltaCrlAttribute;
    }

    public void setDeltaCrlAttribute(final String ldapPublisherDeltaCrlAttribute) {
        this.deltaCrlAttribute = ldapPublisherDeltaCrlAttribute;
    }

    public String getArlAttribute() {
        return arlAttribute;
    }

    public void setArlAttribute(final String ldapPublisherArlAttribute) {
        this.arlAttribute = ldapPublisherArlAttribute;
    }

    public ArrayList<Integer> getUseFieldInLdapDN() {
        return useFieldInLdapDN;
    }

    public void setUseFieldInLdapDN(final ArrayList<Integer> ldapPublisherUseFieldsInDN) {
        this.useFieldInLdapDN = ldapPublisherUseFieldsInDN;
    }
    
    public List<SelectItem> getLdapPublisherLocationFieldsFromCertificateDN() {
        final List<SelectItem> result = new ArrayList<>();
        List<Integer> usefieldsindn = DNFieldExtractor.getUseFields(DNFieldExtractor.TYPE_SUBJECTDN);
        String[] usefieldsindntexts = (String[])DnComponents.getDnLanguageTexts().toArray(new String[0]);
        for(int i=0;i < usefieldsindn.size(); i++){ 
            result.add(new SelectItem(usefieldsindn.get(i), EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(usefieldsindntexts[i])));
        }
        return result;
    }

    private void initializeData(final LdapPublisher publisher) {
        hostName = publisher.getHostnames();
        port = publisher.getPort();
        connectionSecurity = publisher.getConnectionSecurity();
        baseDN = publisher.getBaseDN();
        loginDN = publisher.getLoginDN();
        loginPWD = getPasswordPlaceholder(publisher);
        confirmPWD = getPasswordPlaceholder(publisher);
        connectionTimeout = publisher.getConnectionTimeOut();
        readTimeout = publisher.getReadTimeOut();
        storeTimeout = publisher.getStoreTimeOut();
        createNonExistingUsers = publisher.getCreateNonExistingUsers();
        modifyExistingUsers = publisher.getModifyExistingUsers();
        modifyExistingAttributes = publisher.getModifyExistingAttributes();
        addNonExistingAttributes = publisher.getAddNonExistingAttributes();
        createImmidiateNodes = publisher.getCreateIntermediateNodes();
        addMultipleCertificates = publisher.getAddMultipleCertificates();
        removeRevokedCertificates = publisher.getRemoveRevokedCertificates();
        removeUserOnCertRevoke = publisher.getRemoveUsersWhenCertRevoked();
        setUserPassword = publisher.getSetUserPassword();
        userObjectClass = publisher.getUserObjectClass();
        caObjectClass = publisher.getCAObjectClass();
        userCertificateAttr = publisher.getUserCertAttribute();
        caCertificateAttr = publisher.getCACertAttribute();
        crlAttribute = publisher.getCRLAttribute();
        deltaCrlAttribute = publisher.getDeltaCRLAttribute();
        arlAttribute = publisher.getARLAttribute();
        useFieldInLdapDN = new ArrayList<Integer>(publisher.getUseFieldInLdapDN());

        securityItems.put(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("PLAIN"), ConnectionSecurity.PLAIN);
        securityItems.put(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("STARTTLS"), ConnectionSecurity.STARTTLS);
        securityItems.put(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("SSL"), ConnectionSecurity.SSL);
    }
    
    public void setLdapPublisherParameters(final LdapPublisher ldapPublisher) {
        ldapPublisher.setHostnames(hostName);
        ldapPublisher.setPort(port);
        ldapPublisher.setConnectionSecurity(connectionSecurity);
        ldapPublisher.setBaseDN(baseDN);
        ldapPublisher.setLoginDN(loginDN);
        if (!PASSWORD_LDAPLOGINPASSWORDPLACEHOLDER.equals(loginPWD)) {
            ldapPublisher.setLoginPassword(loginPWD);
        }
        ldapPublisher.setConnectionTimeOut(connectionTimeout);
        ldapPublisher.setReadTimeOut(readTimeout);
        ldapPublisher.setStoreTimeOut(storeTimeout);
        ldapPublisher.setCreateNonExistingUsers(createNonExistingUsers);
        ldapPublisher.setModifyExistingUsers(modifyExistingUsers);
        ldapPublisher.setModifyExistingAttributes(modifyExistingAttributes);
        ldapPublisher.setAddNonExistingAttributes(addNonExistingAttributes);
        ldapPublisher.setCreateIntermediateNodes(createImmidiateNodes);
        ldapPublisher.setAddMultipleCertificates(addMultipleCertificates);
        ldapPublisher.setRemoveRevokedCertificates(removeRevokedCertificates);
        ldapPublisher.setRemoveUsersWhenCertRevoked(removeUserOnCertRevoke);
        ldapPublisher.setUserPassword(setUserPassword);
        ldapPublisher.setUserObjectClass(userObjectClass);
        ldapPublisher.setCAObjectClass(caObjectClass);
        ldapPublisher.setUserCertAttribute(userCertificateAttr);
        ldapPublisher.setCACertAttribute(caCertificateAttr);
        ldapPublisher.setCRLAttribute(crlAttribute);
        ldapPublisher.setDeltaCRLAttribute(deltaCrlAttribute);
        ldapPublisher.setARLAttribute(arlAttribute);
        ldapPublisher.setUseFieldInLdapDN(useFieldInLdapDN);
    }
    
    
    /**
     * @return password placeholder instead of real password in order to not send clear text password to browser, 
     *         or empty string in case there is no ldap password (i.e. new publisher).
     */
    private String getPasswordPlaceholder(final LdapPublisher publisher) {
        final String currentPassword = (String) publisher.getRawData().get(LdapPublisher.LOGINPASSWORD);
        if (StringUtils.isNotEmpty(currentPassword)) {
            return PASSWORD_LDAPLOGINPASSWORDPLACEHOLDER;
        }
        return StringUtils.EMPTY;
    }
    
}
