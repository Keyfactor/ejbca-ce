package org.ejbca.ui.web.admin.publisher;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.faces.model.SelectItem;

import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.certificates.util.DnComponents;
import org.ejbca.core.model.ca.publisher.LdapPublisher;
import org.ejbca.core.model.ca.publisher.LdapPublisher.ConnectionSecurity;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

public final class LdapPublisherMBData {
    
    public final Map<String, ConnectionSecurity> securityItems = new LinkedHashMap<>();

    private String hostName;
    private String port;
    private ConnectionSecurity connectionSecurity;
    private String baseDN;
    private String loginDN;
    private String loginPWD;
    private String confirmPWD;
    private long connectionTimeout;
    private long readTimeout;
    private long storeTimeout;
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
    
    public String getHostName() {
        return hostName;
    }

    public void setHostName(final String ldapPublisherHostName) {
        this.hostName = ldapPublisherHostName;
    }

    public String getPort() {
        switch (this.connectionSecurity) {
        case SSL:
            return LdapPublisher.DEFAULT_SSLPORT;
        default:
            return LdapPublisher.DEFAULT_PORT;
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

    public long getConnectionTimeout() {
        return connectionTimeout;
    }

    public void setConnectionTimeout(final long ldapPublisherConnectionTimeout) {
        this.connectionTimeout = ldapPublisherConnectionTimeout;
    }

    public long getReadTimeout() {
        return readTimeout;
    }

    public void setReadTimeout(final long ldapPublisherReadTimeout) {
        this.readTimeout = ldapPublisherReadTimeout;
    }

    public long getStoreTimeout() {
        return storeTimeout;
    }

    public void setStoreTimeout(final long ldapPublisherStoreTimeout) {
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

    public void initializeData(final LdapPublisher publisher) {
        this.port = publisher.getPort();
        this.connectionSecurity = publisher.getConnectionSecurity();
        this.connectionTimeout = publisher.getConnectionTimeOut();
        this.readTimeout = publisher.getReadTimeOut();
        this.storeTimeout = publisher.getStoreTimeOut();
        this.createNonExistingUsers = publisher.getCreateNonExistingUsers();
        this.modifyExistingUsers = publisher.getModifyExistingUsers();
        this.modifyExistingAttributes = publisher.getModifyExistingAttributes();
        this.addNonExistingAttributes = publisher.getAddNonExistingAttributes();
        this.createImmidiateNodes = publisher.getCreateIntermediateNodes();
        this.addMultipleCertificates = publisher.getAddMultipleCertificates();
        this.removeRevokedCertificates = publisher.getRemoveRevokedCertificates();
        this.removeUserOnCertRevoke = publisher.getRemoveUsersWhenCertRevoked();
        this.setUserPassword = publisher.getSetUserPassword();
        this.userObjectClass = publisher.getUserObjectClass();
        this.caObjectClass = publisher.getCAObjectClass();
        this.userCertificateAttr = publisher.getUserCertAttribute();
        this.caCertificateAttr = publisher.getCACertAttribute();
        this.crlAttribute = publisher.getCRLAttribute();
        this.deltaCrlAttribute = publisher.getDeltaCRLAttribute();
        this.arlAttribute = publisher.getARLAttribute();
        this.useFieldInLdapDN = new ArrayList<Integer>(publisher.getUseFieldInLdapDN());
        
        this.securityItems.put(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("PLAIN"), ConnectionSecurity.PLAIN);
        this.securityItems.put(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("STARTTLS"), ConnectionSecurity.STARTTLS);
        this.securityItems.put(EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("SSL"), ConnectionSecurity.SSL);
        
    }
    
}
