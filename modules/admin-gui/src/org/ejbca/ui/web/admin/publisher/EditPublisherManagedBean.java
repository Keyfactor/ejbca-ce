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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.TreeSet;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.certificates.util.DnComponents;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.publisher.ActiveDirectoryPublisher;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.CustomPublisherProperty;
import org.ejbca.core.model.ca.publisher.GeneralPurposeCustomPublisher;
import org.ejbca.core.model.ca.publisher.ICustomPublisher;
import org.ejbca.core.model.ca.publisher.LdapPublisher;
import org.ejbca.core.model.ca.publisher.LdapSearchPublisher;
import org.ejbca.core.model.ca.publisher.LegacyValidationAuthorityPublisher;
import org.ejbca.core.model.ca.publisher.MultiGroupPublisher;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.SortableSelectItem;

/**
 * 
 * @version $Id$
 *
 */
@ManagedBean(name = "editPublisher")
@ViewScoped
public class EditPublisherManagedBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(EditPublisherManagedBean.class);


    private static final Map<Integer, String> AVAILABLEPUBLISHERS;
    private static final Map<Integer, String> AVAILABLESAMACCOUNTS;
    private final Map<String, String> LDAPPUBLISHERSECURITYITEMS = new LinkedHashMap<>();
    private final Map<Class <? extends BasePublisher>, Runnable> PUBLISHERINIT = new HashMap<>();

    static {
        AVAILABLEPUBLISHERS = new HashMap<>();
        AVAILABLEPUBLISHERS.put(PublisherConst.TYPE_LDAPPUBLISHER, "LDAPPUBLISHER");
        AVAILABLEPUBLISHERS.put(PublisherConst.TYPE_LDAPSEARCHPUBLISHER, "LDAPSEARCHPUBLISHER");
        AVAILABLEPUBLISHERS.put(PublisherConst.TYPE_ADPUBLISHER, "ACTIVEDIRECTORYPUBLISHER");
        AVAILABLEPUBLISHERS.put(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER, "CUSTOMPUBLISHER");
        AVAILABLEPUBLISHERS.put(PublisherConst.TYPE_MULTIGROUPPUBLISHER, "MULTIGROUPPUBLISHER");
        
        AVAILABLESAMACCOUNTS = new HashMap<>();
        AVAILABLESAMACCOUNTS.put(DNFieldExtractor.UPN, "MATCHUPN");
        AVAILABLESAMACCOUNTS.put(DNFieldExtractor.CN, "MATCHCOMMONNAME");
        AVAILABLESAMACCOUNTS.put(DNFieldExtractor.UID, "MATCHUID");
        AVAILABLESAMACCOUNTS.put(DNFieldExtractor.SN, "MATCHDNSERIALNUMBER");
        AVAILABLESAMACCOUNTS.put(DNFieldExtractor.GIVENNAME, "MATCHGIVENNAME");
        AVAILABLESAMACCOUNTS.put(DNFieldExtractor.SURNAME, "MATCHSURNAME");
    }
    
    private String selectedPublisherType;

    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private PublisherQueueSessionLocal publisherqueuesession;
    @EJB
    private CAAdminSessionLocal cAAdminSession;

    private BasePublisher publisher;
    private int publisherId;
    private String userDescription;
    private String searchBaseDN;
    private String searchFilter;
    private String currentCustomClass;
    private String customPublisherPropertySelectOneMenuValue;
    private String customPublisherPropertyInputText;
    private String customPublisherPropertyInputPassword;
    private String customPublisherPropertyOutputTextArea;
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

    @ManagedProperty(value = "#{listPublishersManagedBean}")
    private ListPublishersManagedBean listPublishersManagedBean;

    public ListPublishersManagedBean getListPublishersManagedBean() {
        return listPublishersManagedBean;
    }

    public void setListPublishersManagedBean(final ListPublishersManagedBean listPublishersManagedBean) {
        this.listPublishersManagedBean = listPublishersManagedBean;
    }

    @PostConstruct
    public void init() {
        this.publisher = publisherSession.getPublisher(listPublishersManagedBean.getSelectedPublisherName());
        fillPublisherInitMap();
        PUBLISHERINIT.get(this.publisher.getClass()).run();
    }

    private void fillPublisherInitMap() {
        this.PUBLISHERINIT.put(ActiveDirectoryPublisher.class, () -> initActiveDirectoryPublisher());
        this.PUBLISHERINIT.put(LdapSearchPublisher.class, () -> initLdapSearchPublisher());
        this.PUBLISHERINIT.put(LdapPublisher.class, () -> initLdapPublisher()); 
        this.PUBLISHERINIT.put(CustomPublisherContainer.class, () -> initCustomPublisher());
    }

    private Object initCustomPublisher() {
        this.currentCustomClass = ((CustomPublisherContainer) publisher).getClassPath();
        return null;
    }

    private Void initLdapPublisher() {
        LDAPPUBLISHERSECURITYITEMS.put(getEjbcaWebBean().getText("PLAIN"), "PLAIN");
        LDAPPUBLISHERSECURITYITEMS.put(getEjbcaWebBean().getText("STARTTLS"), "STARTTLS");
        LDAPPUBLISHERSECURITYITEMS.put(getEjbcaWebBean().getText("SSL"), "SSL");
        return null;
    }

    public void initAccess() throws Exception {
        // To check access 
        if (!FacesContext.getCurrentInstance().isPostback()) {
            final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
            getEjbcaWebBean().initialize(request, AccessRulesConstants.REGULAR_VIEWPUBLISHER);
        }
    }

    public List<SortableSelectItem> getAvailablePublisherTypes() {
        final List<SortableSelectItem> availablePublisherTypes = new ArrayList<>();
        // List all built in publisher types and all the dynamic ones
        for (final int publisherType : AVAILABLEPUBLISHERS.keySet()) {
            if (publisherType == PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER) {
                for (final String klass : getCustomClasses()) {
                    availablePublisherTypes.add(new SortableSelectItem(publisherType + "-" + klass, getPublisherName(klass)));
                }
            } else {
                // Add built in publisher types
                availablePublisherTypes.add(new SortableSelectItem(publisherType, getEjbcaWebBean().getText(AVAILABLEPUBLISHERS.get(publisherType))));
            }
        }
        // Allow selection of any class path
        if (WebConfiguration.isManualClassPathsEnabled()) {
            availablePublisherTypes.add(new SortableSelectItem(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER,
                    getEjbcaWebBean().getText(AVAILABLEPUBLISHERS.get(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER))));
        }
        // If an publisher was configured before the plugin mechanism we still want to show it
        boolean customNoLongerAvailable = true;
        final String selectedPublisherValue = getSelectedPublisherValue();
        for (final SortableSelectItem currentItem : availablePublisherTypes) {
            if (currentItem.getValue().equals(selectedPublisherValue)) {
                customNoLongerAvailable = false;
                break;
            }
        }
/*        if (customNoLongerAvailable) {
            log.error("Amin the selected publisher value is " + selectedPublisherValue);
            
            availablePublisherTypes.add(new SelectItem(selectedPublisherValue, selectedPublisherValue.split("-")[1]));
        }*/
        
        Collections.sort(availablePublisherTypes);
        return availablePublisherTypes;
    }

    public String getSelectedPublisherValue() {
        if (getPublisherType() == PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER) {
            final CustomPublisherContainer custompublisher = (CustomPublisherContainer) publisherSession
                    .getPublisher(listPublishersManagedBean.getSelectedPublisherName());
            final String currentClass = custompublisher.getClassPath();
            if (currentClass == null || currentClass.isEmpty()) {
                return Integer.valueOf(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER).toString();
            } else {
                return Integer.valueOf(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER).toString() + "-" + currentClass;
            }
        }
        return Integer.valueOf(getPublisherType()).toString();
    }

    @SuppressWarnings("deprecation")
    private int getPublisherType() {
        int retval = PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER;
        if (publisher instanceof CustomPublisherContainer) {
            retval = PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER;
        }
        if (publisher instanceof LdapPublisher) {
            retval = PublisherConst.TYPE_LDAPPUBLISHER;
        }
        if (publisher instanceof LdapSearchPublisher) {
            retval = PublisherConst.TYPE_LDAPSEARCHPUBLISHER;
        }
        // Legacy VA publisher doesn't exist in community edition, so check the qualified class name instead.
        if (publisher.getClass().getName().equals("org.ejbca.core.model.ca.publisher.ValidationAuthorityPublisher")) {
            retval = PublisherConst.TYPE_VAPUBLISHER;
        }
        if (publisher instanceof ActiveDirectoryPublisher) {
            retval = PublisherConst.TYPE_ADPUBLISHER;
        }
        if (publisher instanceof MultiGroupPublisher) {
            retval = PublisherConst.TYPE_MULTIGROUPPUBLISHER;
        }
        return retval;
    }

    public boolean getHasEditRights() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(AccessRulesConstants.REGULAR_EDITPUBLISHER);
    }

    public String getEditPublisherTitle() {
        return getEjbcaWebBean().getText("PUBLISHER") + " : " + listPublishersManagedBean.getSelectedPublisherName();
    }

    /**
    *
    * @return true if the publisher type is inherently read-only
    */
    public boolean isReadOnly() {
        if (!getHasEditRights()) {
            return true;
        } else if (publisher instanceof CustomPublisherContainer) {
            ICustomPublisher pub = ((CustomPublisherContainer) publisher).getCustomPublisher();
            // Can be null if custom publisher has not been set up yet, then it has to be editable
            return pub == null ? false : pub.isReadOnly();
        }
        return false;
    }

    /**
    *
    * @return true if the publisher is deprecated and shouldn't be editable.
    */
    public boolean isDeprecated() {
        return publisher.getClass().getName().equals(LegacyValidationAuthorityPublisher.OLD_VA_PUBLISHER_QUALIFIED_NAME);
    }

    public List<String> getCustomClasses() {
        final List<String> classes = new ArrayList<>();
        final ServiceLoader<ICustomPublisher> svcloader = ServiceLoader.load(ICustomPublisher.class);
        final boolean enabled = ((GlobalConfiguration) getEjbcaWebBean().getEjb().getGlobalConfigurationSession()
                .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableExternalScripts();
        String name = null;
        for (final ICustomPublisher implInstance : svcloader) {
            if (!implInstance.isReadOnly()) {
                name = implInstance.getClass().getName();
                if (enabled || !GeneralPurposeCustomPublisher.class.getName().equals(name)) {
                    classes.add(name);
                }
            }
        }
        return classes;
    }

    private String getPublisherName(final String className) {
        final String klassSimpleName = className.substring(className.lastIndexOf('.') + 1);
        // Present the publisher with a nice name if a language key is present
        String text = getEjbcaWebBean().getText(klassSimpleName.toUpperCase());
        if (text.equals(klassSimpleName.toUpperCase())) {
            // Present the publisher with the class name when no language key is present
            text = klassSimpleName + " (" + getEjbcaWebBean().getText(AVAILABLEPUBLISHERS.get(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER)) + ")";
        }
        return text;
    }

    public String getSelectedPublisherType() {
        return selectedPublisherType;
    }

    public void setSelectedPublisherType(String selectedPublisherType) {
        this.selectedPublisherType = selectedPublisherType;
    }
    
    public String getDescription() {
        return publisher.getDescription();
    }
    
    public boolean getOnlyUseQueue() {
        return publisher.getOnlyUseQueue();
    }

    public boolean getKeepPublishedInQueue() {
        return publisher.getKeepPublishedInQueue();
    }
    
    public boolean getUseQueueForCrls() {
        return publisher.getUseQueueForCRLs();
    }
    
    public boolean getUseQueueForCertificates() {
        return publisher.getUseQueueForCertificates();
    }
    
    public String getPublisherQueue() {
        int[] times = getPublisherQueueLength(new int[]{0, 1*60, 10*60, 60*60}, new int[]{1*60, 10*60, 60*60, -1});
        return Arrays.stream(times).mapToObj(Integer::toString).collect(Collectors.joining(", "));
    }
    
    private int[] getPublisherQueueLength(final int[] intervalLower, final int[] intervalUpper) {
        return publisherqueuesession.getPendingEntriesCountForPublisherInIntervals(publisherSession.getPublisherId(listPublishersManagedBean.getSelectedPublisherName()), intervalLower, intervalUpper);
    }
    
    public List<String> getAvailablePublisherList() {
        final List<String> availablePublisherList = new ArrayList<>();
        final Collection<Integer> authorizedPublisherIds = cAAdminSession.getAuthorizedPublisherIds(getEjbcaWebBean().getAdminObject(),
                Arrays.asList(PublisherConst.TYPE_MULTIGROUPPUBLISHER));
        authorizedPublisherIds.remove(this.publisherId);
        final Map<Integer, String> publisherIdToNameMap = publisherSession.getPublisherIdToNameMap();
        for (final int publisherId : authorizedPublisherIds) {
            availablePublisherList.add(publisherIdToNameMap.get(publisherId));
        }
        Collections.sort(availablePublisherList);
        return availablePublisherList;
    }
    
    public String getMultiPublishersDataAsString(){
        MultiGroupPublisher multiGroupPublisher = (MultiGroupPublisher) this.publisher;
        final List<TreeSet<Integer>> publisherGroups = multiGroupPublisher.getPublisherGroups();
        final Map<Integer, String> publisherIdToNameMap = publisherSession.getPublisherIdToNameMap();
        return convertMultiPublishersDataToString(publisherIdToNameMap, publisherGroups);
    }
    
    private String convertMultiPublishersDataToString(final Map<Integer,String> publisherIdToNameMap, final List<TreeSet<Integer>> data){
        StringBuffer multiPublishersDataAsString = new StringBuffer();
        String prefix = "";
        for (final TreeSet<Integer> group : data) {
            List<String> publisherNames = new ArrayList<>();
            for (Integer publisherId : group) {
                String name = publisherIdToNameMap.get(publisherId);
                if (StringUtils.isNotEmpty(name)) {
                    publisherNames.add(name);
                } else {
                    log.info("No name found for publisher with id " + publisherId);
                }
            }
            Collections.sort(publisherNames);
            for (final String publisherName : publisherNames) {
                multiPublishersDataAsString.append(prefix);
                multiPublishersDataAsString.append(publisherName);
                prefix = "\n";
            }
            if (!publisherNames.isEmpty()) {
                multiPublishersDataAsString.append("\n");
            }
        }
        multiPublishersDataAsString.setLength(Math.max(multiPublishersDataAsString.length() - 1, 0));
        return multiPublishersDataAsString.toString();
    }
    
    public List<SelectItem> getSAMAccountName() {
        final List<SelectItem> samAccountName = new ArrayList<>();
        for (final int accountName : AVAILABLESAMACCOUNTS.keySet()) {
            samAccountName.add(new SelectItem(accountName, AVAILABLESAMACCOUNTS.get(accountName)));
        }
        return samAccountName;
    }

    public String getUserDescription() {
        return userDescription;
    }

    public void setUserDescription(final String userDescription) {
        this.userDescription = userDescription;
    }

    public String getSearchBaseDN() {
        return searchBaseDN;
    }

    public void setSearchBaseDN(String searchBaseDN) {
        this.searchBaseDN = searchBaseDN;
    }    

    public String getSearchFilter() {
        return searchFilter;
    }

    public void setSearchFilter(String searchFilter) {
        this.searchFilter = searchFilter;
    }
    
    public String getCurrentPublisherName() {
        if (publisher instanceof CustomPublisherContainer) {
            ICustomPublisher iCustomPublisher = ((CustomPublisherContainer) publisher).getCustomPublisher();
            if(iCustomPublisher != null) {
                return getPublisherName(iCustomPublisher.getClass().getName());
            }
        }
        return getPublisherName(publisher.getClass().getName());
    }
    
    public boolean isCustomClassChoice() {
        CustomPublisherContainer custompublisher = (CustomPublisherContainer) publisher;
        final String currentClass = custompublisher.getClassPath();
        return !getCustomClasses().stream().anyMatch(customClass -> customClass.equals(currentClass));
    }
    
    public String getCustomPublisherSettingText() {
        return getEjbcaWebBean().getText("PUBLISHERSETTINGS") + " : " + getCurrentClassText();
    }
    
    public boolean isManualClassPathsEnabledOrIsCustomClassChoice() {
        return WebConfiguration.isManualClassPathsEnabled() || isCustomClassChoice();
    }

    public boolean isManualClassPathsEnabledAndIsCustomClassChoice() {
        return WebConfiguration.isManualClassPathsEnabled() && isCustomClassChoice();
    }
    
    public boolean isCustomUiRenderingSupported() {
        return ((CustomPublisherContainer)publisher).isCustomUiRenderingSupported();
    }
    
    public String getPropertyData() {
        return ((CustomPublisherContainer)publisher).getPropertyData();
    }
    
    public List<CustomPublisherProperty> getCustomUiPropertyList() {
        return ((CustomPublisherContainer)publisher).getCustomUiPropertyList(getEjbcaWebBean().getAdminObject());
    }
    
    public String getCustomPublisherPropertyText(final CustomPublisherProperty customPublisherProperty) {
        return getEjbcaWebBean().getText(getCurrentClassSimple().toUpperCase()+"_" + customPublisherProperty.getName().replaceAll("\\.", "_").toUpperCase());
    }
    
    public List<SelectItem> getCustomPublisherPropertySelectOneMenuList(final CustomPublisherProperty customPublisherProperty) {
        final List<SelectItem> customPublisherPropertySelectOneMenuList = new ArrayList<>();
        for (int i=0; i < customPublisherProperty.getOptions().size(); i++) {
            final String option = customPublisherProperty.getOptions().get(i);
            final String optionText = customPublisherProperty.getOptionTexts().get(i);
            customPublisherPropertySelectOneMenuList.add(new SelectItem(option, optionText));
        }
        return customPublisherPropertySelectOneMenuList;
    }
    
    public boolean renderCustomSelectOneMenu(final CustomPublisherProperty customPublisherProperty) {
        return customPublisherProperty.getType() == CustomPublisherProperty.UI_SELECTONE;
    }
    
    public boolean renderCustomInputPassword(final CustomPublisherProperty customPublisherProperty) {
        return customPublisherProperty.getType() == CustomPublisherProperty.UI_TEXTINPUT_PASSWORD;
    }
    
    public boolean renderCustomCheckbox(final CustomPublisherProperty customPublisherProperty) {
        return customPublisherProperty.getType() == CustomPublisherProperty.UI_BOOLEAN;
    }
    
    public boolean renderCustomOutputTextArea(final CustomPublisherProperty customPublisherProperty) {
        return customPublisherProperty.getType() == CustomPublisherProperty.UI_TEXTOUTPUT;
    }
    
    public boolean renderCustomHelp(final CustomPublisherProperty customPublisherProperty) {
        return !getEjbcaWebBean()
                .getText(getCurrentClassSimple().toUpperCase() + "_" + customPublisherProperty.getName().replaceAll("\\.", "_").toUpperCase()
                        + "_HELP")
                .equals(getCurrentClassSimple().toUpperCase() + "_" + customPublisherProperty.getName().replaceAll("\\.", "_").toUpperCase()
                        + "_HELP");
    }
    
    public String getCustomHelpText(final CustomPublisherProperty customPublisherProperty) {
        return getEjbcaWebBean().getText(
                getCurrentClassSimple().toUpperCase() + "_" + customPublisherProperty.getName().replaceAll("\\.", "_").toUpperCase() + "_HELP");
    }
    
    private String getCurrentClassSimple() {
        return this.currentCustomClass.substring(currentCustomClass.lastIndexOf('.')+1);
    }
    
    private String getCurrentClassText() {
        CustomPublisherContainer custompublisher = (CustomPublisherContainer) publisher;
        final String currentClass = custompublisher.getClassPath();
        final String currentClassSimple = currentClass.substring(currentClass.lastIndexOf('.') + 1);
        String currentClassText = getEjbcaWebBean().getText(currentClassSimple.toUpperCase());
        if (currentClassText.equals(currentClassSimple.toUpperCase())) {
            currentClassText = currentClassSimple;
        }
        return currentClassText;
    }
    
    
    private Void initActiveDirectoryPublisher() {
        userDescription = ((ActiveDirectoryPublisher) publisher).getUserDescription();
        return null;
    }
    
    private Void initLdapSearchPublisher() {
        searchBaseDN = ((LdapSearchPublisher) publisher).getSearchBaseDN();
        searchFilter = ((LdapSearchPublisher) publisher).getSearchFilter();
        return null;
    }

    public String getCurrentClass() {
        return currentCustomClass;
    }

    public void setCurrentClass(final String currentClass) {
        this.currentCustomClass = currentClass;
    }

    public String getCustomPublisherPropertySelectOneMenuValue() {
        return customPublisherPropertySelectOneMenuValue;
    }

    public void setCustomPublisherPropertySelectOneMenuValue(final String customPublisherPropertySelectOneMenuValue) {
        this.customPublisherPropertySelectOneMenuValue = customPublisherPropertySelectOneMenuValue;
    }

    public String getCustomPublisherPropertyInputText() {
        return customPublisherPropertyInputText;
    }

    public void setCustomPublisherPropertyInputText(final String customPublisherPropertyInputText) {
        this.customPublisherPropertyInputText = customPublisherPropertyInputText;
    }

    public String getCustomPublisherPropertyInputPassword() {
        return customPublisherPropertyInputPassword;
    }

    public void setCustomPublisherPropertyInputPassword(final String customPublisherPropertyInputPassword) {
        this.customPublisherPropertyInputPassword = customPublisherPropertyInputPassword;
    }

    public String getCustomPublisherPropertyOutputTextArea() {
        return customPublisherPropertyOutputTextArea;
    }

    public void setCustomPublisherPropertyOutputTextArea(final String customPublisherPropertyOutputTextArea) {
        this.customPublisherPropertyOutputTextArea = customPublisherPropertyOutputTextArea;
    }

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
        return this.LDAPPUBLISHERSECURITYITEMS;
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

    public boolean isLdapPublisherAddMultipleCertificate() {
        return ldapPublisherAddMultipleCertificates;
    }

    public void setLdapPublisherAddMultipleCertificate(final boolean ldapPublisherAddMultipleCertificate) {
        this.ldapPublisherAddMultipleCertificates = ldapPublisherAddMultipleCertificate;
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
    
    public List<SelectItem> getLdapPublisherLocationFieldsFromCertificateDN() {
        final List<SelectItem> result = new ArrayList<>();
        List<Integer> usefieldsindn = DNFieldExtractor.getUseFields(DNFieldExtractor.TYPE_SUBJECTDN);
        String[] usefieldsindntexts = (String[])DnComponents.getDnLanguageTexts().toArray(new String[0]);
        for(int i=0;i < usefieldsindn.size(); i++){ 
            result.add(new SelectItem(usefieldsindn.get(i), getEjbcaWebBean().getText(usefieldsindntexts[i])));
        }
        return result;
    }
    
}
