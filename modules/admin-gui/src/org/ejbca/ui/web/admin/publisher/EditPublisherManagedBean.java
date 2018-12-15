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
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.faces.event.AjaxBehaviorEvent;
import javax.faces.model.SelectItem;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.util.DNFieldExtractor;
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
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherDoesntExistsException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
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

    private static final Map<Integer, String> AVAILABLE_PUBLISHERS;
    private static final Map<Integer, String> AVAILABLE_SAM_ACCOUNTS;
    private final Map<Class <? extends BasePublisher>, Runnable> publisherInitMap = new HashMap<>();
    private Map<String, Object> customPublisherPropertyValues;
    private List<CustomPublisherProperty> availableCustomPublisherPropertyList;

    static {
        AVAILABLE_PUBLISHERS = new LinkedHashMap<>();
        AVAILABLE_PUBLISHERS.put(PublisherConst.TYPE_LDAPPUBLISHER, "LDAPPUBLISHER");
        AVAILABLE_PUBLISHERS.put(PublisherConst.TYPE_LDAPSEARCHPUBLISHER, "LDAPSEARCHPUBLISHER");
        AVAILABLE_PUBLISHERS.put(PublisherConst.TYPE_ADPUBLISHER, "ACTIVEDIRECTORYPUBLISHER");
        AVAILABLE_PUBLISHERS.put(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER, "CUSTOMPUBLISHER");
        AVAILABLE_PUBLISHERS.put(PublisherConst.TYPE_MULTIGROUPPUBLISHER, "MULTIGROUPPUBLISHER");
        
        AVAILABLE_SAM_ACCOUNTS = new LinkedHashMap<>();
        AVAILABLE_SAM_ACCOUNTS.put(DNFieldExtractor.UPN, "MATCHUPN");
        AVAILABLE_SAM_ACCOUNTS.put(DNFieldExtractor.CN, "MATCHCOMMONNAME");
        AVAILABLE_SAM_ACCOUNTS.put(DNFieldExtractor.UID, "MATCHUID");
        AVAILABLE_SAM_ACCOUNTS.put(DNFieldExtractor.SN, "MATCHDNSERIALNUMBER");
        AVAILABLE_SAM_ACCOUNTS.put(DNFieldExtractor.GIVENNAME, "MATCHGIVENNAME");
        AVAILABLE_SAM_ACCOUNTS.put(DNFieldExtractor.SURNAME, "MATCHSURNAME");
    }
    
    private String selectedPublisherType;

    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private PublisherQueueSessionLocal publisherqueuesession;
    @EJB
    private CAAdminSessionLocal cAAdminSession;
    
    private LdapPublisherMBData ldapPublisherMBData;
    private LdapSearchPublisherMBData ldapSearchPublisherMBData;
    private ActiveDirectoryPublisherMBData activeDirectoryPublisherMBData;
    private MultiGroupPublisherMBData multiGroupPublisherMBData;
    
    public MultiGroupPublisherMBData getMultiGroupPublisherMBData() {
        return multiGroupPublisherMBData;
    }

    public ActiveDirectoryPublisherMBData getActiveDirectoryPublisherMBData() {
        return activeDirectoryPublisherMBData;
    }

    public LdapSearchPublisherMBData getLdapSearchPublisherMBData() {
        return ldapSearchPublisherMBData;
    }

    public LdapPublisherMBData getLdapPublisherMBData() {
        return ldapPublisherMBData;
    }

    private BasePublisher publisher = null;
    private Integer publisherId = null;
    
    public int getPublisherId(){
        return publisherId;
    }

    private String customPublisherPropertyData;
    private String customPublisherCurrentClass;

    private String publisherDescription;
    private boolean useQueueForCertificates;
    private boolean useQueueForCRLs;
    private boolean keepPublishedInQueue;
    private boolean onlyUseQueue;

    @ManagedProperty(value = "#{listPublishers}")
    private ListPublishersManagedBean listPublishers;

    public ListPublishersManagedBean getListPublishers() {
        return listPublishers;
    }

    public void setListPublishers(final ListPublishersManagedBean listPublishers) {
        this.listPublishers = listPublishers;
    }

    @PostConstruct
    public void init() {
        initializePage();
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
        for (final int publisherType : AVAILABLE_PUBLISHERS.keySet()) {
            if (publisherType == PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER) {
                for (final String klass : getCustomClasses()) {
                    availablePublisherTypes.add(new SortableSelectItem(String.valueOf(publisherType) + "-" + klass, getPublisherName(klass)));
                }
            } else {
                // Add built in publisher types
                availablePublisherTypes.add(new SortableSelectItem(String.valueOf(publisherType), getEjbcaWebBean().getText(AVAILABLE_PUBLISHERS.get(publisherType))));
            }
        }
        // Allow selection of any class path
        if (WebConfiguration.isManualClassPathsEnabled()) {
            availablePublisherTypes.add(new SortableSelectItem(String.valueOf(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER),
                    getEjbcaWebBean().getText(AVAILABLE_PUBLISHERS.get(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER))));
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
        
        if (customNoLongerAvailable) {
            availablePublisherTypes.add(new SortableSelectItem(selectedPublisherValue, selectedPublisherValue.split("-")[1]));
        }
        
        Collections.sort(availablePublisherTypes);
        return availablePublisherTypes;
    }

    private String getSelectedPublisherValue() {
        if (getPublisherType() == PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER) {
            final CustomPublisherContainer custompublisher = (CustomPublisherContainer) publisher;
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
        return getEjbcaWebBean().getText("PUBLISHER") + " : " + listPublishers.getSelectedPublisherName();
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
            text = klassSimpleName + " (" + getEjbcaWebBean().getText(AVAILABLE_PUBLISHERS.get(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER)) + ")";
        }
        return text;
    }

    public String getCustomPublisherPropertyData() {
        return customPublisherPropertyData;
    }

    public void setCustomPublisherPropertyData(final String customPublisherPropertyData) {
        this.customPublisherPropertyData = customPublisherPropertyData;
    }
    
    public String getSelectedPublisherType() {
        return selectedPublisherType;
    }

    public void setSelectedPublisherType(final String selectedPublisherType) {
        this.selectedPublisherType = selectedPublisherType;
    }
    
    public Map<String, Object> getCustomPublisherPropertyValues() {
        return customPublisherPropertyValues;
    }

    public String getPublisherQueue() {
        final int[] times = getPublisherQueueLength(new int[]{0, 1*60, 10*60, 60*60}, new int[]{1*60, 10*60, 60*60, -1});
        return Arrays.stream(times).mapToObj(Integer::toString).collect(Collectors.joining(", "));
    }
    
    private int[] getPublisherQueueLength(final int[] intervalLower, final int[] intervalUpper) {
        return publisherqueuesession.getPendingEntriesCountForPublisherInIntervals(publisherSession.getPublisherId(listPublishers.getSelectedPublisherName()), intervalLower, intervalUpper);
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
    
    public List<SelectItem> getSAMAccountName() {
        final List<SelectItem> samAccountName = new ArrayList<>();
        for (final int accountName : AVAILABLE_SAM_ACCOUNTS.keySet()) {
            samAccountName.add(new SelectItem(accountName, AVAILABLE_SAM_ACCOUNTS.get(accountName)));
        }
        return samAccountName;
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
        if (publisher instanceof CustomPublisherContainer) {
            return ((CustomPublisherContainer) publisher).isCustomUiRenderingSupported();
        } else
            return false;
    }
    
    public List<CustomPublisherProperty> getCustomUiPropertyList() {
        if (publisher instanceof CustomPublisherContainer) {
            availableCustomPublisherPropertyList = new ArrayList<>();
            for (CustomPublisherProperty property : ((CustomPublisherContainer) publisher).getCustomUiPropertyList(getAdmin())) {
                availableCustomPublisherPropertyList.add(property);
            }
            return this.availableCustomPublisherPropertyList;
        }
        return Collections.<CustomPublisherProperty> emptyList();
    }
   
    public String getCustomPublisherPropertyText(final CustomPublisherProperty customPublisherProperty) {
        return getEjbcaWebBean()
                .getText(getCurrentClassSimple().toUpperCase() + "_" + customPublisherProperty.getName().replaceAll("\\.", "_").toUpperCase());
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
    
    public boolean renderCustomTextInput(final CustomPublisherProperty customPublisherProperty) {
        return customPublisherProperty.getType() == CustomPublisherProperty.UI_TEXTINPUT;
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

    public String changePublisherType(AjaxBehaviorEvent event) {
        int dashPos = selectedPublisherType.indexOf('-');
        if (dashPos == -1) {
            switch (Integer.valueOf(selectedPublisherType)) {
            case PublisherConst.TYPE_ADPUBLISHER:
                publisher = new ActiveDirectoryPublisher();
                break;
            case PublisherConst.TYPE_LDAPPUBLISHER:
                publisher = new LdapPublisher();
                break;
            case PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER:
                publisher = new CustomPublisherContainer();
                break;
            case PublisherConst.TYPE_LDAPSEARCHPUBLISHER:
                publisher = new LdapSearchPublisher();
                break;
            case PublisherConst.TYPE_MULTIGROUPPUBLISHER:
                publisher = new MultiGroupPublisher();
                break;
            default:
                break;
            }
        } else {
            publisher = new CustomPublisherContainer();
            final String customClassName = selectedPublisherType.substring(dashPos + 1);
            if (getCustomClasses().contains(customClassName)) {
                ((CustomPublisherContainer) publisher).setClassPath(customClassName);
            }
        }
        initializePage();
        return "editpublisher";
    }
    
    public boolean renderLdapPublisherPage() {
        return publisher instanceof LdapPublisher;
    }

    public boolean renderLdapSearchPublisherPage() {
        return publisher instanceof LdapSearchPublisher;
    }

    public boolean renderActiveDirectoryPublisherPage() {
        return publisher instanceof ActiveDirectoryPublisher;
    }

    public boolean renderCustomPublisherPage() {
        return publisher instanceof CustomPublisherContainer;
    }

    public boolean renderMultiGroupPublisherPage() {
        return publisher instanceof MultiGroupPublisher;
    }
    
    public List<SelectItem> getAvailableSamAccountNames() {
        List<SelectItem> result = new ArrayList<>();
        for(final int samAccount : AVAILABLE_SAM_ACCOUNTS.keySet()){ 
            result.add(new SelectItem(samAccount, getEjbcaWebBean().getText(AVAILABLE_SAM_ACCOUNTS.get(samAccount))));
        }
        return result;
    }
    

    public String getCustomPublisherCurrentClass() {
        return customPublisherCurrentClass;
    }

    public void setCustomPublisherCurrentClass(final String customPublisherCurrentClass) {
        this.customPublisherCurrentClass = customPublisherCurrentClass;
    }

    public String getPublisherDescription() {
        return publisherDescription;
    }

    public void setPublisherDescription(String publisherDescription) {
        this.publisherDescription = publisherDescription;
    }

    public boolean isUseQueueForCertificates() {
        return useQueueForCertificates;
    }

    public void setUseQueueForCertificates(boolean useQueueForCertificates) {
        this.useQueueForCertificates = useQueueForCertificates;
    }

    public boolean isUseQueueForCRLs() {
        return useQueueForCRLs;
    }

    public void setUseQueueForCRLs(boolean useQueueForCRLs) {
        this.useQueueForCRLs = useQueueForCRLs;
    }

    public boolean isKeepPublishedInQueue() {
        return keepPublishedInQueue;
    }

    public void setKeepPublishedInQueue(boolean keepPublishedInQueue) {
        this.keepPublishedInQueue = keepPublishedInQueue;
    }

    public boolean isOnlyUseQueue() {
        return onlyUseQueue;
    }

    public void setOnlyUseQueue(boolean onlyUseQueue) {
        this.onlyUseQueue = onlyUseQueue;
    }
    
    //Actions
    public String savePublisher() throws AuthorizationDeniedException {
        prepareForSave();
        publisherSession.changePublisher(getAdmin(), listPublishers.getSelectedPublisherName(), publisher);
        return "listpublishers?faces-redirect=true";
    }
    
    public void savePublisherAndTestConnection() throws AuthorizationDeniedException {
        prepareForSave();
        publisherSession.changePublisher(getAdmin(), listPublishers.getSelectedPublisherName(), publisher);
        try {
            publisherSession.testConnection(publisherId);
            addInfoMessage(getEjbcaWebBean().getText("CONTESTEDSUCESSFULLY"));
        } catch (PublisherConnectionException pce) {
            log.error("Error connecting to publisher " + listPublishers.getSelectedPublisherName(), pce);
            addErrorMessage(getEjbcaWebBean().getText("ERRORCONNECTINGTOPUB"), listPublishers.getSelectedPublisherName());
        }
    }
    
    private void prepareForSave() {
        //Set General Settings
        setPublisherQueueAndGeneralSettings();
        
        if (publisher instanceof LdapPublisher) {
            ldapPublisherMBData.setLdapPublisherParameters((LdapPublisher) publisher);
        } 
        
        if (publisher instanceof ActiveDirectoryPublisher) {
            activeDirectoryPublisherMBData.setActiveDirectoryPublisherParameters((ActiveDirectoryPublisher) publisher);
        }
        
        if (publisher instanceof LdapSearchPublisher) {
            ldapSearchPublisherMBData.setLdapSearchPublisherParameters((LdapSearchPublisher) publisher);
        }
        
        if (publisher instanceof MultiGroupPublisher) {
            try {
                multiGroupPublisherMBData.setMultiGroupPublisherParameters((MultiGroupPublisher) publisher);
            } catch (PublisherDoesntExistsException | PublisherExistsException e) {
                addErrorMessage(e.getMessage());
            }
        }
        
        if (publisher instanceof CustomPublisherContainer) {
            setCustomPublisherData();
        }
         
    }

    private void setCustomPublisherData() {
        final CustomPublisherContainer customPublisherContainer = ((CustomPublisherContainer) publisher);
        customPublisherContainer.setClassPath(customPublisherCurrentClass);
        if (customPublisherContainer.isCustomUiRenderingSupported()) {
            final StringBuilder sb = new StringBuilder();
            for (final CustomPublisherProperty customPublisherProperty : customPublisherContainer.getCustomUiPropertyList(getAdmin())) { 
                if (customPublisherProperty.getType() == CustomPublisherProperty.UI_BOOLEAN) {
                    if (((Boolean)customPublisherPropertyValues.get(customPublisherProperty.getName()))) {
                        sb.append(customPublisherProperty.getName()).append('=').append("true").append('\n');
                    } else {
                        sb.append(customPublisherProperty.getName()).append('=').append("false").append('\n');
                    }
                } else {
                    if (customPublisherPropertyValues.get(customPublisherProperty.getName()) != null) {
                        sb.append(customPublisherProperty.getName()).append('=')
                                .append(customPublisherPropertyValues.get(customPublisherProperty.getName())).append('\n');
                    }
                }
            }
            customPublisherContainer.setPropertyData(sb.toString());
        } else {
            customPublisherContainer.setPropertyData(customPublisherPropertyData);
        }
    }

    private void setPublisherQueueAndGeneralSettings() {
        publisher.setOnlyUseQueue(onlyUseQueue);
        publisher.setKeepPublishedInQueue(keepPublishedInQueue);
        publisher.setUseQueueForCRLs(useQueueForCRLs);
        publisher.setUseQueueForCertificates(useQueueForCertificates);
        publisher.setDescription(publisherDescription);        
    }

    private Void initLdapPublisher() {
        ldapPublisherMBData = new LdapPublisherMBData((LdapPublisher) publisher);
        return null;
    }    
    
    private Void initLdapSearchPublisher() {
        ldapPublisherMBData = new LdapPublisherMBData((LdapPublisher) publisher);
        ldapSearchPublisherMBData = new LdapSearchPublisherMBData((LdapSearchPublisher) publisher);
        return null;
    }

    private Void initActiveDirectoryPublisher() {
        ldapPublisherMBData = new LdapPublisherMBData((LdapPublisher) publisher);
        activeDirectoryPublisherMBData = new ActiveDirectoryPublisherMBData((ActiveDirectoryPublisher) publisher);
        return null;
    }
    
    private Void initMultiGroupPublisher() {
        multiGroupPublisherMBData = new MultiGroupPublisherMBData((MultiGroupPublisher) publisher);
        return null;
    }

    private Void initCustomPublisher() {
        customPublisherCurrentClass = ((CustomPublisherContainer) publisher).getClassPath();
        customPublisherPropertyData = ((CustomPublisherContainer) publisher).getPropertyData();

        customPublisherPropertyValues = new HashMap<>();

        for (final CustomPublisherProperty customPublisherProperty : ((CustomPublisherContainer) publisher).getCustomUiPropertyList(getEjbcaWebBean().getAdminObject())) {
                customPublisherPropertyValues.put(customPublisherProperty.getName(), customPublisherProperty.getValue());
        }
        return null;
    }
    
    private String getCurrentClassSimple() {
        if (publisher instanceof CustomPublisherContainer) {
            final String currentCustomClass = ((CustomPublisherContainer) publisher).getClassPath();
            return currentCustomClass.substring(currentCustomClass.lastIndexOf('.') + 1);
        }
        return StringUtils.EMPTY;
    }
    
    private String getCurrentClassText() {
        if (publisher instanceof CustomPublisherContainer) {
            CustomPublisherContainer custompublisher = (CustomPublisherContainer) publisher;
            final String currentClass = custompublisher.getClassPath();
            final String currentClassSimple = currentClass.substring(currentClass.lastIndexOf('.') + 1);
            String currentClassText = getEjbcaWebBean().getText(currentClassSimple.toUpperCase());
            if (currentClassText.equals(currentClassSimple.toUpperCase())) {
                currentClassText = currentClassSimple;
            }
            return currentClassText;
        }
        return StringUtils.EMPTY;
    }

    
    private void initializePage() {
        initCommonParts();
        publisherInitMap.get(publisher.getClass()).run();
    }

    private void initCommonParts() {
        if (publisher == null) { // Loading from database
            publisher = publisherSession.getPublisher(listPublishers.getSelectedPublisherName());
            publisherId = publisher.getPublisherId();
            fillPublisherInitMapAndInitPublisherData();
        }

        selectedPublisherType = getSelectedPublisherValue();
        publisherDescription = publisher.getDescription();
        onlyUseQueue = publisher.getOnlyUseQueue();
        keepPublishedInQueue = publisher.getKeepPublishedInQueue();
        useQueueForCRLs = publisher.getUseQueueForCRLs();
        useQueueForCertificates = publisher.getUseQueueForCertificates();
    }

    private void fillPublisherInitMapAndInitPublisherData() {
        publisherInitMap.put(ActiveDirectoryPublisher.class, () -> initActiveDirectoryPublisher());
        publisherInitMap.put(LdapSearchPublisher.class, () -> initLdapSearchPublisher());
        publisherInitMap.put(LdapPublisher.class, () -> initLdapPublisher()); 
        publisherInitMap.put(CustomPublisherContainer.class, () -> initCustomPublisher());
        publisherInitMap.put(MultiGroupPublisher.class, () -> initMultiGroupPublisher());
    }
    
}
