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
import javax.faces.event.AjaxBehaviorEvent;
import javax.faces.view.ViewScoped;
import javax.inject.Inject;
import javax.inject.Named;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
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
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.ui.web.ParameterException;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.SortableSelectItem;

/**
 * 
 *
 */
@Named("editPublisher")
@ViewScoped
public class EditPublisherManagedBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(EditPublisherManagedBean.class);

    private static final Map<Integer, String> AVAILABLE_PUBLISHERS;
    private final Map<Class <? extends BasePublisher>, Runnable> publisherInitMap = new HashMap<>();
    private List<CustomPublisherProperty> availableCustomPublisherPropertyList;

    static {
        AVAILABLE_PUBLISHERS = new LinkedHashMap<>();
        AVAILABLE_PUBLISHERS.put(PublisherConst.TYPE_LDAPPUBLISHER, "LDAPPUBLISHER");
        AVAILABLE_PUBLISHERS.put(PublisherConst.TYPE_LDAPSEARCHPUBLISHER, "LDAPSEARCHPUBLISHER");
        AVAILABLE_PUBLISHERS.put(PublisherConst.TYPE_ADPUBLISHER, "ACTIVEDIRECTORYPUBLISHER");
        AVAILABLE_PUBLISHERS.put(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER, "CUSTOMPUBLISHER");
        AVAILABLE_PUBLISHERS.put(PublisherConst.TYPE_MULTIGROUPPUBLISHER, "MULTIGROUPPUBLISHER");
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
    private CustomPublisherMBData customPublisherMBData;

    public LdapPublisherMBData getLdapPublisherMBData() {
        return ldapPublisherMBData;
    }
    
    public LdapSearchPublisherMBData getLdapSearchPublisherMBData() {
        return ldapSearchPublisherMBData;
    }

    public ActiveDirectoryPublisherMBData getActiveDirectoryPublisherMBData() {
        return activeDirectoryPublisherMBData;
    }
    
    public MultiGroupPublisherMBData getMultiGroupPublisherMBData() {
        return multiGroupPublisherMBData;
    }
    
    public CustomPublisherMBData getCustomPublisherMBData() {
        return customPublisherMBData;
    }

    private BasePublisher publisher = null;
    private Integer publisherId = null;
    
    public int getPublisherId(){
        return publisherId;
    }

    private String publisherDescription;
    private boolean useQueueForCertificates;
    private boolean useQueueForCRLs;
    private boolean useQueueForOcspResponses;
    private boolean keepPublishedInQueue;
    private boolean onlyUseQueue;
    private boolean safeDirectPublishing;

    @Inject
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

    public EditPublisherManagedBean() {
        super(AccessRulesConstants.REGULAR_VIEWPUBLISHER);
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
        if (publisher.getClass().getName().equals(LegacyValidationAuthorityPublisher.OLD_VA_PUBLISHER_QUALIFIED_NAME)) {
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
    
    public String getSelectedPublisherType() {
        return selectedPublisherType;
    }

    public void setSelectedPublisherType(final String selectedPublisherType) {
        this.selectedPublisherType = selectedPublisherType;
    }

    public String getPublisherQueue() {
        final int[] times = getPublisherQueueLength(new int[]{1*60, 10*60, 60*60, -1}, new int[]{0, 1*60, 10*60, 60*60});
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
        for (final int authPublisherId : authorizedPublisherIds) {
            if (!publisherIdToNameMap.containsKey(authPublisherId)) {
                log.warn("Cannot find publisher with ID " + publisherId + ". Perhaps it is not allowed with external scripts disabled?");
                continue;
            }
            availablePublisherList.add(publisherIdToNameMap.get(authPublisherId));
        }
        Collections.sort(availablePublisherList);
        return availablePublisherList;
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

    public String changePublisherType(AjaxBehaviorEvent event) {
        int dashPos = selectedPublisherType.indexOf('-');
        if (dashPos == -1) {
            publisher = publisherSession.createPublisherObjectFromTypeId(Integer.valueOf(selectedPublisherType));
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
    
    public boolean isRenderLdapPublisherPage() {
        return publisher instanceof LdapPublisher;
    }

    public boolean isRenderLdapSearchPublisherPage() {
        return publisher instanceof LdapSearchPublisher;
    }

    public boolean isRenderActiveDirectoryPublisherPage() {
        return publisher instanceof ActiveDirectoryPublisher;
    }

    public boolean isRenderCustomPublisherPage() {
        return publisher instanceof CustomPublisherContainer;
    }

    public boolean isRenderMultiGroupPublisherPage() {
        return publisher instanceof MultiGroupPublisher;
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
    
    public boolean isUseQueueForOcspResponses() {
        return useQueueForOcspResponses;
    }

    public void setUseQueueForOcspResponses(boolean useQueueForOcspResponses) {
        this.useQueueForOcspResponses = useQueueForOcspResponses;
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
    
    public boolean isSafeDirectPublishing() {
        return safeDirectPublishing;
    }

    public void setSafeDirectPublishing(boolean safeDirectPublishing) {
        this.safeDirectPublishing = safeDirectPublishing;
    }

    public String getCustomPublisherPropertyText(final CustomPublisherProperty customPublisherProperty) {
        return getEjbcaWebBean()
                .getText(getCurrentClassSimple().toUpperCase() + "_" + customPublisherProperty.getName().replaceAll("\\.", "_").toUpperCase());
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
    
    //Actions
    public String savePublisher() throws AuthorizationDeniedException {
        try {
            prepareForSave();
        } catch (PublisherDoesntExistsException | PublisherExistsException | PublisherException | ParameterException e) {
            addErrorMessage(e.getMessage());
            return StringUtils.EMPTY;
        }
        publisherSession.changePublisher(getAdmin(), listPublishers.getSelectedPublisherName(), publisher);
        return "listpublishers?faces-redirect=true";
    }
    
    public void savePublisherAndTestConnection() throws AuthorizationDeniedException {
        try {
            prepareForSave();
        } catch (PublisherDoesntExistsException | PublisherExistsException | PublisherException | ParameterException e) {
            addErrorMessage(e.getMessage());
            return;
        }
        publisherSession.changePublisher(getAdmin(), listPublishers.getSelectedPublisherName(), publisher);
        try {
            publisherSession.testConnection(publisherId);
            addInfoMessage("CONTESTEDSUCESSFULLY");
        } catch (PublisherConnectionException pce) {
            log.error("Error connecting to publisher " + listPublishers.getSelectedPublisherName(), pce);
            addErrorMessage("ERRORCONNECTINGTOPUB", listPublishers.getSelectedPublisherName(), pce.getMessage());
        }
    }
    
    // This is ugly but could not find a better way for it
    public boolean isPublisherSupportingOcspResponses() {
        return StringUtils.contains(selectedPublisherType, "PeerPublisher")
                || StringUtils.contains(selectedPublisherType, "EnterpriseValidationAuthorityPublisher");
    }
    
    private void prepareForSave() throws PublisherDoesntExistsException, PublisherExistsException, PublisherException, ParameterException {
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
            multiGroupPublisherMBData.setMultiGroupPublisherParameters((MultiGroupPublisher) publisher);
        }
        
        if (publisher instanceof CustomPublisherContainer) {
            customPublisherMBData.setCustomPublisherData((CustomPublisherContainer) publisher);
        }
    }

    private void setPublisherQueueAndGeneralSettings() {
        publisher.setOnlyUseQueue(onlyUseQueue);
        publisher.setSafeDirectPublishing(safeDirectPublishing);
        publisher.setKeepPublishedInQueue(keepPublishedInQueue);
        publisher.setUseQueueForCRLs(useQueueForCRLs);
        publisher.setUseQueueForCertificates(useQueueForCertificates);
        publisher.setUseQueueForOcspResponses(useQueueForOcspResponses);
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
        customPublisherMBData = new CustomPublisherMBData((CustomPublisherContainer) publisher);
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
        safeDirectPublishing = publisher.getSafeDirectPublishing();
        keepPublishedInQueue = publisher.getKeepPublishedInQueue();
        useQueueForCRLs = publisher.getUseQueueForCRLs();
        useQueueForCertificates = publisher.getUseQueueForCertificates();
        useQueueForOcspResponses = publisher.getUseQueueForOcspResponses();
    }

    private void fillPublisherInitMapAndInitPublisherData() {
        publisherInitMap.put(ActiveDirectoryPublisher.class, () -> initActiveDirectoryPublisher());
        publisherInitMap.put(LdapSearchPublisher.class, () -> initLdapSearchPublisher());
        publisherInitMap.put(LdapPublisher.class, () -> initLdapPublisher()); 
        publisherInitMap.put(CustomPublisherContainer.class, () -> initCustomPublisher());
        publisherInitMap.put(MultiGroupPublisher.class, () -> initMultiGroupPublisher());
    }
    
}
