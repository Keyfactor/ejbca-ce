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
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.publisher.ActiveDirectoryPublisher;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
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


    private static final Map<Integer, String> AVAILABLEPUBLISHERS = new HashMap<>();
    private static final Map<Integer, String> AVAILABLESAMACCOUNTS = new HashMap<>();
    private final Map<Class <? extends BasePublisher>, Runnable> PUBLISHERINIT = new HashMap<>();

    static {
        AVAILABLEPUBLISHERS.put(PublisherConst.TYPE_LDAPPUBLISHER, "LDAPPUBLISHER");
        AVAILABLEPUBLISHERS.put(PublisherConst.TYPE_LDAPSEARCHPUBLISHER, "LDAPSEARCHPUBLISHER");
        AVAILABLEPUBLISHERS.put(PublisherConst.TYPE_ADPUBLISHER, "ACTIVEDIRECTORYPUBLISHER");
        AVAILABLEPUBLISHERS.put(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER, "CUSTOMPUBLISHER");
        AVAILABLEPUBLISHERS.put(PublisherConst.TYPE_MULTIGROUPPUBLISHER, "MULTIGROUPPUBLISHER");
        
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
    }

    private Void initLdapPublisher() {
        // TODO Auto-generated method stub
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
    
    private Void initActiveDirectoryPublisher() {
        userDescription = ((ActiveDirectoryPublisher) publisher).getUserDescription();
        return null;
    }
    
    private Void initLdapSearchPublisher() {
        searchBaseDN = ((LdapSearchPublisher) publisher).getSearchBaseDN();
        searchFilter = ((LdapSearchPublisher) publisher).getSearchFilter();
        return null;
    }
    
}
