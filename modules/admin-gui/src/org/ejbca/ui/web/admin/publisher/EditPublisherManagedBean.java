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
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
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

    static {
        AVAILABLEPUBLISHERS.put(PublisherConst.TYPE_LDAPPUBLISHER, "LDAPPUBLISHER");
        AVAILABLEPUBLISHERS.put(PublisherConst.TYPE_LDAPSEARCHPUBLISHER, "LDAPSEARCHPUBLISHER");
        AVAILABLEPUBLISHERS.put(PublisherConst.TYPE_ADPUBLISHER, "ACTIVEDIRECTORYPUBLISHER");
        AVAILABLEPUBLISHERS.put(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER, "CUSTOMPUBLISHER");
        AVAILABLEPUBLISHERS.put(PublisherConst.TYPE_MULTIGROUPPUBLISHER, "MULTIGROUPPUBLISHER");
    }
    
    private String selectedPublisherType;

    @EJB
    private PublisherSessionLocal publisherSession;

    private BasePublisher basePublisher;

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
        this.basePublisher = publisherSession.getPublisher(listPublishersManagedBean.getSelectedPublisherName());
    }

    public void initAccess() throws Exception {
        // To check access 
        if (!FacesContext.getCurrentInstance().isPostback()) {
            final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
            getEjbcaWebBean().initialize(request, AccessRulesConstants.REGULAR_VIEWPUBLISHER);
        }
    }

    public List<SelectItem> getAvailablePublisherTypes() {
        final List<SelectItem> availablePublisherTypes = new ArrayList<>();
        // List all built in publisher types and all the dynamic ones
        for (final int publisherType : AVAILABLEPUBLISHERS.keySet()) {
            if (publisherType == PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER) {
                for (final String klass : getCustomClasses()) {
                    availablePublisherTypes.add(new SelectItem(publisherType + "-" + klass, getPublisherName(klass)));
                }
            } else {
                // Add built in publisher types
                availablePublisherTypes.add(new SelectItem(publisherType, getEjbcaWebBean().getText(AVAILABLEPUBLISHERS.get(publisherType))));
            }
        }
        // Allow selection of any class path
        if (WebConfiguration.isManualClassPathsEnabled()) {
            availablePublisherTypes.add(new SelectItem(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER,
                    getEjbcaWebBean().getText(AVAILABLEPUBLISHERS.get(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER))));
        }
        // If an publisher was configured before the plugin mechanism we still want to show it
        boolean customNoLongerAvailable = true;
        final String selectedPublisherValue = getSelectedPublisherValue();
        for (final SelectItem current : availablePublisherTypes) {
            if (current.getValue().equals(selectedPublisherValue)) {
                customNoLongerAvailable = false;
                break;
            }
        }
/*        if (customNoLongerAvailable) {
            log.error("Amin the selected publisher value is " + selectedPublisherValue);
            
            availablePublisherTypes.add(new SelectItem(selectedPublisherValue, selectedPublisherValue.split("-")[1]));
        }*/
        // Sort by label
        Collections.sort(availablePublisherTypes, new Comparator<SelectItem>() {
            @Override
            public int compare(final SelectItem selectItem0, final SelectItem selectItem1) {
                return String.valueOf(selectItem0.getLabel()).compareTo(String.valueOf(selectItem1.getLabel()));
            }
        });
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
        if (basePublisher instanceof CustomPublisherContainer) {
            retval = PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER;
        }
        if (basePublisher instanceof LdapPublisher) {
            retval = PublisherConst.TYPE_LDAPPUBLISHER;
        }
        if (basePublisher instanceof LdapSearchPublisher) {
            retval = PublisherConst.TYPE_LDAPSEARCHPUBLISHER;
        }
        // Legacy VA publisher doesn't exist in community edition, so check the qualified class name instead.
        if (basePublisher.getClass().getName().equals("org.ejbca.core.model.ca.publisher.ValidationAuthorityPublisher")) {
            retval = PublisherConst.TYPE_VAPUBLISHER;
        }
        if (basePublisher instanceof ActiveDirectoryPublisher) {
            retval = PublisherConst.TYPE_ADPUBLISHER;
        }
        if (basePublisher instanceof MultiGroupPublisher) {
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
        } else if (basePublisher instanceof CustomPublisherContainer) {
            ICustomPublisher pub = ((CustomPublisherContainer) basePublisher).getCustomPublisher();
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
        return basePublisher.getClass().getName().equals(LegacyValidationAuthorityPublisher.OLD_VA_PUBLISHER_QUALIFIED_NAME);
    }

    public List<String> getCustomClasses() {
        final List<String> classes = new ArrayList<>();
        final ServiceLoader<ICustomPublisher> svcloader = ServiceLoader.load(ICustomPublisher.class);
        final boolean enabled = ((GlobalConfiguration) getEjbcaWebBean().getEjb().getGlobalConfigurationSession()
                .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableExternalScripts();
        String name = null;
        for (ICustomPublisher implInstance : svcloader) {
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

}
