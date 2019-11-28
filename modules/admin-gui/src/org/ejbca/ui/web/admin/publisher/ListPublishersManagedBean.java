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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.common.exception.ReferencesToItemExistException;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.publisher.ActiveDirectoryPublisher;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.LdapPublisher;
import org.ejbca.core.model.ca.publisher.LdapSearchPublisher;
import org.ejbca.core.model.ca.publisher.MultiGroupPublisher;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherDoesntExistsException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.SortableSelectItem;

/**
 * Managed bean to back the list publisher xhtml page.
 * 
 * @version $Id$
 *
 */
@ManagedBean(name = "listPublishers")
@SessionScoped
public class ListPublishersManagedBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(ListPublishersManagedBean.class);
    
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    
    private String selectedPublisherName;
    private String newPublisherName = StringUtils.EMPTY;
    
    private static final Map<Integer, String> AVAILABLE_PUBLISHERS;

    static {
        AVAILABLE_PUBLISHERS = new LinkedHashMap<>();
        AVAILABLE_PUBLISHERS.put(PublisherConst.TYPE_LDAPPUBLISHER, "LDAPPUBLISHER");
        AVAILABLE_PUBLISHERS.put(PublisherConst.TYPE_LDAPSEARCHPUBLISHER, "LDAPSEARCHPUBLISHER");
        AVAILABLE_PUBLISHERS.put(PublisherConst.TYPE_ADPUBLISHER, "ACTIVEDIRECTORYPUBLISHER");
        AVAILABLE_PUBLISHERS.put(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER, "CUSTOMPUBLISHER");
        AVAILABLE_PUBLISHERS.put(PublisherConst.TYPE_MULTIGROUPPUBLISHER, "MULTIGROUPPUBLISHER");
    }
    
    public void initAccess() throws Exception {
        // To check access 
        if (!FacesContext.getCurrentInstance().isPostback()) {
            final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
            getEjbcaWebBean().initialize(request, AccessRulesConstants.REGULAR_VIEWPUBLISHER);
        }
    }
    
    public String getSelectedPublisherName() {
        return selectedPublisherName;
    }

    public void setSelectedPublisherName(final String selectedPublisherName) {
        this.selectedPublisherName = selectedPublisherName;
    }

    public String getNewPublisherName() {
        return newPublisherName;
    }

    public void setNewPublisherName(final String newPublisherName) {
        this.newPublisherName = newPublisherName;
    }
    
    public List<SortableSelectItem> getAvailablePublishers() {
        List<SortableSelectItem> availablePublishers = new ArrayList<>();
        getEjbcaWebBean().getAuthorizedPublisherNames().forEach(publisher -> availablePublishers.add(new SortableSelectItem(publisher, publisher + " (" + getPublisherType(publisher) + ") ")));
        Collections.sort(availablePublishers);
        return availablePublishers;
    }

    // Actions //
    public String editPublisher() {
        if (StringUtils.isNotEmpty(selectedPublisherName)) {
            return "editpublisher?faces-redirect=true";
        } else {
            addErrorMessage("YOUHAVETOSELECTAPUBLISHER");
            return "listpublishers";
        }
    }
    
    public String deletePublisher() throws AuthorizationDeniedException {
        if (StringUtils.isNotEmpty(selectedPublisherName)) {
            try {
                publisherSession.removePublisher(getAdmin(), selectedPublisherName);
            } catch (ReferencesToItemExistException e) {
                log.info("Error while deleting the publisher " + selectedPublisherName + e);
                addErrorMessage("COULDNTDELETEPUBLISHERDUETOEXISTINGREF");
            }
        } else {
            addErrorMessage("YOUHAVETOSELECTAPUBLISHER");
        }
        newPublisherName = StringUtils.EMPTY;
        return "listpublishers";
    }
    
    public String renamePublisher() throws AuthorizationDeniedException {
        if (StringUtils.isEmpty(selectedPublisherName)) {
            addErrorMessage("YOUHAVETOSELECTAPUBLISHER");
        } else if (StringUtils.isEmpty(StringUtils.trim(newPublisherName))) {
            addErrorMessage("YOUHAVETOENTERAPUBLISHER");
        } else {
            try {
                publisherSession.renamePublisher(getAdmin(), selectedPublisherName, newPublisherName);
            } catch (PublisherExistsException e) {
                log.info("Publisher " + newPublisherName + " already exists!", e);
                addErrorMessage("PUBLISHERALREADYEXISTS", newPublisherName);
            }
        }
        newPublisherName = StringUtils.EMPTY;
        return "listpublishers";
    }
    
    public String addPublisher() throws AuthorizationDeniedException {
        if (StringUtils.isEmpty(StringUtils.trim(newPublisherName))) {
            addErrorMessage("YOUHAVETOENTERAPUBLISHER");
        } else {
            try {
                publisherSession.addPublisher(getAdmin(), newPublisherName, new LdapPublisher());
            } catch (PublisherExistsException e) {
                log.info("Publisher " + newPublisherName + " already exists!", e);
                addErrorMessage("PUBLISHERALREADYEXISTS", newPublisherName);
            }
        }
        newPublisherName = StringUtils.EMPTY;
        return "listpublishers";
    }    
    
    public String clonePublisher() throws AuthorizationDeniedException {
        if (StringUtils.isEmpty(selectedPublisherName)) {
            addErrorMessage("YOUHAVETOSELECTAPUBLISHER");
        } else if (StringUtils.isEmpty(StringUtils.trim(newPublisherName))) {
            addErrorMessage("YOUHAVETOENTERAPUBLISHER");
        } else {            
                try {
                    publisherSession.clonePublisher(getAdmin(), selectedPublisherName, newPublisherName);
                } catch (PublisherDoesntExistsException e) {
                    log.info("Publisher " + selectedPublisherName + " does not exists!", e);
                    addErrorMessage("PUBLISHERDOESNOTEXISTS", selectedPublisherName);
                } catch (PublisherExistsException e) {
                    log.info("Publisher " + newPublisherName + " already exists!", e);
                    addErrorMessage("PUBLISHERALREADYEXISTS", newPublisherName);
                }
        }
        newPublisherName = StringUtils.EMPTY;
        return "listpublishers";
    }
    
    /** 
     * @return true if admin has access to /ca_functionality/edit_publisher/
     */
    public boolean getHasEditRights() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_EDITPUBLISHER);
    }
    
    private String getPublisherType(String publisherName) {
        BasePublisher publisher = publisherSession.getPublisher(publisherName);
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
        return getActualType(retval, publisher); 
    }

    private String getActualType(final int publisherType, final BasePublisher publisher) {
        if (publisherType == PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER) {
            final CustomPublisherContainer custompublisher = (CustomPublisherContainer) publisher;
            final String currentClass = custompublisher.getClassPath();
            if (currentClass == null || currentClass.isEmpty()) {
                return Integer.valueOf(PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER).toString();
            } else {
                return currentClass.substring(currentClass.lastIndexOf('.') + 1);
            }
        }
        return getEjbcaWebBean().getText(AVAILABLE_PUBLISHERS.get(publisherType));
    }

}
