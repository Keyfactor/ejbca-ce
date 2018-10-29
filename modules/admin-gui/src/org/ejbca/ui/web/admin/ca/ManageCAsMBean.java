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
package org.ejbca.ui.web.admin.ca;

import java.beans.Beans;
import java.io.IOException;
import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

import javax.annotation.PostConstruct;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.cainterface.CADataHandler;
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;

/**
 * 
 * JSF MBean backing the manage ca page.
 *
 * @version $Id$
 * 
 */
@ManagedBean
@ViewScoped
public class ManageCAsMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(ManageCAsMBean.class);
    
    private TreeMap<String, Integer> canames = getEjbcaWebBean().getCANames();
    private CAInterfaceBean caBean;
    private int selectedCaId;
    private String createCaName;
    private boolean isEditCA;
    CADataHandler cadatahandler;
    Map<Integer, String> caidtonamemap;


    
    public String getCreateCaName() {
        return createCaName;
    }

    public void setCreateCaName(String createCaName) {
        this.createCaName = createCaName;
    }

    public void initAccess() throws Exception {
        // To check access 
        if (!FacesContext.getCurrentInstance().isPostback()) {
            final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
            getEjbcaWebBean().initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
        }
    }
    
    @PostConstruct
    public void init() {
        final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        caBean = (CAInterfaceBean) request.getSession().getAttribute("caBean");
        if (caBean == null) {
            try {
                caBean = (CAInterfaceBean) Beans.instantiate(Thread.currentThread().getContextClassLoader(),
                        CAInterfaceBean.class.getName());
            } catch (ClassNotFoundException | IOException e) {
                log.error("Error while instantiating the ca bean!", e);
            }
            request.getSession().setAttribute("cabean", caBean);
        }
        caBean.initialize(getEjbcaWebBean());
        cadatahandler = caBean.getCADataHandler();
        caidtonamemap = caBean.getCAIdToNameMap();
    }
    
    public Map<Integer, String> getListOfCas() {
        final Map<Integer, String> caMap = new LinkedHashMap<>();
        for (final String nameofca : canames.keySet()) {
            int caId = canames.get(nameofca).intValue();
            int caStatus = caBean.getCAStatusNoAuth(caId);

            String nameandstatus = nameofca + ", (" + getEjbcaWebBean().getText(CAConstants.getStatusText(caStatus)) + ")";
            if (caBean.isAuthorizedToCa(caId)) {
                caMap.put(caId, nameandstatus);
            }
        }
        return caMap;
    }
    
    public String getEditCAButtonValue() {
        return isAuthorized() ? getEjbcaWebBean().getText("VIECA") : getEjbcaWebBean().getText("EDITCA");
    }
    
    private boolean isAuthorized() {
        boolean onlyView = false;
        if (getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAEDIT.resource())
                || getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAVIEW.resource())) {
            onlyView = !getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAEDIT.resource())
                    && getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAVIEW.resource());
        }
        return onlyView;
    }
    
    public int getSelectedCaId() {
        return selectedCaId;
    }

    public void setSelectedCaId(final int selectedCaId) {
        this.selectedCaId = selectedCaId;
    }    
    
    public boolean isCanRemoveResource() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAREMOVE.resource());
    }
    
    public String getImportKeystoreText() {
        return getEjbcaWebBean().getText("IMPORTCA_KEYSTORE") + "...";
    }
    
    public boolean isCanAddResource() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAADD.resource());
    }
    
    public String getImportCertificateText() {
        return getEjbcaWebBean().getText("IMPORTCA_CERTIFICATE") + "...";
    }
    
    public boolean isCanRenewResource() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CARENEW.resource());
    }
    
    public boolean isCanAddOrEditResource() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAADD.resource())
                || getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAEDIT.resource());
    }
    
    public String getCreateCaNameTitle() {
        return " : " + this.createCaName;
    }
    
    public boolean isCanEditResource() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAEDIT.resource());
    }
    
    public String getConfirmMessage() {
        if (selectedCaId != 0) {
            return getEjbcaWebBean().getText("AREYOUSURETODELETECA", true, caidtonamemap.get(selectedCaId));
        } else {
            return StringUtils.EMPTY;
        }
    }

    public String updateIsEditCA(final boolean isEditCA) {
        if (!isEditCA && (createCaName == null || createCaName.isEmpty())) {
            return EditCaUtil.MANAGE_CA_NAV;
        }
        
        if (!isEditCA && canames.containsKey(createCaName)) {
            addErrorMessage("Ca " + createCaName + " already exists!");
            return EditCaUtil.MANAGE_CA_NAV;
        }
        
        if (isEditCA && (selectedCaId == 0)) {
            return EditCaUtil.MANAGE_CA_NAV;
        }
        
        this.setEditCA(isEditCA);
        // Here we set what is needed in EditCAsMBean
        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("editCaName", caidtonamemap.get(selectedCaId));
        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("createCaName", EditCaUtil.getTrimmedName(this.createCaName));
        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("isEditCA", this.isEditCA);        
        return EditCaUtil.EDIT_CA_NAV;
    }

    public boolean isEditCA() {
        return isEditCA;
    }

    public void setEditCA(boolean isEditCA) {
        this.isEditCA = isEditCA;
    }
    
    public String deleteCA() {
        try {
            cadatahandler.removeCA(selectedCaId);
        } catch (AuthorizationDeniedException e) {
            addErrorMessage(e.getMessage());
            log.error("Error while calling remove ca function!", e);
        }
        return EditCaUtil.MANAGE_CA_NAV;
    }
    
    public String renameCA() {
        if (canames.containsKey(createCaName)) {
            log.error("Ca already exists!");
            addErrorMessage("Ca " + createCaName + " already exists!");
            return EditCaUtil.MANAGE_CA_NAV;
        } else if (selectedCaId == 0) {
            log.error("Select a CA to rename first!");
            addErrorMessage("Select a CA to rename first!");
            return EditCaUtil.MANAGE_CA_NAV;
        }
        
        try {
            cadatahandler.renameCA(selectedCaId, createCaName);
        } catch (CADoesntExistsException | AuthorizationDeniedException e) {
            log.error("Error happened while renaming ca! ", e);
            addErrorMessage(e.getMessage());
        } 
        return EditCaUtil.MANAGE_CA_NAV;
    }


}
