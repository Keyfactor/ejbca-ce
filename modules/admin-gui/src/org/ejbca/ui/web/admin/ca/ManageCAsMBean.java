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
import javax.ejb.EJB;
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
import org.cesecore.certificates.ca.CaSessionLocal;
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

    @EJB
    private CaSessionLocal caSession;

    private TreeMap<String, Integer> canames = getEjbcaWebBean().getCANames();
    private CAInterfaceBean caBean;
    private int selectedCaId;
    private String createCaName;
    private CADataHandler cadatahandler;
    private Map<Integer, String> caidtonamemap;
    
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
            getEjbcaWebBean().initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CAVIEW.resource());
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
        caidtonamemap = caSession.getCAIdToNameMap();
    }
    
    public Map<Integer, String> getListOfCas() {
        final Map<Integer, String> caMap = new LinkedHashMap<>();
        for (final String nameofca : canames.keySet()) {
            int caId = canames.get(nameofca);
            int caStatus = caBean.getCAStatusNoAuth(caId);

            String nameandstatus = nameofca + ", (" + getEjbcaWebBean().getText(CAConstants.getStatusText(caStatus)) + ")";
            if (caSession.authorizedToCANoLogging(getAdmin(), caId)) {
                caMap.put(caId, nameandstatus);
            }
        }
        return caMap;
    }
    
    public String getEditCAButtonValue() {
        return isAuthorized() ? getEjbcaWebBean().getText("VIEWCA") : getEjbcaWebBean().getText("EDITCA");
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

    public String editCaPage() {
        if (selectedCaId == 0) {
            return EditCaUtil.MANAGE_CA_NAV;
        }
        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("editcaname", caidtonamemap.get(selectedCaId));
        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("caid", selectedCaId);
        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("iseditca", true);
        return EditCaUtil.EDIT_CA_NAV;
    }
    
    public String createCaPage() {
        if (createCaName == null || createCaName.isEmpty()) {
            return EditCaUtil.MANAGE_CA_NAV;
        }
        
        if (canames.containsKey(createCaName)) {
            addErrorMessage("CAALREADYEXISTS", createCaName);
            return EditCaUtil.MANAGE_CA_NAV;
        }
        
        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("createcaname", EditCaUtil.getTrimmedName(this.createCaName));
        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("iseditca", false);
        return EditCaUtil.EDIT_CA_NAV;
    }
    
    public String deleteCA() {
        try {
            if (!cadatahandler.removeCA(selectedCaId)) {
                addErrorMessage("COULDNTDELETECA");
            }
        } catch (AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(e.getMessage());
        }
        return EditCaUtil.MANAGE_CA_NAV;
    }
    
    public String renameCA() {
        if (canames.containsKey(createCaName)) {
            addErrorMessage("CAALREADYEXISTS", createCaName);
            return EditCaUtil.MANAGE_CA_NAV;
        } else if (selectedCaId == 0) {
            addErrorMessage("SELECTCATORENAME");
            return EditCaUtil.MANAGE_CA_NAV;
        }
        
        try {
            cadatahandler.renameCA(selectedCaId, createCaName);
        } catch (CADoesntExistsException | AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(e);
        } 
        return EditCaUtil.MANAGE_CA_NAV;
    }
    
    public String createAuthCertSignRequest() {
        if (selectedCaId != 0) {
            FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("selectedCaName", caidtonamemap.get(selectedCaId));
            FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("selectedCaId", selectedCaId);
            return EditCaUtil.SIGN_CERT_REQ_NAV;
        } else {
            addErrorMessage("SELECTCAFIRST");
            return EditCaUtil.MANAGE_CA_NAV;
        }
    }
}
