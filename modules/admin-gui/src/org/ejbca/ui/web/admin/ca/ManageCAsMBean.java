package org.ejbca.ui.web.admin.ca;

import java.beans.Beans;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
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

@ManagedBean
@ViewScoped
public class ManageCAsMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(ManageCAsMBean.class);
    
    private TreeMap<String, Integer> canames = getEjbcaWebBean().getCANames();
    private CAInterfaceBean caBean;
    private String editCaName;
    private String createCaName;
    private boolean isEditCA;
    CADataHandler cadatahandler;
    
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
    }
    
    public List<String> getListOfCas() {
        final List<String> caList = new ArrayList<String>();
        for (final String nameofca : canames.keySet()) {
            int caId = canames.get(nameofca).intValue();
            int caStatus = caBean.getCAStatusNoAuth(caId);

            String nameandstatus = nameofca + ", (" + getEjbcaWebBean().getText(CAConstants.getStatusText(caStatus)) + ")";
            if (caBean.isAuthorizedToCa(caId)) {
                caList.add(nameandstatus);
            }
        }
        return caList;
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
    

    public String getEditCaName() {
        return this.editCaName;
    }

    public void setEditCaName(final String editCaName) {
        this.editCaName = editCaName;
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
        if (editCaName != null && !editCaName.isEmpty()) {
            return getEjbcaWebBean().getText("AREYOUSURETODELETECA", true, getTrimmedName(this.editCaName));
        } else {
            return StringUtils.EMPTY;
        }
    }
    
    private Object getTrimmedName(final String name) {
        if (name != null && !name.isEmpty()) {
            return name.replaceAll("\\([^()]*\\)", StringUtils.EMPTY).replaceAll(", ", StringUtils.EMPTY);
        } else {
            return StringUtils.EMPTY;
        }
    }

    public String updateIsEditCA(final boolean isEditCA) {
        if (!isEditCA && (createCaName == null || createCaName.isEmpty())) {
            return StringUtils.EMPTY;
        }
        if (isEditCA && (editCaName == null || editCaName.isEmpty())) {
            return StringUtils.EMPTY;
        }
        
        this.setEditCA(isEditCA);
        // Here we set what is needed in EditCAsMBean
        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("editCaName", this.editCaName);
        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("createCaName", this.createCaName);
        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("isEditCA", this.isEditCA);        
        return "editcapage";
    }

    public boolean isEditCA() {
        return isEditCA;
    }

    public void setEditCA(boolean isEditCA) {
        this.isEditCA = isEditCA;
    }
    
    public String deleteCA() {
        
        if (cadatahandler == null) {
            log.info("amin ca datahandler is null!!!");
        }
        
        if (canames == null) {
            log.info("amin canames is null!!!");
        }
        
        
        log.info("Amin edit ca name is " + editCaName);
        
        try {
            cadatahandler.removeCA(canames.get(getTrimmedName(editCaName)));
        } catch (AuthorizationDeniedException e) {
            log.error("Error while calling remove ca function!", e);
        }
        return "managecas";
    }
    
    public String renameCA() throws CADoesntExistsException, AuthorizationDeniedException {
        if (canames.containsValue(createCaName)) {
            log.error("ca already exists!");
            return StringUtils.EMPTY;
        } else if (editCaName == null || editCaName.isEmpty()) {
            log.error("Select a CA first!");
            return StringUtils.EMPTY;
        }
        
        cadatahandler.renameCA(canames.get(getTrimmedName(editCaName)), createCaName);
        return "managecas";
    }
    
}
