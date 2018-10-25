package org.ejbca.ui.web.admin.ca;

import java.beans.Beans;
import java.io.IOException;
import java.io.Serializable;

import javax.annotation.PostConstruct;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.apache.myfaces.custom.fileupload.UploadedFile;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.cainterface.CADataHandler;
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;

@ManagedBean
@ViewScoped
public class ImportCaCertMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(ImportCaCertMBean.class);

    private CAInterfaceBean caBean;
    private CADataHandler cadatahandler;
    private String importCaCertName;
    private UploadedFile uploadedFile;
    
    @PostConstruct
    public void init() {
        final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        caBean = (CAInterfaceBean) request.getSession().getAttribute("caBean");
        if (caBean == null) {
            try {
                caBean = (CAInterfaceBean) Beans.instantiate(Thread.currentThread().getContextClassLoader(), CAInterfaceBean.class.getName());
            } catch (ClassNotFoundException | IOException e) {
                log.error("Error while instantiating the ca bean!", e);
            }
            request.getSession().setAttribute("cabean", caBean);
        }
        caBean.initialize(getEjbcaWebBean());
        cadatahandler = caBean.getCADataHandler();
    }
    
    public String getImportCaCertName() {
        return importCaCertName;
    }

    public void setImportCaCertName(final String importCaCertName) {
        this.importCaCertName = importCaCertName;
    }
    
    public UploadedFile getUploadedFile() {
        return uploadedFile;
    }

    public void setUploadedFile(final UploadedFile uploadedFile) {
        this.uploadedFile = uploadedFile;
    }    
    
    public String importCaCertificate() {
        byte[] fileBuffer = null;
        try {
            fileBuffer = uploadedFile.getBytes();
        } catch (IOException e) {
            log.error("Error happened while uploading file!", e);
        }
        try {
            cadatahandler.importCACert(importCaCertName, fileBuffer);
        } catch (Exception e) {
            addErrorMessage(e.getMessage());
            log.error("Error happened while importing ca cert!", e);
        }
        return EditCaUtil.MANAGE_CA_NAV;
    }
}
