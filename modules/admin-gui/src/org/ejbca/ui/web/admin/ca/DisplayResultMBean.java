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

import java.io.Serializable;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.faces.context.FacesContext;
import javax.faces.view.ViewScoped;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CAInfo;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.attribute.AttributeMapping.SESSION;
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;

/**
 * 
 * JSF MBean backing the displayresult xhtml page.
 *
 */
@Named
@ViewScoped
public class DisplayResultMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(DisplayResultMBean.class);

    private GlobalConfiguration globalconfiguration;
    private String headline;
    
    private String[] headlines = {"CERTREQGEN","CERTIFICATEGENERATED"};

    private String resultString = null;
    private int filemode;

    private String pemlink = null;
    private String binarylink =  null;
    private String pkcs7link = StringUtils.EMPTY;
    private String caName;
    
    public DisplayResultMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CAVIEW.resource());
    }
    
    @PostConstruct
    public void init() {
        EditCaUtil.navigateToManageCaPageIfNotPostBack();
        
        final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        try {
            globalconfiguration = getEjbcaWebBean().initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CAVIEW.resource());
        } catch (Exception e) {
            log.error("Error while initializing the global configuration!", e);
        }

        final Map<String, Object> requestMap = FacesContext.getCurrentInstance().getExternalContext().getRequestMap();
        
        filemode = (Integer) requestMap.get("filemode");
        caName = (String) requestMap.get("caname");
        final CAInterfaceBean caBean = (CAInterfaceBean) requestMap.get(SESSION.CA_INTERFACE_BEAN);
        final int caType = (Integer) requestMap.get("caType");
        final String filePath = getEjbcaWebBean().getBaseUrl() + globalconfiguration.getCaPath();

        if (filemode == EditCaUtil.CERTGENMODE) {
            try {
                resultString = caBean.getProcessedCertificateAsString();
            } catch (Exception e) {
                addNonTranslatedErrorMessage(e);
            }
        } else {
            try {
                resultString = caBean.getRequestDataAsString(caType);
            } catch (Exception e) {
                if (e.getMessage() == null) {
                    // For some reason e doesn't provide a message for example in CVC certificate parser case
                    addNonTranslatedErrorMessage("An unknown exception happened while getting request data as string!");
                } else {
                    addNonTranslatedErrorMessage(e);
                }
            }
        }
        
        initializeDownloadLinks(caType, filePath);
        headline = getEjbcaWebBean().getText(headlines[filemode]);
    }

    public String getHeadline() {
        return headline;
    }
    
    public String getCaName() {
        return getEjbcaWebBean().getText("CANAME") + " : " + caName;
    }

    public String getResultString() {
        return resultString;
    }

    public String getPemlink() {
        return pemlink;
    }

    public String getPkcs7link() {
        return pkcs7link;
    }

    public String getBinarylink() {
        return binarylink;
    }
    
    public boolean isRenderPkcs7Link() {
        return filemode == EditCaUtil.CERTGENMODE;
    }
    
    public boolean isRenderPemLink() {
        return pemlink!=null;
    }
    
    private void initializeDownloadLinks(final int caType, final String filePath) {
        if (filemode == EditCaUtil.CERTGENMODE) {
            pemlink = filePath + "/editcas/cacertreq?cmd=cert";
            binarylink = filePath + "/editcas/cacertreq?cmd=cert&format=binary";
            pkcs7link = filePath + "/editcas/cacertreq?cmd=certpkcs7";
        } else {
            if (caType != CAInfo.CATYPE_CITS) {
                pemlink = filePath + "/editcas/cacertreq?cmd=certreq&caType=" + caType;
                binarylink = filePath + "/editcas/cacertreq?cmd=certreq&format=binary&caType=" + caType;
            } else {
                binarylink = filePath + "/editcas/cacertreq?cmd=itsecacsr&caname=" + caName + "&caType=" + caType;
            }
            pkcs7link = StringUtils.EMPTY;
        }
    }
}
