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
package org.ejbca.ui.web.admin.cainterface;

import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.TreeMap;

import javax.annotation.PostConstruct;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.apache.myfaces.custom.fileupload.UploadedFile;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.crl.CRLInfo;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CertTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.AdminIndexMBean;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * JSF Managed Bean or the ca functions page in the Admin GUI.
 *
 * @version $Id: CAFunctionsMBean.java 25797 2018-08-10 15:52:00Z jekaterina $
 */
@ManagedBean
@ViewScoped
public class CAFunctionsMBean extends BaseManagedBean implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(CAFunctionsMBean.class);


    private GlobalConfiguration globalConfiguration;
    private CAInterfaceBean caBean;
    List<CAGuiInfo> caGuiInfos = null;
    private UploadedFile uploadFile;
    List<String> extCaNameList;
    private String crlImportCaName;
    private String message;
    private String errorMessage;

    @PostConstruct
    private void postConstruct() throws Exception {
        final HttpServletRequest req = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        globalConfiguration = getEjbcaWebBean().initialize(req, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CAVIEW.resource());

        caBean = (CAInterfaceBean) req.getSession().getAttribute("caBean");
        if ( caBean == null ){
            try {
                caBean = (CAInterfaceBean) java.beans.Beans.instantiate(Thread.currentThread().getContextClassLoader(), CAInterfaceBean.class.getName());
            } catch (ClassNotFoundException exc) {
                throw new ServletException(exc.getMessage());
            }catch (Exception exc) {
                throw new ServletException (" Cannot create bean of class "+CAInterfaceBean.class.getName(), exc);
            }
            req.getSession().setAttribute("cabean", caBean);
        }
        try{
            caBean.initialize(getEjbcaWebBean());
        } catch(Exception e){
            throw new java.io.IOException("Error initializing AdminIndexMBean");
        }
        TreeMap<String, Integer> externalCANames = getEjbcaWebBean().getExternalCANames();
        extCaNameList = new ArrayList<String>(externalCANames.keySet());
    }

    public void clearMessages(){
        message = null;
        errorMessage = null;
    }


    /** GUI representation of a CA for the CA Structure page */
    public class CAGuiInfo {
        private final String name;
        private final int caId;
        private final String subjectdn;
        private final List<Certificate> certificatechain;
        private final CRLInfo crlinfo;
        private final CRLInfo deltacrlinfo;
        private final Boolean deltaPeriodEnabled;
        private final Boolean caStatusActive;
        private boolean showJksDownloadForm[];

        public CAGuiInfo(String name, int caId, String subjectdn, List<Certificate> certificatechain, CRLInfo crlinfo, CRLInfo deltacrlinfo, Boolean deltaPeriodEnabled, Boolean caStatusActive) {
            this.name = name;
            this.caId = caId;
            this.subjectdn = subjectdn;
            this.certificatechain = certificatechain;
            this.crlinfo = crlinfo;
            this.deltacrlinfo = deltacrlinfo;
            this.deltaPeriodEnabled = deltaPeriodEnabled;
            showJksDownloadForm = new boolean[certificatechain.size()];
            this.caStatusActive = caStatusActive;
        }

        public String getName() {
            return name;
        }

        public int getCaId() {
            return caId;
        }

        public String getSubjectdn() {
            return subjectdn;
        }

        public List<Certificate> getCertificatechain() {
            return certificatechain;
        }

        public CRLInfo getCrlinfo() {
            return crlinfo;
        }

        public boolean isShowJksDownloadForm(int index) {
            return showJksDownloadForm[index];
        }

        public void showJksDownloadForm(int index){
            showJksDownloadForm[index] = true;
        }

        public void hideJksDownloadForm(){
            for(int i = 0; i<showJksDownloadForm.length; i++){
                showJksDownloadForm[i] = false;
            }
        }

        public CRLInfo getDeltacrlinfo() {
            return deltacrlinfo;
        }

        public Boolean getDeltaPeriodEnabled() {
            return deltaPeriodEnabled;
        }

        public boolean isCrlInfoEmpty() {
            return crlinfo == null;
        }

        public String getCrlCreateDate(){
            return getEjbcaWebBean().formatAsISO8601(crlinfo.getCreateDate());
        }

        public String getCrlExpireDate(){
            return getEjbcaWebBean().formatAsISO8601(crlinfo.getExpireDate());
        }

        public boolean isCrlExpired(){
           return crlinfo.getExpireDate().compareTo(new Date()) < 0;
        }

        public boolean isDeltaCrlInfoEmpty() {
            return deltacrlinfo == null;
        }

        public String getDeltaCrlCreateDate(){
            return getEjbcaWebBean().formatAsISO8601(deltacrlinfo.getCreateDate());
        }

        public String getDeltaCrlExpireDate(){
            return getEjbcaWebBean().formatAsISO8601(deltacrlinfo.getExpireDate());
        }

        public boolean isDeltaCrlExpired(){
            return deltacrlinfo.getExpireDate().compareTo(new Date()) < 0;
        }

        public Boolean getCaStatusActive() {
            return caStatusActive;
        }
    }

    public CAInterfaceBean getCaBean(){
        return caBean;
    }

    public List<CAGuiInfo> getCaInfos(){
        if (caGuiInfos == null) {
            refreshCaGuiInfos();
        }
        return caGuiInfos;
    }

    private void refreshCaGuiInfos() {
        caGuiInfos = new ArrayList<>();
        TreeMap<String, Integer> canames = getEjbcaWebBean().getCANames();
        List<String> caNameList = new ArrayList<String>(canames.keySet());
        Collections.sort(caNameList, new Comparator<String>() {
            public int compare(String o1, String o2) {
                return o1.compareToIgnoreCase(o2);
            }
        });
        for (String caname : caNameList) {
            int caid = ((Integer) canames.get(caname)).intValue();
            CAInfo cainfo = getCaBean().getCAInfoFastNoAuth(caid);
            if (cainfo == null) {
                continue;    // Something wrong happened retrieving this CA?
            }
            CRLInfo crlinfo = getCaBean().getLastCRLInfo(cainfo, false);
            CRLInfo deltacrlinfo = getCaBean().getLastCRLInfo(cainfo, true);

            CAGuiInfo caGuiInfo = new CAGuiInfo(caname, caid, cainfo.getSubjectDN(), cainfo.getCertificateChain(), crlinfo, deltacrlinfo,
                    cainfo.getDeltaCRLPeriod() > 0, cainfo.getStatus() == CAConstants.CA_ACTIVE);
            caGuiInfos.add(caGuiInfo);
        }
    }

    public String getUnescapedRdnValue(Certificate certificate){
        return CertTools.getUnescapedRdnValue(CertTools.getSubjectDN(certificate));
    }

    public String getCertificatePopupLink(int caid) throws UnsupportedEncodingException {
        StringBuilder link = new StringBuilder();
        link.append(getEjbcaWebBean().getBaseUrl()).append(globalConfiguration.getAdminWebPath()).append("viewcertificate.jsp?caid=").append(caid);
        return link.toString();
    }
    public String openCertificateInfoPopup(int caid){
        StringBuilder link = new StringBuilder();
        link.append(getEjbcaWebBean().getBaseUrl()).append(globalConfiguration.getCaPath()).append("/viewcainfo.jsp?caid=").append(caid);
        return link.toString();
    }

    public String getDownloadCertificateLink(){
        StringBuilder link = new StringBuilder();
        link.append(getEjbcaWebBean().getBaseUrl()).append(globalConfiguration.getCaPath()).append("/cacert");
        return link.toString();
    }

    public String getDownloadCrlLink(){
        StringBuilder link = new StringBuilder();
        link.append(getEjbcaWebBean().getBaseUrl()).append(globalConfiguration.getCaPath()).append("/getcrl/getcrl");
        return link.toString();
    }

    public void showJksDownloadForm(CAGuiInfo caGuiInfo, int index) {
        for (CAGuiInfo info : caGuiInfos) {
            info.hideJksDownloadForm();
        }
        caGuiInfo.showJksDownloadForm(index);
    }

    public void uploadCrlFile() throws IOException {
        clearMessages();
        byte[] bytes = uploadFile.getBytes();
        String responseMessage = caBean.importCRL(crlImportCaName, bytes);
        if(responseMessage.startsWith("Error")) {
            errorMessage = responseMessage;
        } else {
            message = responseMessage;
        }

    }

    public void createNewCrl(int caid) throws CAOfflineException, CryptoTokenOfflineException {
        getCaBean().createCRL(caid);
        refreshCaGuiInfos();
    }
    public void createNewDeltaCrl(int caid) throws CAOfflineException, CryptoTokenOfflineException {
        getCaBean().createDeltaCRL(caid);
        refreshCaGuiInfos();
    }


    public List<SelectItem> getExtCaNameSeletItemList() {
        final List<SelectItem> ret = new ArrayList<>();
        for (String alias : extCaNameList) {
            ret.add(new SelectItem(alias, alias));
        }
        return ret;
    }

    public boolean hasCreatecrlrights() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CREATECRL.resource());
    }

    public String getCrlImportCaName() {
        return crlImportCaName;
    }

    public void setCrlImportCaName(String crlImportCaName) {
        this.crlImportCaName = crlImportCaName;
    }

    public UploadedFile getUploadFile() {
        return uploadFile;
    }

    public void setUploadFile(UploadedFile uploadFile) {
        this.uploadFile = uploadFile;
    }

    public List<String> getExtCaNameList() {
        return extCaNameList;
    }

    public String getMessage() {
        return message;
    }

    public String getErrorMessage() {
        return errorMessage;
    }
}
