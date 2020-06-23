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
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.TreeMap;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.apache.myfaces.custom.fileupload.UploadedFile;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.crl.CRLInfo;
import org.cesecore.certificates.crl.CrlImportException;
import org.cesecore.certificates.crl.CrlStoreException;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CertTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.crl.ImportCrlSessionLocal;
import org.ejbca.core.ejb.crl.PublishingCrlSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * JSF Managed Bean or the ca functions page in the CA UI.
 *
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class CAFunctionsMBean extends BaseManagedBean implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(CAFunctionsMBean.class);

    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CrlStoreSessionLocal crlStoreSession;
    @EJB
    private ImportCrlSessionLocal importCrlSession;
    @EJB
    private PublishingCrlSessionLocal publishingCrlSession;

    private GlobalConfiguration globalConfiguration;
    List<CAGuiInfo> caGuiInfos = null;
    private UploadedFile uploadFile;
    List<String> extCaNameList;
    private String crlImportCaName;

    public CAFunctionsMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CAVIEW.resource());
        globalConfiguration = getEjbcaWebBean().getGlobalConfiguration();
        final TreeMap<String, Integer> externalCANames = getEjbcaWebBean().getExternalCANames();
        extCaNameList = new ArrayList<String>(externalCANames.keySet());
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
        private final boolean showJksDownloadForm[];
        private final String caType;

        public CAGuiInfo(final String name, final int caId, final String subjectdn, final List<Certificate> certificatechain, final CRLInfo crlinfo,
                final CRLInfo deltacrlinfo, final Boolean deltaPeriodEnabled, final Boolean caStatusActive, final String caType) {
            this.name = name;
            this.caId = caId;
            this.subjectdn = subjectdn;
            this.certificatechain = new ArrayList<Certificate>(certificatechain); 
            Collections.reverse(this.certificatechain);
            this.crlinfo = crlinfo;
            this.deltacrlinfo = deltacrlinfo;
            this.deltaPeriodEnabled = deltaPeriodEnabled;
            showJksDownloadForm = new boolean[certificatechain.size()];
            this.caStatusActive = caStatusActive;
            this.caType = caType;
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

        public boolean isShowJksDownloadForm(final int index) {
            return showJksDownloadForm[index];
        }

        public void showJksDownloadForm(final int index){
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

        public String getCaType() {
            return caType;
        }
    }

    public List<CAGuiInfo> getCaInfos(){
        if (caGuiInfos == null) {
            refreshCaGuiInfos();
        }
        return caGuiInfos;
    }

    private void refreshCaGuiInfos() {
        caGuiInfos = new ArrayList<>();
        final TreeMap<String, Integer> canames = getEjbcaWebBean().getCANames();
        final List<String> caNameList = new ArrayList<String>(canames.keySet());
        Collections.sort(caNameList, new Comparator<String>() {
            @Override
            public int compare(final String o1, final String o2) {
                return o1.compareToIgnoreCase(o2);
            }
        });
        for (final String caname : caNameList) {
            final int caid = canames.get(caname);
            final CAInfo cainfo = caSession.getCAInfoInternal(caid);
            if (cainfo == null) {
                continue;    // Something wrong happened retrieving this CA?
            }
            // TODO GUI support for Partitioned CRLs (ECA-7961)
            final CRLInfo crlinfo = crlStoreSession.getLastCRLInfo(cainfo.getLatestSubjectDN(), CertificateConstants.NO_CRL_PARTITION, false);
            final CRLInfo deltacrlinfo = crlStoreSession.getLastCRLInfo(cainfo.getLatestSubjectDN(), CertificateConstants.NO_CRL_PARTITION, true);

            final CAGuiInfo caGuiInfo = new CAGuiInfo(caname, caid, cainfo.getSubjectDN(), cainfo.getCertificateChain(), crlinfo, deltacrlinfo,
                    cainfo.getDeltaCRLPeriod() > 0, cainfo.getStatus() == CAConstants.CA_ACTIVE, cainfo.getCaTypeAsString());
            caGuiInfos.add(caGuiInfo);
        }
    }

    public String getUnescapedRdnValue(final Certificate certificate){
        return CertTools.getUnescapedRdnValue(CertTools.getSubjectDN(certificate));
    }

    public String getCertificatePopupLink(final int caid) {
        final StringBuilder link = new StringBuilder();
        link.append(getEjbcaWebBean().getBaseUrl()).append(globalConfiguration.getAdminWebPath()).append("viewcertificate.xhtml?caid=").append(caid);
        return link.toString();
    }

    public String openCertificateInfoPopup(final int caid) {
        final StringBuilder link = new StringBuilder();
        link.append(getEjbcaWebBean().getBaseUrl()).append(globalConfiguration.getCaPath()).append("/viewcainfo.xhtml?caid=").append(caid);
        return link.toString();
    }

    public String getDownloadCertificateLink(){
        final StringBuilder link = new StringBuilder();
        link.append(getEjbcaWebBean().getBaseUrl()).append(globalConfiguration.getCaPath()).append("/cacert");
        return link.toString();
    }
    
    public String getSshPublicKeyLink(){
        final StringBuilder link = new StringBuilder();
        link.append(getEjbcaWebBean().getBaseUrl()).append("ssh");
        return link.toString();
    }

    public String getDownloadCrlLink(){
        final StringBuilder link = new StringBuilder();
        link.append(getEjbcaWebBean().getBaseUrl()).append(globalConfiguration.getCaPath()).append("/getcrl/getcrl");
        return link.toString();
    }

    public void showJksDownloadForm(final CAGuiInfo caGuiInfo, final int index) {
        for (final CAGuiInfo info : caGuiInfos) {
            info.hideJksDownloadForm();
        }
        caGuiInfo.showJksDownloadForm(index);
    }

    public void uploadCrlFile() throws IOException {
        if (uploadFile == null) {
            addNonTranslatedErrorMessage("No CRL file uploaded");
            return;
        }
        final byte[] bytes = uploadFile.getBytes();
        if (bytes == null || bytes.length == 0) {
            addNonTranslatedErrorMessage("No CRL file uploaded, or file is empty");
            return;
        }
        try {
            final CAInfo cainfo = caSession.getCAInfo(getAdmin(), crlImportCaName);
            final X509CRL x509crl = CertTools.getCRLfromByteArray(bytes);
            if (x509crl == null) {
                addNonTranslatedErrorMessage("Could not parse CRL. It must be in DER format.");
            } else if (!StringUtils.equals(cainfo.getSubjectDN(), CertTools.getIssuerDN(x509crl))) {
                addNonTranslatedErrorMessage("Error: The CRL in the file in not issued by " + crlImportCaName);
            } else {
                final int crlPartitionIndex = CertificateConstants.NO_CRL_PARTITION; // TODO partitioned CRL import (partition auto-detection) could be added as part of ECA-7961
                importCrlSession.importCrl(getAdmin(), cainfo, bytes, crlPartitionIndex);
                addNonTranslatedInfoMessage("CRL imported successfully or a newer version is already in the database");
                refreshCaGuiInfos();
            }
        } catch (final CRLException e) {
            log.info("Could not parse CRL", e);
            addNonTranslatedErrorMessage("Could not parse CRL");
        } catch (AuthorizationDeniedException | CrlImportException | CrlStoreException e) {
            log.info("Error importing CRL", e);
            addNonTranslatedErrorMessage("Error: " + e.getLocalizedMessage());
        }
    }

    public void createNewCrl(final int caid) throws CAOfflineException {
        try {
            publishingCrlSession.forceCRL(getAdmin(), caid);
            refreshCaGuiInfos();
        } catch (final CADoesntExistsException | AuthorizationDeniedException e) {
            throw new IllegalStateException(e);
        } catch (final CryptoTokenOfflineException e) {
            addErrorMessage("CATOKENISOFFLINE");
        }
    }
    public void createNewDeltaCrl(final int caid) throws CAOfflineException, CryptoTokenOfflineException {
        try {
            publishingCrlSession.forceDeltaCRL(getAdmin(), caid);
        } catch (final CADoesntExistsException | AuthorizationDeniedException e) {
            throw new IllegalStateException(e);
        }
        refreshCaGuiInfos();
    }


    public List<SelectItem> getExtCaNameSeletItemList() {
        final List<SelectItem> ret = new ArrayList<>();
        for (final String alias : extCaNameList) {
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

    public void setCrlImportCaName(final String crlImportCaName) {
        this.crlImportCaName = crlImportCaName;
    }

    public UploadedFile getUploadFile() {
        return uploadFile;
    }

    public void setUploadFile(final UploadedFile uploadFile) {
        this.uploadFile = uploadFile;
    }

    public List<String> getExtCaNameList() {
        return extCaNameList;
    }
}
