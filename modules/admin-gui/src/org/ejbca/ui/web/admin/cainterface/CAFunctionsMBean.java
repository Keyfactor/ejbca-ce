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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

import javax.ejb.EJB;
import javax.faces.model.SelectItem;
import javax.faces.view.ViewScoped;
import javax.inject.Named;
import javax.servlet.http.Part;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.crl.CRLInfo;
import org.cesecore.certificates.crl.CrlImportException;
import org.cesecore.certificates.crl.CrlStoreException;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.crl.DeltaCrlException;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.crl.ImportCrlSessionLocal;
import org.ejbca.core.ejb.crl.PublishingCrlSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 * JSF Managed Bean or the ca functions page in the CA UI.
 */
@Named
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

    private final GlobalConfiguration globalConfiguration;
    private List<CAGuiInfo> caGuiInfos = null;
    private transient Part uploadFile;
    private final List<String> extCaNameList;
    private String crlImportCaName;

    public CAFunctionsMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CAVIEW.resource());
        globalConfiguration = getEjbcaWebBean().getGlobalConfiguration();
        final TreeMap<String, Integer> externalCANames = getEjbcaWebBean().getExternalCANames();
        extCaNameList = new ArrayList<>(externalCANames.keySet());
    }

    /**
     * GUI representation of a CA for the CA Structure page
     */
    public class CAGuiInfo implements Serializable {
        private static final long serialVersionUID = -555096060949439122L;

        private final String name;
        private final int caId;
        private final String subjectdn;
        private final List<CertificateChainElement> certificatechain;
        private final List<CRLGuiInfo> crlinfo;
        private final CRLInfo deltacrlinfo;
        private final Boolean deltaPeriodEnabled;
        private final Boolean caStatusActive;
        private final boolean[] showJksDownloadForm;
        private final String caType;

        public CAGuiInfo(final String name, final int caId, final String subjectdn, final List<CertificateChainElement> certificatechain, final List<CRLGuiInfo> crlinfo,
                         final CRLInfo deltacrlinfo, final Boolean deltaPeriodEnabled, final Boolean caStatusActive, final String caType) {
            this.name = name;
            this.caId = caId;
            this.subjectdn = subjectdn;
            this.certificatechain = certificatechain != null ? new ArrayList<>(certificatechain) : new ArrayList<>();
            Collections.reverse(this.certificatechain);
            this.crlinfo = crlinfo;
            this.deltacrlinfo = deltacrlinfo;
            this.deltaPeriodEnabled = deltaPeriodEnabled;
            showJksDownloadForm = new boolean[this.certificatechain.size()];
            this.caStatusActive = caStatusActive;
            this.caType = caType;
        }

        public String getName() {
            return name;
        }

        public String getEscapedName() {
            return URLEncoder.encode(name, StandardCharsets.UTF_8);
        }

        public int getCaId() {
            return caId;
        }

        public String getSubjectdn() {
            return subjectdn;
        }

        public String getEscapedSubjectDn() {
            return URLEncoder.encode(subjectdn, StandardCharsets.UTF_8);
        }

        public List<CertificateChainElement> getCertificatechain() {
            return certificatechain;
        }

        public List<CRLGuiInfo> getCrlinfo() {
            return crlinfo;
        }

        public boolean isShowJksDownloadForm(final int index) {
            return showJksDownloadForm[index];
        }

        public void showJksDownloadForm(final int index) {
            showJksDownloadForm[index] = true;
        }

        public void hideJksDownloadForm() {
            Arrays.fill(showJksDownloadForm, false);
        }

        public CRLInfo getDeltacrlinfo() {
            return deltacrlinfo;
        }

        public Boolean getDeltaPeriodEnabled() {
            return deltaPeriodEnabled;
        }

        public boolean isCrlInfoEmpty() {
            return crlinfo == null || crlinfo.isEmpty();
        }

        public boolean isDeltaCrlInfoEmpty() {
            return deltacrlinfo == null;
        }

        public String getDeltaCrlCreateDate() {
            return getEjbcaWebBean().formatAsISO8601(deltacrlinfo.getCreateDate());
        }

        public String getDeltaCrlExpireDate() {
            return getEjbcaWebBean().formatAsISO8601(deltacrlinfo.getExpireDate());
        }

        public boolean isDeltaCrlExpired() {
            return deltacrlinfo.getExpireDate().compareTo(new Date()) < 0;
        }

        public Boolean getCaStatusActive() {
            return caStatusActive;
        }

        public String getCaType() {
            return caType;
        }

        public boolean isDisplayPartitions() {
            return crlinfo.size() > 1;
        }

        public boolean isCrlSupported() {
            return "X.509".equals(getCaType());
        }

    }

    public class CertificateChainElement {
        private final Certificate cert;
        private final String subjectDN;

        public CertificateChainElement(Certificate cert, String subjectDN) {
            this.cert = cert;
            this.subjectDN = subjectDN;
        }

        public Certificate getCertificate() {
            return cert;
        }

        public String getSubjectDN() {
            return DnComponents.getUnescapedRdnValue(subjectDN);
        }

        public boolean isCertExists() {
            return Objects.nonNull(cert);
        }

        public boolean isRoot() {
            return Objects.nonNull(cert)
                    && StringUtils.isNotEmpty(CertTools.getIssuerDN(cert))
                    && StringUtils.isNotEmpty(CertTools.getSubjectDN(cert))
                    && CertTools.isSelfSigned(cert);
        }

    }

    public class CRLGuiInfo {
        private final Date createDate;
        private final Date expireDate;
        private final String subjectDn;
        private final int lastCrlNumber;
        private final int partitionIndex;

        public CRLGuiInfo(CRLInfo crlInfo) {
            createDate = crlInfo.getCreateDate();
            expireDate = crlInfo.getExpireDate();
            subjectDn = crlInfo.getSubjectDN();
            lastCrlNumber = crlInfo.getLastCRLNumber();
            partitionIndex = crlInfo.getCrlPartitionIndex();
        }

        public String getCrlCreateDate() {
            return getEjbcaWebBean().formatAsISO8601(createDate);
        }

        public String getCrlExpireDate() {
            return getEjbcaWebBean().formatAsISO8601(expireDate);
        }

        public boolean isCrlExpired() {
            return expireDate.compareTo(new Date()) < 0;
        }

        public String getSubjectDn() {
            return subjectDn;
        }

        public String getURLEncodedSubjectDn() {
            return URLEncoder.encode(subjectDn, StandardCharsets.UTF_8);
        }

        public int getLastCrlNumber() {
            return lastCrlNumber;
        }

        public int getPartitionIndex() {
            return partitionIndex;
        }

    }

    public List<CAGuiInfo> getCaInfos() {
        if (caGuiInfos == null) {
            refreshCaGuiInfos();
        }
        return caGuiInfos;
    }

    private void refreshCaGuiInfos() {
        caGuiInfos = new ArrayList<>();
        final TreeMap<String, Integer> caNames = caSession.getAuthorizedCaNamesToIds(getAdmin());
        final List<String> caNameList = new ArrayList<>(caNames.keySet());
        caNameList.sort(String::compareToIgnoreCase);
        for (final String caName : caNameList) {
            final int caid = caNames.get(caName);
            final CAInfo cainfo = caSession.getCAInfoInternal(caid);
            if (cainfo == null) {
                continue;    // Something wrong happened retrieving this CA?
            }

            final List<CRLGuiInfo> crlInfos = new ArrayList<>();
            if (cainfo instanceof X509CAInfo) {
                final int numberOfPartitions = cainfo.getAllCrlPartitionIndexes() == null
                        ? 1
                        : cainfo.getAllCrlPartitionIndexes().getMaximumInteger();
                for (int currentPartitionIndex = 0; currentPartitionIndex <= numberOfPartitions; currentPartitionIndex++) {
                    final CRLInfo currentCrlInfo = crlStoreSession.getLastCRLInfoLightWeight(cainfo.getLatestSubjectDN(), currentPartitionIndex, false);
                    if (currentCrlInfo != null) {
                        crlInfos.add(new CRLGuiInfo(currentCrlInfo));
                    }
                }
            } else {
                final CRLInfo crlinfo = crlStoreSession.getLastCRLInfoLightWeight(cainfo.getLatestSubjectDN(), CertificateConstants.NO_CRL_PARTITION, false);
                if (crlinfo != null) {
                    crlInfos.add(new CRLGuiInfo(crlinfo));
                }
            }

            final CRLInfo deltacrlinfo = crlStoreSession.getLastCRLInfoLightWeight(cainfo.getLatestSubjectDN(), CertificateConstants.NO_CRL_PARTITION, true);

            final CAGuiInfo caGuiInfo = new CAGuiInfo(caName, caid, cainfo.getSubjectDN(),
                    cainfo.getCAType() != CAInfo.CATYPE_PROXY
                            ? getCertificateChain(cainfo.getCertificateChain())
                            : null,
                    crlInfos, deltacrlinfo, cainfo.getDeltaCRLPeriod() > 0,
                    cainfo.getStatus() == CAConstants.CA_ACTIVE, cainfo.getCaTypeAsString());
            caGuiInfos.add(caGuiInfo);
        }
    }

    private List<CertificateChainElement> getCertificateChain(final List<Certificate> originalChain) {
        final Set<Certificate> missingChainCerts = new HashSet<>();
        final Set<Certificate> certificates = new HashSet<>(originalChain);

        certificates.stream()
                .filter(Objects::nonNull)
                .map(cert -> caSession.findBySubjectDN(CertTools.getIssuerDN(cert)))
                .filter(Objects::nonNull)
                .forEach(caData ->
                        missingChainCerts.add(caData.getCA().getCACertificate())
                );

        certificates.addAll(missingChainCerts);

        try {

            List<Certificate> chain = certificates.size() == 1 ? new ArrayList<>(certificates) : CertTools.createCertChain(certificates);
            final List<CertificateChainElement> uiChain = new ArrayList<>();
            boolean needToAddAliasToParent = !isRoot(chain.get(chain.size() - 1));
            chain.forEach(cert -> uiChain.add(new CertificateChainElement(cert, CertTools.getSubjectDN(cert))));

            //Add last because this list will be reverted
            if (needToAddAliasToParent) {
                uiChain.add(new CertificateChainElement(null, CertTools.getIssuerDN(chain.get(chain.size() - 1))));
            }
            return uiChain;

        } catch (Exception e) {
            log.info("Could not build valid chain, displaying original one, size = " + originalChain.size() + ", error = " + e.getMessage());
            return originalChain
                    .stream()
                    .map(cert -> new CertificateChainElement(cert, CertTools.getSubjectDN(cert)))
                    .collect(Collectors.toList());
        }
    }

    public boolean isRoot(final Certificate certificate) {
        return StringUtils.isNotEmpty(CertTools.getIssuerDN(certificate))
                && StringUtils.isNotEmpty(CertTools.getSubjectDN(certificate))
                && CertTools.isSelfSigned(certificate);
    }

    public String getCertificatePopupLink(final int caid) {
        return getEjbcaWebBean().getBaseUrl() + globalConfiguration.getAdminWebPath() + "viewcertificate.xhtml?caid=" + caid;
    }

    public String openCertificateInfoPopup(final int caid) {
        return getEjbcaWebBean().getBaseUrl() + globalConfiguration.getCaPath() + "/viewcainfo.xhtml?caid=" + caid;
    }

    public String getDownloadCertificateLink() {
        return getEjbcaWebBean().getBaseUrl() + globalConfiguration.getCaPath() + "/cacert";
    }

    public String getSshPublicKeyLink() {
        return getEjbcaWebBean().getBaseUrl() + "ssh";
    }

    public String getDownloadCrlLink() {
        return getEjbcaWebBean().getBaseUrl() + globalConfiguration.getCaPath() + "/getcrl/getcrl";
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

        final byte[] bytes = IOUtils.toByteArray(uploadFile.getInputStream(), uploadFile.getSize());

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
        } catch (final CADoesntExistsException | AuthorizationDeniedException | DeltaCrlException e) {
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

    public Part getUploadFile() {
        return uploadFile;
    }

    public void setUploadFile(final Part uploadFile) {
        this.uploadFile = uploadFile;
    }

    public List<String> getExtCaNameList() {
        return extCaNameList;
    }
}
