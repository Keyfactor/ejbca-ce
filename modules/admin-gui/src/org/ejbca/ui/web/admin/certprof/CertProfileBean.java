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
package org.ejbca.ui.web.admin.certprof;

import java.io.IOException;
import java.io.Serializable;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CvcCA;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CertificateExtension;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificatetransparency.CTLogInfo;
import org.cesecore.certificates.certificatetransparency.CertificateTransparencyFactory;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.approval.ApprovalProfileSession;
import org.ejbca.cvc.AccessRightAuthTerm;
import org.ejbca.ui.web.ParameterException;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * JSF MBean backing the certificate profile pages.
 *  
 * @version $Id$
 */
// Declarations in faces-config.xml
//@javax.faces.bean.SessionScoped
//@javax.faces.bean.ManagedBean(name="certProfileBean")
public class CertProfileBean extends BaseManagedBean implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(CertProfileBean.class);

    // Declarations in faces-config.xml
    //@javax.faces.bean.ManagedProperty(value="#{certProfilesBean}")
    private CertProfilesBean certProfilesBean;
    
    private int currentCertProfileId = -1;
    private CertificateProfile certificateProfile = null;
    private ListDataModel<CertificatePolicy> certificatePoliciesModel = null;
    private CertificatePolicy newCertificatePolicy = null;
    private ListDataModel<String> caIssuersModel = null;
    private String newCaIssuer = "";
    private ListDataModel<String> documentTypeList = null;
    private String documentTypeListNew = "";

    /** Since this MBean is session scoped we need to reset all the values when needed. */
    private void reset() {
        currentCertProfileId = -1;
        certificateProfile = null;
        certificatePoliciesModel = null;
        newCertificatePolicy = null;
        caIssuersModel = null;
        newCaIssuer = "";
        documentTypeList = null;
        documentTypeListNew = "";
    }

    public CertProfilesBean getCertProfilesBean() { return certProfilesBean; }
    public void setCertProfilesBean(CertProfilesBean certProfilesBean) { this.certProfilesBean = certProfilesBean; }

   
    public Integer getSelectedCertProfileId() {
        return certProfilesBean.getSelectedCertProfileId();
    }

    public String getSelectedCertProfileName() {
        return getEjbcaWebBean().getEjb().getCertificateProfileSession().getCertificateProfileName(getSelectedCertProfileId());
    }

    public CertificateProfile getCertificateProfile() {
        if (currentCertProfileId!=-1 && certificateProfile!=null && getSelectedCertProfileId().intValue() != currentCertProfileId) {
            reset();
        }
        if (certificateProfile==null) {
            currentCertProfileId = getSelectedCertProfileId().intValue();
            final CertificateProfile certificateProfile = getEjbcaWebBean().getEjb().getCertificateProfileSession().getCertificateProfile(currentCertProfileId);
            try {
                this.certificateProfile = certificateProfile.clone();
                // Add some defaults
                final GlobalConfiguration globalConfiguration = getEjbcaWebBean().getGlobalConfiguration();
                if (this.certificateProfile.getCRLDistributionPointURI().length()==0) {
                    this.certificateProfile.setCRLDistributionPointURI(globalConfiguration.getStandardCRLDistributionPointURI());
                    this.certificateProfile.setCRLIssuer(globalConfiguration.getStandardCRLIssuer());
                }
                if (this.certificateProfile.getFreshestCRLURI().length()==0) {
                    this.certificateProfile.setFreshestCRLURI(globalConfiguration.getStandardDeltaCRLDistributionPointURI());
                }
            } catch (CloneNotSupportedException e) {
                log.error("Certificate Profiles should be clonable, but this one was not!", e);
            }
        }
        return certificateProfile;
    }

    public String cancel() {
        reset();
        return "done";  // Outcome defined in faces-config.xml
    }

    public String save() {
        boolean success = true;
        try {
            // Perform last minute validations before saving
            CertificateProfile prof = getCertificateProfile();
            if (prof.getAvailableKeyAlgorithmsAsList().isEmpty()) {
                addErrorMessage("ONEAVAILABLEKEYALGORITHM");
                success = false;
            }
            if (prof.getAvailableBitLengthsAsList().isEmpty()) {
                addErrorMessage("ONEAVAILABLEBITLENGTH");
                success = false;
            }
            if (isCtEnabled()) {
                int numEnabledLogs = prof.getEnabledCTLogs().size();
                if (numEnabledLogs == 0) {
                    addErrorMessage("NOCTLOGSSELECTED");
                    success = false;
                } else if (prof.getCTMinSCTs() < 0 || prof.getCTMinSCTsOCSP() < 0 ||
                    prof.getCTMinSCTs() > numEnabledLogs ||
                    prof.getCTMinSCTsOCSP() > numEnabledLogs ||
                    prof.getCTMaxSCTs() < 1 || prof.getCTMaxSCTsOCSP() < 1 ||
                    prof.getCTMaxSCTs() > numEnabledLogs || prof.getCTMaxSCTsOCSP() > numEnabledLogs ||
                    prof.getCTMinSCTs() > prof.getCTMaxSCTs() ||
                    prof.getCTMinSCTsOCSP() > prof.getCTMaxSCTsOCSP()) {
                    addErrorMessage("INCORRECTMINMAXSCTS");
                    success = false;
                }
            }
            if (success) {
                // Remove the added defaults if they were never used
                final CertificateProfile certificateProfile = getCertificateProfile();
                if (!certificateProfile.getUseCRLDistributionPoint() || certificateProfile.getUseDefaultCRLDistributionPoint()) {
                    certificateProfile.setCRLDistributionPointURI("");
                    certificateProfile.setCRLIssuer("");
                }
                if (!certificateProfile.getUseFreshestCRL() || certificateProfile.getUseCADefinedFreshestCRL()) {
                    certificateProfile.setFreshestCRLURI("");
                }
                // Modify the profile
                getEjbcaWebBean().getEjb().getCertificateProfileSession().changeCertificateProfile(getAdmin(), getSelectedCertProfileName(), certificateProfile);
                getEjbcaWebBean().getInformationMemory().certificateProfilesEdited();
                addInfoMessage("CERTIFICATEPROFILESAVED");
                reset();
                return "done";  // Outcome defined in faces-config.xml
            }
        } catch (AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage("Not authorized to edit certificate profile.");
        }
        return "";
    }

    public boolean isTypeCA() throws AuthorizationDeniedException {
        return isTypeRootCa() || isTypeSubCa();
    }
    
    public boolean isTypeEndEntityAvailable() { return true; }
    public boolean isTypeSubCaAvailable() { return isAuthorizedTo(StandardRules.ROLE_ROOT.resource()); }
    public boolean isTypeRootCaAvailable() { return isAuthorizedTo(StandardRules.ROLE_ROOT.resource()); }
    public boolean isTypeHardTokenAvailable() { return isAuthorizedTo(StandardRules.ROLE_ROOT.resource()) && getEjbcaWebBean().getGlobalConfiguration().getIssueHardwareTokens(); }

    public boolean isTypeEndEntity() throws AuthorizationDeniedException { return getCertificateProfile().getType() == CertificateConstants.CERTTYPE_ENDENTITY; }
    public boolean isTypeSubCa() throws AuthorizationDeniedException { return getCertificateProfile().getType()==CertificateConstants.CERTTYPE_SUBCA; }
    public boolean isTypeRootCa() throws AuthorizationDeniedException { return getCertificateProfile().getType()==CertificateConstants.CERTTYPE_ROOTCA; }
    public boolean isTypeHardToken() throws AuthorizationDeniedException { return getCertificateProfile().getType()==CertificateConstants.CERTTYPE_HARDTOKEN; }
    
    public void setTypeEndEntity() throws AuthorizationDeniedException { getCertificateProfile().setType(CertificateConstants.CERTTYPE_ENDENTITY); }
    public void setTypeSubCa() throws AuthorizationDeniedException { getCertificateProfile().setType(CertificateConstants.CERTTYPE_SUBCA); }
    public void setTypeRootCa() throws AuthorizationDeniedException { getCertificateProfile().setType(CertificateConstants.CERTTYPE_ROOTCA); }
    public void setTypeHardToken() throws AuthorizationDeniedException { getCertificateProfile().setType(CertificateConstants.CERTTYPE_HARDTOKEN); }

    public boolean isUniqueCertificateSerialNumberIndex() {
        return getEjbcaWebBean().getEjb().getCertificateCreateSession().isUniqueCertificateSerialNumberIndex();
    }
    
    public List<SelectItem/*<String,String>*/> getAvailableKeyAlgorithmsAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        for (final String current : AlgorithmTools.getAvailableKeyAlgorithms()) {
            ret.add(new SelectItem(current));
        }
        return ret;
    }

    public List<SelectItem/*<String,String>*/> getAvailableEcCurvesAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        final Map<String, List<String>> namedEcCurvesMap = AlgorithmTools.getNamedEcCurvesMap(false);
        final String[] keys = namedEcCurvesMap.keySet().toArray(new String[namedEcCurvesMap.size()]);
        Arrays.sort(keys);
        ret.add(new SelectItem(CertificateProfile.ANY_EC_CURVE, getEjbcaWebBean().getText("AVAILABLEECDSABYBITS")));
        for (final String name : keys) {
            ret.add(new SelectItem(name, StringTools.getAsStringWithSeparator(" / ", namedEcCurvesMap.get(name))));
        }
        return ret;
    }

    public List<SelectItem/*<Integer,String*/> getAvailableBitLengthsAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        for (final int current : CertificateProfile.DEFAULTBITLENGTHS) {
            ret.add(new SelectItem(current, current + " " + getEjbcaWebBean().getText("BITS")));
        }
        return ret;
    }
    
    public List<SelectItem> getAvailableApprovalProfiles() {
        List<SelectItem> ret = new ArrayList<SelectItem>();
        ret.add(new SelectItem(-1, "None"));
        ApprovalProfileSession approvalProfileSession = getEjbcaWebBean().getEjb().getApprovalProfileSession();
        Map<Integer, String> approvalProfiles = approvalProfileSession.getApprovalProfileIdToNameMap();
        Set<Entry<Integer, String>> entries = approvalProfiles.entrySet();
        for(Entry<Integer, String> entry : entries) {
            ret.add(new SelectItem(entry.getKey(), entry.getValue()));
        }
        return ret;
    }
    
    public List<SelectItem/*<String,String*/> getSignatureAlgorithmAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        // null becomes ""-value.
        ret.add(new SelectItem(null, getEjbcaWebBean().getText("INHERITFROMCA")));
        for (final String current : AlgorithmConstants.AVAILABLE_SIGALGS) {
            ret.add(new SelectItem(current, current));
        }
        return ret;
    }
    public String getSignatureAlgorithm() throws AuthorizationDeniedException {
        return getCertificateProfile().getSignatureAlgorithm();
    }
    public void setSignatureAlgorithm(String signatureAlgorithm) throws AuthorizationDeniedException {
        // Inherit signature algorithm from issuing CA is signaled by null, but is rendered as "".
        if ("".equals(signatureAlgorithm)) {
            signatureAlgorithm = null;
        }
        getCertificateProfile().setSignatureAlgorithm(signatureAlgorithm);
    }
    
    public String getValidity() throws AuthorizationDeniedException {
        return ValidityDate.getString(getCertificateProfile().getValidity());
    }
    public void setValidity(String validityString) throws AuthorizationDeniedException, ParameterException {
        validityString = validityString.trim();
        if (validityString.length()>0) {
            final long validity = ValidityDate.encode(validityString);
            if (validity<0) {
                throw new ParameterException(getEjbcaWebBean().getText("INVALIDVALIDITYORCERTEND"));
            }
            getCertificateProfile().setValidity(validity);
        }
    }

    public void toggleUseBasicConstraints() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseBasicConstraints(!getCertificateProfile().getUseBasicConstraints());
        redirectToComponent("header_x509v3extensions");
    }
    
    public void toggleUsePathLengthConstraint() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUsePathLengthConstraint(!getCertificateProfile().getUsePathLengthConstraint());
        if (getCertificateProfile().getUsePathLengthConstraint()) {
            getCertificateProfile().setPathLengthConstraint(1);
        } else {
            getCertificateProfile().setPathLengthConstraint(0);
        }
        redirectToComponent("header_x509v3extensions");
    }
    
    public void toggleUseKeyUsage() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseKeyUsage(!getCertificateProfile().getUseKeyUsage());
        redirectToComponent("header_x509v3extensions_usages");
    }
    
    public boolean isKeyUsageDigitalSignature() throws AuthorizationDeniedException { return getCertificateProfile().getKeyUsage(CertificateConstants.DIGITALSIGNATURE); }
    public boolean isKeyUsageNonRepudiation() throws AuthorizationDeniedException { return getCertificateProfile().getKeyUsage(CertificateConstants.NONREPUDIATION); }
    public boolean isKeyUsageKeyEncipherment() throws AuthorizationDeniedException { return getCertificateProfile().getKeyUsage(CertificateConstants.KEYENCIPHERMENT); }
    public boolean isKeyUsageDataEncipherment() throws AuthorizationDeniedException { return getCertificateProfile().getKeyUsage(CertificateConstants.DATAENCIPHERMENT); }
    public boolean isKeyUsageKeyAgreement() throws AuthorizationDeniedException { return getCertificateProfile().getKeyUsage(CertificateConstants.KEYAGREEMENT); }
    public boolean isKeyUsageKeyCertSign() throws AuthorizationDeniedException { return getCertificateProfile().getKeyUsage(CertificateConstants.KEYCERTSIGN); }
    public boolean isKeyUsageKeyCrlSign() throws AuthorizationDeniedException { return getCertificateProfile().getKeyUsage(CertificateConstants.CRLSIGN); }
    public boolean isKeyUsageEncipherOnly() throws AuthorizationDeniedException { return getCertificateProfile().getKeyUsage(CertificateConstants.ENCIPHERONLY); }
    public boolean isKeyUsageDecipherOnly() throws AuthorizationDeniedException { return getCertificateProfile().getKeyUsage(CertificateConstants.DECIPHERONLY); }
    public void setKeyUsageDigitalSignature(final boolean enabled) throws AuthorizationDeniedException { getCertificateProfile().setKeyUsage(CertificateConstants.DIGITALSIGNATURE, enabled); }
    public void setKeyUsageNonRepudiation(final boolean enabled) throws AuthorizationDeniedException { getCertificateProfile().setKeyUsage(CertificateConstants.NONREPUDIATION, enabled); }
    public void setKeyUsageKeyEncipherment(final boolean enabled) throws AuthorizationDeniedException { getCertificateProfile().setKeyUsage(CertificateConstants.KEYENCIPHERMENT, enabled); }
    public void setKeyUsageDataEncipherment(final boolean enabled) throws AuthorizationDeniedException { getCertificateProfile().setKeyUsage(CertificateConstants.DATAENCIPHERMENT, enabled); }
    public void setKeyUsageKeyAgreement(final boolean enabled) throws AuthorizationDeniedException { getCertificateProfile().setKeyUsage(CertificateConstants.KEYAGREEMENT, enabled); }
    public void setKeyUsageKeyCertSign(final boolean enabled) throws AuthorizationDeniedException { getCertificateProfile().setKeyUsage(CertificateConstants.KEYCERTSIGN, enabled); }
    public void setKeyUsageKeyCrlSign(final boolean enabled) throws AuthorizationDeniedException { getCertificateProfile().setKeyUsage(CertificateConstants.CRLSIGN, enabled); }
    public void setKeyUsageEncipherOnly(final boolean enabled) throws AuthorizationDeniedException { getCertificateProfile().setKeyUsage(CertificateConstants.ENCIPHERONLY, enabled); }
    public void setKeyUsageDecipherOnly(final boolean enabled) throws AuthorizationDeniedException { getCertificateProfile().setKeyUsage(CertificateConstants.DECIPHERONLY, enabled); }

    public void toggleUseExtendedKeyUsage() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseExtendedKeyUsage(!getCertificateProfile().getUseExtendedKeyUsage());
        redirectToComponent("header_x509v3extensions_usages");
    }

    public List<SelectItem> getExtendedKeyUsageOidsAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        AvailableExtendedKeyUsagesConfiguration ekuConfig = getEjbcaWebBean().getAvailableExtendedKeyUsagesConfiguration();
        Map<String, String> ekus = ekuConfig.getAllEKUOidsAndNames();
        ArrayList<String> usedEKUs = getCertificateProfile().getExtendedKeyUsageOids();
        //If in view only mode, display only used EKU's
        if (certProfilesBean.getViewOnly()) {
            for(String oid : usedEKUs) {
                if(ekus.containsKey(oid)) {
                    ret.add(new SelectItem(oid, getEjbcaWebBean().getText(ekus.get(oid))));
                } else {
                    ret.add(new SelectItem(oid, oid));
                }
            }
        } else {
            for (Entry<String, String> eku : ekus.entrySet()) {
                ret.add(new SelectItem(eku.getKey(), getEjbcaWebBean().getText(eku.getValue())));
            }           
            for (String oid : usedEKUs) {
                if (!ekus.containsKey(oid)) {
                    ret.add(new SelectItem(oid, oid));
                }
            }
        }
        Collections.sort(ret, new Comparator<SelectItem>() {
            @Override
            public int compare(SelectItem first, SelectItem second) {
                return first.getLabel().compareTo(second.getLabel());
            }
            
        });
        return ret;
    }
    
    public void toggleUseSubjectAlternativeName() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseSubjectAlternativeName(!getCertificateProfile().getUseSubjectAlternativeName());
        redirectToComponent("header_x509v3extensions_names");
    }
    
    public void toggleUseIssuerAlternativeName() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseIssuerAlternativeName(!getCertificateProfile().getUseIssuerAlternativeName());
        redirectToComponent("header_x509v3extensions_names");
    }

    public void toggleUseNameConstraints() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseNameConstraints(!getCertificateProfile().getUseNameConstraints());
        redirectToComponent("header_x509v3extensions_names");
    }
    
    public void toggleUseCRLDistributionPoint() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseCRLDistributionPoint(!getCertificateProfile().getUseCRLDistributionPoint());
        redirectToComponent("header_x509v3extensions_valdata");
    }
    
    public void toggleUseDefaultCRLDistributionPoint() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseDefaultCRLDistributionPoint(!getCertificateProfile().getUseDefaultCRLDistributionPoint());
        redirectToComponent("header_x509v3extensions_valdata");
    }
    
    public void toggleUseCADefinedFreshestCRL() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseCADefinedFreshestCRL(!getCertificateProfile().getUseCADefinedFreshestCRL());
        redirectToComponent("header_x509v3extensions_valdata");
    }
    
    public void toggleUseFreshestCRL() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseFreshestCRL(!getCertificateProfile().getUseFreshestCRL());
        redirectToComponent("header_x509v3extensions_valdata");
    }
    
    public void toggleUseCertificatePolicies() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseCertificatePolicies(!getCertificateProfile().getUseCertificatePolicies());
        redirectToComponent("header_x509v3extensions_usages");
    }
    
    public ListDataModel<CertificatePolicy> getCertificatePolicies() throws AuthorizationDeniedException {
        if (certificatePoliciesModel==null) {
            final List<CertificatePolicy> certificatePolicies = getCertificateProfile().getCertificatePolicies();
            if (certificatePolicies!=null) {
                certificatePoliciesModel = new ListDataModel<CertificatePolicy>(certificatePolicies);
            } else {
                certificatePoliciesModel = new ListDataModel<CertificatePolicy>();
            }
        }
        return certificatePoliciesModel;
    }
    
    public boolean isCurrentCertificatePolicyQualifierIdNone() throws AuthorizationDeniedException {
        return "".equals(((CertificatePolicy)getCertificatePolicies().getRowData()).getQualifierId());
    }
    public boolean isCurrentCertificatePolicyQualifierIdCpsUri() throws AuthorizationDeniedException {
        return CertificatePolicy.id_qt_cps.equals(((CertificatePolicy)getCertificatePolicies().getRowData()).getQualifierId());
    }
    public boolean isCurrentCertificatePolicyQualifierIdUserNotice() throws AuthorizationDeniedException {
        return CertificatePolicy.id_qt_unotice.equals(((CertificatePolicy)getCertificatePolicies().getRowData()).getQualifierId());
    }

    public CertificatePolicy getNewCertificatePolicy() {
        if (newCertificatePolicy==null) {
            newCertificatePolicy = new CertificatePolicy("", "", "");
        }
        return newCertificatePolicy;
    }
    public void setNewCertificatePolicy(final CertificatePolicy newCertificatePolicy) { this.newCertificatePolicy = newCertificatePolicy; }

    public void actionNewCertificatePolicyQualifierIdNone() throws IOException {
        getNewCertificatePolicy().setQualifierId("");
        getNewCertificatePolicy().setQualifier("");
        redirectToComponent("header_x509v3extensions_usages");
    }
    public void actionNewCertificatePolicyQualifierIdCpsUri() throws IOException {
        getNewCertificatePolicy().setQualifierId(CertificatePolicy.id_qt_cps);
        getNewCertificatePolicy().setQualifier("");
        redirectToComponent("header_x509v3extensions_usages");
    }
    public void actionNewCertificatePolicyQualifierIdUserNotice() throws IOException {
        getNewCertificatePolicy().setQualifierId(CertificatePolicy.id_qt_unotice);
        getNewCertificatePolicy().setQualifier("");
        redirectToComponent("header_x509v3extensions_usages");
    }
    public boolean isNewCertificatePolicyQualifierIdNone() { return "".equals(getNewCertificatePolicy().getQualifierId()); }
    public boolean isNewCertificatePolicyQualifierIdCpsUri() { return CertificatePolicy.id_qt_cps.equals(getNewCertificatePolicy().getQualifierId()); }
    public boolean isNewCertificatePolicyQualifierIdUserNotice() { return CertificatePolicy.id_qt_unotice.equals(getNewCertificatePolicy().getQualifierId()); }

    public String addCertificatePolicy() throws AuthorizationDeniedException, IOException {
        CertificatePolicy newCertificatePolicy = getNewCertificatePolicy();
        if (newCertificatePolicy.getPolicyID().trim().length()>0) {
            // Only add the policy if something is specified in the PolicyID field
            newCertificatePolicy = new CertificatePolicy(newCertificatePolicy.getPolicyID().trim(), newCertificatePolicy.getQualifierId(), newCertificatePolicy.getQualifier().trim());
            getCertificateProfile().addCertificatePolicy(newCertificatePolicy);
        }
        setNewCertificatePolicy(null);
        certificatePoliciesModel = null;
        redirectToComponent("header_x509v3extensions_usages");
        return "";
    }

    public String deleteCertificatePolicy() throws AuthorizationDeniedException, IOException {
        final CertificatePolicy certificatePolicy = (CertificatePolicy) getCertificatePolicies().getRowData();
        getCertificateProfile().removeCertificatePolicy(certificatePolicy);
        newCertificatePolicy = certificatePolicy;
        certificatePoliciesModel = null;
        redirectToComponent("header_x509v3extensions_usages");
        return "";
    }

    public ListDataModel<String> getCaIssuers() throws AuthorizationDeniedException {
        if (caIssuersModel==null) {
            final List<String> caIssuers = getCertificateProfile().getCaIssuers();
            if (caIssuers!=null) {
                caIssuersModel = new ListDataModel<String>(caIssuers);
            } else {
                caIssuersModel = new ListDataModel<String>();
            }
        }
        return caIssuersModel;
    }

    public void toggleUseAuthorityInformationAccess() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseAuthorityInformationAccess(!getCertificateProfile().getUseAuthorityInformationAccess());
        redirectToComponent("header_x509v3extensions_valdata");
    }
    
    public void toggleUseDefaultOCSPServiceLocator() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseDefaultOCSPServiceLocator(!getCertificateProfile().getUseDefaultOCSPServiceLocator());
        redirectToComponent("header_x509v3extensions_valdata");
    }
    
    public String getNewCaIssuer() { return newCaIssuer; }
    public void setNewCaIssuer(String newCaIssuer) { this.newCaIssuer = newCaIssuer.trim(); }

    public String addCaIssuer() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().addCaIssuer(newCaIssuer);
        newCaIssuer = "";
        caIssuersModel = null;
        redirectToComponent("header_x509v3extensions_valdata");
        return "";
    }

    public String deleteCaIssuer() throws AuthorizationDeniedException, IOException {
        final String caIssuer = (String) getCaIssuers().getRowData();
        getCertificateProfile().removeCaIssuer(caIssuer);
        newCaIssuer = caIssuer;
        caIssuersModel = null;
        redirectToComponent("header_x509v3extensions_valdata");
        return "";
    }
    
    public void toggleUsePrivateKeyUsagePeriodNotBefore() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUsePrivateKeyUsagePeriodNotBefore(!getCertificateProfile().isUsePrivateKeyUsagePeriodNotBefore());
        redirectToComponent("header_x509v3extensions_valdata");
    }

    public String getPrivateKeyUsagePeriodStartOffset() throws AuthorizationDeniedException {
        final CertificateProfile certificateProfile = getCertificateProfile();
        if (certificateProfile.isUsePrivateKeyUsagePeriodNotBefore()) {
            return ValidityDate.getString(certificateProfile.getPrivateKeyUsagePeriodStartOffset() / (24 * 3600));
        } else {
            return "";
        }
    }
    public void setPrivateKeyUsagePeriodStartOffset(String privateKeyUsagePeriodStartOffset) throws ParameterException, AuthorizationDeniedException {
        privateKeyUsagePeriodStartOffset = privateKeyUsagePeriodStartOffset.trim();
        if (privateKeyUsagePeriodStartOffset.length()>0) {
            final long validity = ValidityDate.encode(privateKeyUsagePeriodStartOffset);
            if (validity<0) {
                throw new ParameterException(getEjbcaWebBean().getText("INVALIDPRIVKEYSTARTOFFSET"));
            }
            getCertificateProfile().setPrivateKeyUsagePeriodStartOffset(validity*24*3600);
        }
    }

    public void toggleUsePrivateKeyUsagePeriodNotAfter() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUsePrivateKeyUsagePeriodNotAfter(!getCertificateProfile().isUsePrivateKeyUsagePeriodNotAfter());
        redirectToComponent("header_x509v3extensions_valdata");
    }
    
    public String getPrivateKeyUsagePeriodLength() throws AuthorizationDeniedException {
        final CertificateProfile certificateProfile = getCertificateProfile();
        if (certificateProfile.isUsePrivateKeyUsagePeriodNotAfter()) {
            return ValidityDate.getString(certificateProfile.getPrivateKeyUsagePeriodLength() / (24 * 3600));
        } else {
            return "";
        }
    }
    public void setPrivateKeyUsagePeriodLength(String privateKeyUsagePeriodLength) throws ParameterException, AuthorizationDeniedException {
        privateKeyUsagePeriodLength = privateKeyUsagePeriodLength.trim();
        if (privateKeyUsagePeriodLength.length()>0) {
            final long validity = ValidityDate.encode(privateKeyUsagePeriodLength);
            if (validity<0) {
                throw new ParameterException(getEjbcaWebBean().getText("INVALIDPRIVKEYPERIOD"));
            }
            getCertificateProfile().setPrivateKeyUsagePeriodLength(validity*24*3600);
        }
    }

    public void toggleUseQCStatement() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseQCStatement(!getCertificateProfile().getUseQCStatement());
        redirectToComponent("header_qcStatements");
    }
    
    public void toggleUseQCEtsiValueLimit() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseQCEtsiValueLimit(!getCertificateProfile().getUseQCEtsiValueLimit());
        redirectToComponent("header_qcStatements");
    }
    
    public void toggleUseQCEtsiRetentionPeriod() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseQCEtsiRetentionPeriod(!getCertificateProfile().getUseQCEtsiRetentionPeriod());
        redirectToComponent("header_qcStatements");
    }
    
    public void toggleUseQCCustomString() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseQCCustomString(!getCertificateProfile().getUseQCCustomString());
        redirectToComponent("header_qcStatements");
    }
    
    public void toggleUseCertificateTransparencyInCerts() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseCertificateTransparencyInCerts(!getCertificateProfile().isUseCertificateTransparencyInCerts());
        redirectToComponent("header_certificatetransparency");
    }

    public void toggleUseCertificateTransparencyInOCSP() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseCertificateTransparencyInOCSP(!getCertificateProfile().isUseCertificateTransparencyInOCSP());
        redirectToComponent("header_certificatetransparency");
    }
    
    public void toggleUseCertificateTransparencyInPublishers() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseCertificateTransparencyInPublishers(!getCertificateProfile().isUseCertificateTransparencyInPublishers());
        redirectToComponent("header_certificatetransparency");
    }
    
    public boolean isCtAvailable() { return CertificateTransparencyFactory.isCTAvailable(); }
    public boolean isCtEnabled() throws AuthorizationDeniedException {
        return getCertificateProfile().isUseCertificateTransparencyInCerts() ||
            getCertificateProfile().isUseCertificateTransparencyInOCSP() ||
            getCertificateProfile().isUseCertificateTransparencyInPublishers();
    }
    
    public boolean isCtInCertsOrOCSPEnabled() throws AuthorizationDeniedException {
        return getCertificateProfile().isUseCertificateTransparencyInCerts() ||
            getCertificateProfile().isUseCertificateTransparencyInOCSP();
    }
    
    public boolean isCtInOCSPOrPublishersEnabled() throws AuthorizationDeniedException {
        return getCertificateProfile().isUseCertificateTransparencyInOCSP() ||
            getCertificateProfile().isUseCertificateTransparencyInPublishers();
    }
    
    public List<SelectItem/*<String,String*/> getEnabledCTLogsAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        for (final CTLogInfo current : getEjbcaWebBean().getGlobalConfiguration().getCTLogs().values()) {
            ret.add(new SelectItem(String.valueOf(current.getLogId()), current.getUrl()));
        }
        return ret;
    }
    /** @returns the size of the select box */  
    public int getEnabledCTLogsAvailableSize() { return Math.max(3, Math.min(6, getEnabledCTLogsAvailable().size())); }
    public List<String> getEnabledCTLogs() throws AuthorizationDeniedException {
        final List<String> ret = new ArrayList<String>();
        for (Integer current : getCertificateProfile().getEnabledCTLogs()) {
            ret.add(current.toString());
        }
        return ret;
    }
    public void setEnabledCTLogs(final List<String> in) throws AuthorizationDeniedException {
        final Set<Integer> out = new HashSet<Integer>();
        for (String current : in) {
            out.add(Integer.parseInt(current));
        }
        getCertificateProfile().setEnabledCTLogs(out);
    }

    public void toggleUseMicrosoftTemplate() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseMicrosoftTemplate(!getCertificateProfile().getUseMicrosoftTemplate());
        redirectToComponent("otherextensions");
    }
    
    public List<SelectItem/*<String,String*/> getMicrosoftTemplateAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        for (final String current : CertificateProfile.AVAILABLE_MSTEMPLATES) {
            ret.add(new SelectItem(current, current));
        }
        return ret;
    }

    public void toggleUseDocumentTypeList() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseDocumentTypeList(!getCertificateProfile().getUseDocumentTypeList());
        redirectToComponent("cvc_epassport");
    }
    
    public String getDocumentTypeListNew() { return documentTypeListNew; }
    public void setDocumentTypeListNew(String documentTypeListNew) { this.documentTypeListNew = documentTypeListNew.trim(); }

    public void documentTypeListRemove() throws AuthorizationDeniedException, IOException {
        final String current = (String) getDocumentTypeList().getRowData();
        ArrayList<String> documentTypeListValue = getCertificateProfile().getDocumentTypeList();
        documentTypeListValue.remove(current);
        getCertificateProfile().setDocumentTypeList(documentTypeListValue);
        documentTypeListNew = current;
        documentTypeList = null;    // Trigger reload of model
        redirectToComponent("cvc_epassport");
    }
    public void documentTypeListAdd() throws AuthorizationDeniedException, IOException {
        if (documentTypeListNew.length()>0) {
            ArrayList<String> documentTypeListValue = getCertificateProfile().getDocumentTypeList();
            documentTypeListValue.add(documentTypeListNew);
            getCertificateProfile().setDocumentTypeList(documentTypeListValue);
            documentTypeListNew = "";
            documentTypeList = null;    // Trigger reload of model
        }
        redirectToComponent("cvc_epassport");
    }
    public ListDataModel<String> getDocumentTypeList() throws AuthorizationDeniedException {
        if (documentTypeList==null) {
            documentTypeList = new ListDataModel<String>(getCertificateProfile().getDocumentTypeList());
        }
        return documentTypeList;
    }

    public boolean isCvcAvailable() {
        return CvcCA.getImplementationClasses().iterator().hasNext();
    }
    
    public boolean isCvcTerminalTypeIs() throws AuthorizationDeniedException { return getCertificateProfile().getCVCTerminalType() == CertificateProfile.CVC_TERMTYPE_IS; }
    public boolean isCvcTerminalTypeAt() throws AuthorizationDeniedException { return getCertificateProfile().getCVCTerminalType() == CertificateProfile.CVC_TERMTYPE_AT; }
    public boolean isCvcTerminalTypeSt() throws AuthorizationDeniedException { return getCertificateProfile().getCVCTerminalType() == CertificateProfile.CVC_TERMTYPE_ST; }

    public void setCvcTerminalTypeIs() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setCVCTerminalType(CertificateProfile.CVC_TERMTYPE_IS);
        getCertificateProfile().setCVCAccessRights(CertificateProfile.CVC_ACCESS_NONE);
        getCertificateProfile().setCVCLongAccessRights(null);
        redirectToComponent("cvc_epassport");
    }
    public void setCvcTerminalTypeAt() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setCVCTerminalType(CertificateProfile.CVC_TERMTYPE_AT);
        getCertificateProfile().setCVCAccessRights(CertificateProfile.CVC_ACCESS_NONE);
        getCertificateProfile().setCVCLongAccessRights(null);
        redirectToComponent("cvc_epassport");
    }
    public void setCvcTerminalTypeSt() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setCVCTerminalType(CertificateProfile.CVC_TERMTYPE_ST);
        getCertificateProfile().setCVCAccessRights(CertificateProfile.CVC_ACCESS_NONE);
        getCertificateProfile().setCVCLongAccessRights(null);
        redirectToComponent("cvc_epassport");
    }
    
    public List<SelectItem/*<Integer,String*/> getCvcSignTermDVTypeAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        ret.add(new SelectItem(CertificateProfile.CVC_SIGNTERM_DV_AB, getEjbcaWebBean().getText("CVCACCREDITATIONBODY")));
        ret.add(new SelectItem(CertificateProfile.CVC_SIGNTERM_DV_CSP, getEjbcaWebBean().getText("CVCCERTIFICATIONSERVICEPROVIDER")));
        return ret;
    }

    // Translation between UI and CertificateProfile's format
    public List<Integer> getCvcLongAccessRights() throws AuthorizationDeniedException {
        byte[] arl = getCertificateProfile().getCVCLongAccessRights();
        if (arl == null) {
            arl = CertificateProfile.DEFAULT_CVC_RIGHTS_AT;
        }
        AccessRightAuthTerm arlflags;
        try {
            arlflags = new AccessRightAuthTerm(arl);
        } catch (IllegalArgumentException e) {
            // zero-length array or other error
            arlflags = new AccessRightAuthTerm();
        }
        final List<Integer> ret = new ArrayList<Integer>();
        for (int i=0; i<=37; i++) {
            if (arlflags.getFlag(i)) {
                ret.add(Integer.valueOf(i));
            }
        }
        return ret;
    }
    // Translation between UI and CertificateProfile's format
    public void setCvcLongAccessRights(List<Integer> in) throws AuthorizationDeniedException {
        final AccessRightAuthTerm arlflags = new AccessRightAuthTerm(CertificateProfile.DEFAULT_CVC_RIGHTS_AT);
        for (final Integer current : in) {
            arlflags.setFlag(current, true);
        }
        getCertificateProfile().setCVCAccessRights(CertificateProfile.CVC_ACCESS_NONE);
        getCertificateProfile().setCVCLongAccessRights(arlflags.getEncoded());
    }

    public boolean isCvcAccessRightDg3() throws AuthorizationDeniedException { return isCvcAccessRight(CertificateProfile.CVC_ACCESS_DG3); }
    public boolean isCvcAccessRightDg4() throws AuthorizationDeniedException { return isCvcAccessRight(CertificateProfile.CVC_ACCESS_DG4); }
    public boolean isCvcAccessRightSign() throws AuthorizationDeniedException { return isCvcAccessRight(CertificateProfile.CVC_ACCESS_SIGN); }
    public boolean isCvcAccessRightQualSign() throws AuthorizationDeniedException { return isCvcAccessRight(CertificateProfile.CVC_ACCESS_QUALSIGN); }
    public void setCvcAccessRightDg3(final boolean enabled) throws AuthorizationDeniedException { setCvcAccessRight(CertificateProfile.CVC_ACCESS_DG3, enabled); }
    public void setCvcAccessRightDg4(final boolean enabled) throws AuthorizationDeniedException { setCvcAccessRight(CertificateProfile.CVC_ACCESS_DG4, enabled); }
    public void setCvcAccessRightSign(final boolean enabled) throws AuthorizationDeniedException { setCvcAccessRight(CertificateProfile.CVC_ACCESS_SIGN, enabled); }
    public void setCvcAccessRightQualSign(final boolean enabled) throws AuthorizationDeniedException { setCvcAccessRight(CertificateProfile.CVC_ACCESS_QUALSIGN, enabled); }

    private boolean isCvcAccessRight(final int accessRight) throws AuthorizationDeniedException {
        return (getCertificateProfile().getCVCAccessRights() & accessRight) != 0;
    }
    private void setCvcAccessRight(final int accessRight, final boolean enabled) throws AuthorizationDeniedException {
        if (enabled) {
            getCertificateProfile().setCVCAccessRights(getCertificateProfile().getCVCAccessRights() | accessRight);
        } else {
            getCertificateProfile().setCVCAccessRights(getCertificateProfile().getCVCAccessRights() & ~accessRight);
        }
    }

    public List<SelectItem/*<Integer,String*/> getCvcAccessRightsAtAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        ret.add(new SelectItem(String.valueOf(0), getEjbcaWebBean().getText("CVCACCESSAGEVERIFICATION")));
        ret.add(new SelectItem(String.valueOf(1), getEjbcaWebBean().getText("CVCACCESSCOMMUNITYIDVERIFICATION")));
        ret.add(new SelectItem(String.valueOf(2), getEjbcaWebBean().getText("CVCACCESSRESTRICTEDIDENTIFICATION")));
        ret.add(new SelectItem(String.valueOf(3), getEjbcaWebBean().getText("CVCACCESSPRIVILEGEDTERMINAL")));
        ret.add(new SelectItem(String.valueOf(4), getEjbcaWebBean().getText("CVCACCESSCANALLOWED")));
        ret.add(new SelectItem(String.valueOf(5), getEjbcaWebBean().getText("CVCACCESSPINMANAGEMENT")));
        ret.add(new SelectItem(String.valueOf(6), getEjbcaWebBean().getText("CVCACCESSINSTALLCERT")));
        ret.add(new SelectItem(String.valueOf(7), getEjbcaWebBean().getText("CVCACCESSINSTALLQUALIFIEDCERT")));
        final String readDGFormat = getEjbcaWebBean().getText("CVCACCESSREADDG");
        for (int i=8; i<=28; i++) {
            ret.add(new SelectItem(String.valueOf(i), MessageFormat.format(readDGFormat, i-8+1)));
        }
        final String writeDGFormat = getEjbcaWebBean().getText("CVCACCESSWRITEDG");
        ret.add(new SelectItem(String.valueOf(37), MessageFormat.format(writeDGFormat, 17)));
        ret.add(new SelectItem(String.valueOf(36), MessageFormat.format(writeDGFormat, 18)));
        ret.add(new SelectItem(String.valueOf(35), MessageFormat.format(writeDGFormat, 19)));
        ret.add(new SelectItem(String.valueOf(34), MessageFormat.format(writeDGFormat, 20)));
        ret.add(new SelectItem(String.valueOf(33), MessageFormat.format(writeDGFormat, 21)));
        return ret;
    }

    public void toggleUseCustomDnOrder() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseCustomDnOrder(!getCertificateProfile().getUseCustomDnOrder());
        redirectToComponent("otherdata");
    }

    public void toggleUseCNPostfix() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseCNPostfix(!getCertificateProfile().getUseCNPostfix());
        redirectToComponent("otherdata");
    }
    
    public void toggleUseSubjectDNSubSet() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseSubjectDNSubSet(!getCertificateProfile().getUseSubjectDNSubSet());
        redirectToComponent("otherdata");
    }
    
    public List<SelectItem/*<Integer,String*/> getSubjectDNSubSetAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        final Integer[] useSubjectDNFields = DNFieldExtractor.getUseFields(DNFieldExtractor.TYPE_SUBJECTDN);
        for (int i=0; i<useSubjectDNFields.length; i++) {
            ret.add(new SelectItem(useSubjectDNFields[i], getEjbcaWebBean().getText(DnComponents.getDnLanguageTexts().get(i))));
        }
        return ret;
    }

    public void toggleUseSubjectAltNameSubSet() throws AuthorizationDeniedException, IOException {
        getCertificateProfile().setUseSubjectAltNameSubSet(!getCertificateProfile().getUseSubjectAltNameSubSet());
        redirectToComponent("otherdata");
    }
    
    public List<SelectItem/*<Integer,String*/> getSubjectAltNameSubSetAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        final Integer[] useSubjectANFields = DNFieldExtractor.getUseFields(DNFieldExtractor.TYPE_SUBJECTALTNAME);
        for (int i=0; i<useSubjectANFields.length; i++) {
            ret.add(new SelectItem(useSubjectANFields[i], getEjbcaWebBean().getText(DnComponents.getAltNameLanguageTexts().get(i))));
        }
        return ret;
    }

    public List<SelectItem> getAvailableCertificateExtensionsAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        
        AvailableCustomCertificateExtensionsConfiguration cceConfig = getEjbcaWebBean().getAvailableCustomCertExtensionsConfiguration();
        
        List<Integer> usedExtensions = getCertificateProfile().getUsedCertificateExtensions();
        if (certProfilesBean.getViewOnly()) {
            //If in view mode, only display used values.
            for(int id : usedExtensions) {
                if (!cceConfig.isCustomCertExtensionSupported(id)) {
                    String note = id + " (No longer used. Please unselect this option)";
                    ret.add(new SelectItem(id, note));
                } else {
                    ret.add(new SelectItem(id, getEjbcaWebBean().getText(cceConfig.getCustomCertificateExtension(id).getDisplayName())));
                }
            }

        } else {
            for (final CertificateExtension current : cceConfig.getAllAvailableCustomCertificateExtensions()) {
                ret.add(new SelectItem(current.getId(), getEjbcaWebBean().getText(current.getDisplayName())));
            }            
            for (int id : usedExtensions) {
                if (!cceConfig.isCustomCertExtensionSupported(id)) {
                    String note = id + " (No longer used. Please unselect this option)";
                    ret.add(new SelectItem(id, note));
                }
            }
        }
        Collections.sort(ret, new Comparator<SelectItem>() {
            @Override
            public int compare(SelectItem first, SelectItem second) {
                return first.getLabel().compareToIgnoreCase(second.getLabel());
            }
        });
        
        return ret;
    }

    public int getAvailableCertificateExtensionsAvailableSize() {
        return Math.max(1, Math.min(6, getAvailableCertificateExtensionsAvailable().size()));
    }

    public List<SelectItem/*<Integer,String*/> getAvailableCAsAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        final List<Integer> allCAs = getEjbcaWebBean().getEjb().getCaSession().getAllCaIds();
        final List<Integer> authorizedCAs = getEjbcaWebBean().getEjb().getCaSession().getAuthorizedCaIds(getAdmin());
        final Map<Integer, String> caIdToNameMap = getEjbcaWebBean().getEjb().getCaSession().getCAIdToNameMap();
    
        //If in view mode, add only authorized CA's 
        if (certProfilesBean.getViewOnly()) {
            for(final Integer caId : authorizedCAs) {
                ret.add(new SelectItem(caId, caIdToNameMap.get(caId), "", true));
            }
        } else {
            for (final Integer caId : allCAs) {
                ret.add(new SelectItem(caId, caIdToNameMap.get(caId), "", (authorizedCAs.contains(caId) ? false : true)));
            }
        }
        Collections.sort(ret, new Comparator<SelectItem>() {
            @Override
            public int compare(SelectItem first, SelectItem second) {
                return first.getLabel().compareToIgnoreCase(second.getLabel());
            }
        });
        ret. add(0, new SelectItem(String.valueOf(CertificateProfile.ANYCA), getEjbcaWebBean().getText("ANYCA")));
        
        return ret;
    }
    
    public int getAvailableCAsAvailableSize() { return Math.max(1, Math.min(7, getAvailableCAsAvailable().size())); };

    public List<SelectItem/*<Integer,String*/> getPublisherListAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        final Collection<Integer> authorizedPublisherIds = getEjbcaWebBean().getEjb().getCaAdminSession().getAuthorizedPublisherIds(getAdmin());
        final Map<Integer, String> publisherIdToNameMap = getEjbcaWebBean().getEjb().getPublisherSession().getPublisherIdToNameMap();
        for (final Integer publisherId : authorizedPublisherIds) {
            ret.add(new SelectItem(publisherId, publisherIdToNameMap.get(publisherId)));
        }
        return ret;
    }
    public int getPublisherListAvailableSize() { return Math.max(1, Math.min(5, getPublisherListAvailable().size())); };

    public boolean isApprovalEnabledAddEndEntity() throws AuthorizationDeniedException { return isApprovalEnabled(CAInfo.REQ_APPROVAL_ADDEDITENDENTITY); }
    public boolean isApprovalEnabledKeyRecover() throws AuthorizationDeniedException { return isApprovalEnabled(CAInfo.REQ_APPROVAL_KEYRECOVER); }
    public boolean isApprovalEnabledRevocation() throws AuthorizationDeniedException { return isApprovalEnabled(CAInfo.REQ_APPROVAL_REVOCATION); }
    public boolean isApprovalEnabledActivateCa() throws AuthorizationDeniedException { return isApprovalEnabled(CAInfo.REQ_APPROVAL_ACTIVATECA); }
    
    public void setApprovalEnabledAddEndEntity(final boolean enabled) throws AuthorizationDeniedException { setApprovalEnabled(CAInfo.REQ_APPROVAL_ADDEDITENDENTITY, enabled); }
    public void setApprovalEnabledKeyRecover(final boolean enabled) throws AuthorizationDeniedException { setApprovalEnabled(CAInfo.REQ_APPROVAL_KEYRECOVER, enabled); }
    public void setApprovalEnabledRevocation(final boolean enabled) throws AuthorizationDeniedException { setApprovalEnabled(CAInfo.REQ_APPROVAL_REVOCATION, enabled); }
    public void setApprovalEnabledActivateCa(final boolean enabled) throws AuthorizationDeniedException { setApprovalEnabled(CAInfo.REQ_APPROVAL_ACTIVATECA, enabled); }
  
    private boolean isApprovalEnabled(final int approvalType) throws AuthorizationDeniedException {
        return getCertificateProfile().getApprovalSettings().contains(Integer.valueOf(approvalType));
    }
    
    private void setApprovalEnabled(final int approvalType, final boolean enabled) throws AuthorizationDeniedException {
        final List<Integer> approvalSettings = new ArrayList<Integer>(getCertificateProfile().getApprovalSettings());
        if (enabled) {
            if (!approvalSettings.contains(Integer.valueOf(approvalType))) {
                approvalSettings.add(Integer.valueOf(approvalType));
            }
        } else {
            approvalSettings.remove(Integer.valueOf(approvalType));
        }
        getCertificateProfile().setApprovalSettings(approvalSettings);
    }

    public List<SelectItem/*<Integer,String*/> getNumOfReqApprovalsAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        for (int i=1; i<=4; i++) {
            ret.add(new SelectItem(Integer.valueOf(i), String.valueOf(i)));
        }
        return ret;
    }

    /** Redirect the client browser to the relevant section of certificate profile page */
    private void redirectToComponent(final String componentId) throws IOException {
        final ExternalContext ec = FacesContext.getCurrentInstance().getExternalContext();
        ec.redirect(getEjbcaWebBean().getBaseUrl()+getEjbcaWebBean().getGlobalConfiguration().getAdminWebPath()+"ca/editcertificateprofiles/editcertificateprofile.jsf#cpf:"+componentId);
    }
}
