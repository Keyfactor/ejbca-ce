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
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.model.DataModelEvent;
import javax.faces.model.DataModelListener;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CvcCA;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CertificateExtension;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.PKIDisclosureStatement;
import org.cesecore.certificates.certificatetransparency.CTLogInfo;
import org.cesecore.certificates.certificatetransparency.CertificateTransparencyFactory;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.approval.ApprovalProfileSession;
import org.ejbca.cvc.AccessRightAuthTerm;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

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
    private ListDataModel<PKIDisclosureStatement> pdsListModel = null;
    private List<ApprovalRequestItem> approvalRequestItems = null;

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
        pdsListModel = null;
        approvalRequestItems = null;
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
                final int numEnabledLabels = prof.getEnabledCtLabels().size();
                final boolean isNumOfSctsCustom = prof.isNumberOfSctByCustom();
                final boolean isMaxNumOfSctsCustom = prof.isMaxNumberOfSctByCustom();
                if (numEnabledLabels == 0) {
                    addErrorMessage("NOCTLABELSSELECTED");
                    success = false;
                } else if (((prof.getCtMinScts() < 0 && prof.isUseCertificateTransparencyInCerts()) || 
                            (prof.getCtMinSctsOcsp() < 0 && prof.isUseCertificateTransparencyInOCSP())) 
                            && isNumOfSctsCustom) {
                    addErrorMessage("INCORRECTMINSCTS");
                    success = false;
                } else if((prof.getCtMaxScts() < 0 && prof.isUseCertificateTransparencyInCerts()) || 
                          (prof.getCtMaxSctsOcsp() < 0 && prof.isUseCertificateTransparencyInOCSP())) {
                    addErrorMessage("INCORRECTMAXSCTS");
                    success = false;
                    
                } else if (((prof.getCtMaxScts() < prof.getCtMinScts() && prof.isUseCertificateTransparencyInCerts()) ||
                            (prof.getCtMaxSctsOcsp() < prof.getCtMinSctsOcsp() && prof.isUseCertificateTransparencyInOCSP()))
                            && (isNumOfSctsCustom && isMaxNumOfSctsCustom)) {
                    addErrorMessage("INCORRECTMAXLESSTHANMIN");
                    success = false;
                } else if (((prof.getCtMinScts() < numEnabledLabels && prof.getCtMinScts() != 0 && prof.isUseCertificateTransparencyInCerts()) ||
                            (prof.getCtMinSctsOcsp() < numEnabledLabels && prof.getCtMinSctsOcsp() != 0 && prof.isUseCertificateTransparencyInOCSP()))
                            && isNumOfSctsCustom) {
                    addErrorMessage("INCORRECTNUMBEROFLABELS");
                    success = false;
                } else if (((prof.getCtMaxScts() < numEnabledLabels && prof.isUseCertificateTransparencyInCerts()) ||
                           (prof.getCtMaxSctsOcsp() < numEnabledLabels && prof.isUseCertificateTransparencyInOCSP()))
                            && isMaxNumOfSctsCustom) {
                    addErrorMessage("INCORRECTNUMBEROFLABELSMAX");
                    success = false;
                }
            }
            if (prof.getUseExpirationRestrictionForWeekdays()) {
                boolean allDaysExcluded = true;
                for (boolean enabled: prof.getExpirationRestrictionWeekdays()) {
                    if (!enabled) {
                        allDaysExcluded = false;
                        break;
                    }
                }
                if (allDaysExcluded) {
                    addErrorMessage("CERT_EXPIRATION_RESTRICTION_FOR_WEEKDAYS_ALL_EXCLUDED");
                    success = false;
                }
            }
            if (prof.getUseQCStatement()) {
                boolean[] statements = {
                        prof.getUsePkixQCSyntaxV2(),
                        prof.getUseQCEtsiQCCompliance(),
                        prof.getUseQCEtsiSignatureDevice(),
                        prof.getUseQCEtsiValueLimit(),
                        prof.getUseQCEtsiRetentionPeriod(),
                        !StringUtils.isEmpty(prof.getQCEtsiType()),
                        prof.getQCEtsiPds() != null && prof.getQCEtsiPds().size() > 0 && !(prof.getQCEtsiPds().size() == 1 && prof.getQCEtsiPds().get(0).getUrl() == null),
                        prof.getUseQCCustomString() && !prof.getQCCustomStringOid().isEmpty() && !prof.getQCCustomStringText().isEmpty()
                };
                // Check that at least one QC statement is used
                boolean foundUsed = false;
                for (boolean statement : statements) {
                    if (statement) {
                        foundUsed = true;
                    }
                }
                if (!foundUsed) {
                    addErrorMessage("ONEQCSTATEMENTUSED");
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

                applyExpirationRestrictionForValidityWithFixedDate( certificateProfile);

                final List<PKIDisclosureStatement> pdsList = certificateProfile.getQCEtsiPds();
                if (pdsList != null) {
                    final List<PKIDisclosureStatement> pdsCleaned = new ArrayList<>();
                    for (final PKIDisclosureStatement pds : pdsList) {
                        if (!StringUtils.isEmpty(pds.getUrl())) {
                            pdsCleaned.add(pds);
                        }
                    }
                    certificateProfile.setQCEtsiPds(pdsCleaned);
                }
                Map<ApprovalRequestType, Integer> approvals = new HashMap<>();
                for(ApprovalRequestItem approvalRequestItem : approvalRequestItems) {
                    approvals.put(approvalRequestItem.getRequestType(), approvalRequestItem.getApprovalProfileId());
                }
                certificateProfile.setApprovals(approvals);

                // Modify the profile
                getEjbcaWebBean().getEjb().getCertificateProfileSession().changeCertificateProfile(getAdmin(), getSelectedCertProfileName(), certificateProfile);
                addInfoMessage("CERTIFICATEPROFILESAVED");
                reset();
                return "done";  // Outcome defined in faces-config.xml
            }
        } catch (AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage("Not authorized to edit certificate profile.");
        }
        return "";
    }

    private final void applyExpirationRestrictionForValidityWithFixedDate(final CertificateProfile profile) {
        final String encodedValidty = profile.getEncodedValidity();
        if (profile.getUseExpirationRestrictionForWeekdays()) {
            Date endDate = null;
            try {
                endDate = ValidityDate.parseAsIso8601( encodedValidty);
            } catch(ParseException e) {
                // NOOP
            }
            if (null != endDate) { // for fixed end dates.
                log.info("Applying expiration restrictions for weekdays with fixed end date: " + encodedValidty + " days " + Arrays.toString(profile.getExpirationRestrictionWeekdays()));
                try {
                    final Date appliedDate = ValidityDate.applyExpirationRestrictionForWeekdays(endDate,
                        profile.getExpirationRestrictionWeekdays(), profile.getExpirationRestrictionForWeekdaysExpireBefore());
                    if (!appliedDate.equals(endDate)) {
                        final String newEncodedValidity = ValidityDate.formatAsISO8601ServerTZ(appliedDate.getTime(), ValidityDate.TIMEZONE_SERVER);
                        profile.setEncodedValidity(newEncodedValidity);
                        addInfoMessage("CERT_EXPIRATION_RESTRICTION_FIXED_DATE_CHANGED", encodedValidty, newEncodedValidity);
                    }
                }
                catch(Exception e) {
                    log.warn("Expiration restriction of certificate profile could not be applied!");
                }
            }
        }
    }

    public boolean isTypeCA() {
        return isTypeRootCa() || isTypeSubCa();
    }

    public boolean isTypeEndEntityAvailable() { return true; }
    public boolean isTypeSubCaAvailable() { return isAuthorizedTo(StandardRules.ROLE_ROOT.resource()); }
    public boolean isTypeRootCaAvailable() { return isAuthorizedTo(StandardRules.ROLE_ROOT.resource()); }
    public boolean isTypeHardTokenAvailable() { return isAuthorizedTo(StandardRules.ROLE_ROOT.resource()) && getEjbcaWebBean().getGlobalConfiguration().getIssueHardwareTokens(); }

    public boolean isTypeEndEntity() { return getCertificateProfile().getType() == CertificateConstants.CERTTYPE_ENDENTITY; }
    public boolean isTypeSubCa() { return getCertificateProfile().getType()==CertificateConstants.CERTTYPE_SUBCA; }
    public boolean isTypeRootCa() { return getCertificateProfile().getType()==CertificateConstants.CERTTYPE_ROOTCA; }
    public boolean isTypeHardToken() { return getCertificateProfile().getType()==CertificateConstants.CERTTYPE_HARDTOKEN; }

    public void setTypeEndEntity() { getCertificateProfile().setType(CertificateConstants.CERTTYPE_ENDENTITY); }
    public void setTypeSubCa() { getCertificateProfile().setType(CertificateConstants.CERTTYPE_SUBCA); }
    public void setTypeRootCa() { getCertificateProfile().setType(CertificateConstants.CERTTYPE_ROOTCA); }
    public void setTypeHardToken() { getCertificateProfile().setType(CertificateConstants.CERTTYPE_HARDTOKEN); }

    public boolean isUniqueCertificateSerialNumberIndex() {
        return getEjbcaWebBean().getEjb().getCertificateCreateSession().isUniqueCertificateSerialNumberIndex();
    }

    public List<SelectItem/*<String,String>*/> getAvailableKeyAlgorithmsAvailable() {
        final List<SelectItem> ret = new ArrayList<>();
        for (final String current : AlgorithmTools.getAvailableKeyAlgorithms()) {
            ret.add(new SelectItem(current));
        }
        return ret;
    }

    public List<SelectItem/*<String,String>*/> getAvailableEcCurvesAvailable() {
        final List<SelectItem> ret = new ArrayList<>();
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
        final List<SelectItem> ret = new ArrayList<>();
        for (final int current : CertificateProfile.DEFAULTBITLENGTHS) {
            ret.add(new SelectItem(current, current + " " + getEjbcaWebBean().getText("BITS")));
        }
        return ret;
    }

    public List<SelectItem> getAvailableApprovalProfiles() {
        List<SelectItem> ret = new ArrayList<>();
        ApprovalProfileSession approvalProfileSession = getEjbcaWebBean().getEjb().getApprovalProfileSession();
        Map<Integer, String> approvalProfiles = approvalProfileSession.getApprovalProfileIdToNameMap();
        Set<Entry<Integer, String>> entries = approvalProfiles.entrySet();
        for(Entry<Integer, String> entry : entries) {
            ret.add(new SelectItem(entry.getKey(), entry.getValue()));
        }

        // Sort list by name
        Collections.sort(ret, new Comparator<SelectItem>() {
            @Override
            public int compare(final SelectItem a, final SelectItem b) {
                return a.getLabel().compareToIgnoreCase(b.getLabel());
            }
        });
        ret.add(0, new SelectItem(-1, EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("NONE")));
        return ret;
    }

    public List<SelectItem/*<String,String*/> getSignatureAlgorithmAvailable() {
        final List<SelectItem> ret = new ArrayList<>();
        // null becomes ""-value.
        ret.add(new SelectItem(null, getEjbcaWebBean().getText("INHERITFROMCA")));
        for (final String current : AlgorithmConstants.AVAILABLE_SIGALGS) {
            ret.add(new SelectItem(current, current));
        }
        return ret;
    }
    public String getSignatureAlgorithm() {
        return getCertificateProfile().getSignatureAlgorithm();
    }
    public void setSignatureAlgorithm(final String signatureAlgorithm) {
        // Inherit signature algorithm from issuing CA is signaled by null, but is rendered as "".
        final String sigAlg = StringUtils.isBlank(signatureAlgorithm) ? null : signatureAlgorithm;
        getCertificateProfile().setSignatureAlgorithm(sigAlg);
    }

    /**
     * Gets the validity.
     * @return the validity as ISO8601 date or relative time.
     * @See {@link org.cesecore.util.ValidityDate ValidityDate}
     */
    public String getValidity() {
        return getCertificateProfile().getEncodedValidity();
    }

    /**
     * Sets the validity .
     * @param value the validity as ISO8601 date or relative time.
     * @See {@link org.cesecore.util.ValidityDate ValidityDate}
     */
    public void setValidity(final String value) {
        String valueToSet = value;
        if (null != value) {
            try {
                // parse fixed date ISO8601
                ValidityDate.parseAsIso8601(value);
            } catch (ParseException e) {
                // parse simple time and get canonical string
                valueToSet = SimpleTime.toString( SimpleTime.getSecondsFormat().parseMillis(value), SimpleTime.TYPE_DAYS);
            }
            getCertificateProfile().setEncodedValidity(valueToSet);
        }
    }

    /**
     * Gets the validity offset.
     * @return the offset as relative time.
     * @See {@link org.cesecore.util.SimpleTime SimpleTime}
     */
    public String getCertificateValidityOffset() {
        return certificateProfile.getCertificateValidityOffset();
    }

    /**
     * Sets the validity offset.
     * @param value the offset as relative time.
     * @See {@link org.cesecore.util.SimpleTime SimpleTime}
     */
    public void setCertificateValidityOffset(String value) {
        certificateProfile.setCertificateValidityOffset(SimpleTime.toString( SimpleTime.getSecondsFormat().parseMillis(value), SimpleTime.TYPE_MINUTES));
    }

    public void toggleUseCertificateValidityOffset() throws IOException {
        getCertificateProfile().setUseCertificateValidityOffset(!getCertificateProfile().getUseCertificateValidityOffset());
        redirectToComponent("checkusecertificatevalidityoffsetgroup");
    }

    public void toggleUseExpirationRestrictionForWeekdays() throws IOException {
        getCertificateProfile().setUseExpirationRestrictionForWeekdays(!getCertificateProfile().getUseExpirationRestrictionForWeekdays());
        redirectToComponent("checkuseexpirationtrestrictionforweekdaysgroup");
    }

    public boolean isExpirationRestrictionMonday() { return getCertificateProfile().getExpirationRestrictionWeekday(Calendar.MONDAY); }
    public boolean isExpirationRestrictionTuesday() { return getCertificateProfile().getExpirationRestrictionWeekday(Calendar.TUESDAY); }
    public boolean isExpirationRestrictionWednesday() { return getCertificateProfile().getExpirationRestrictionWeekday(Calendar.WEDNESDAY); }
    public boolean isExpirationRestrictionThursday() { return getCertificateProfile().getExpirationRestrictionWeekday(Calendar.THURSDAY); }
    public boolean isExpirationRestrictionFriday() { return getCertificateProfile().getExpirationRestrictionWeekday(Calendar.FRIDAY); }
    public boolean isExpirationRestrictionSaturday() { return getCertificateProfile().getExpirationRestrictionWeekday(Calendar.SATURDAY); }
    public boolean isExpirationRestrictionSunday() { return getCertificateProfile().getExpirationRestrictionWeekday(Calendar.SUNDAY); }
    public void setExpirationRestrictionMonday(final boolean enabled) { getCertificateProfile().setExpirationRestrictionWeekday(Calendar.MONDAY, enabled); }
    public void setExpirationRestrictionTuesday(final boolean enabled) { getCertificateProfile().setExpirationRestrictionWeekday(Calendar.TUESDAY, enabled); }
    public void setExpirationRestrictionWednesday(final boolean enabled) { getCertificateProfile().setExpirationRestrictionWeekday(Calendar.WEDNESDAY, enabled); }
    public void setExpirationRestrictionThursday(final boolean enabled) { getCertificateProfile().setExpirationRestrictionWeekday(Calendar.THURSDAY, enabled); }
    public void setExpirationRestrictionFriday(final boolean enabled) { getCertificateProfile().setExpirationRestrictionWeekday(Calendar.FRIDAY, enabled); }
    public void setExpirationRestrictionSaturday(final boolean enabled) { getCertificateProfile().setExpirationRestrictionWeekday(Calendar.SATURDAY, enabled); }
    public void setExpirationRestrictionSunday(final boolean enabled) { getCertificateProfile().setExpirationRestrictionWeekday(Calendar.SUNDAY, enabled); }

    public List<SelectItem> getExpirationRestrictionWeekdaysAvailable() {
        final List<SelectItem> result = new ArrayList<>();
        result.add(new SelectItem(Boolean.TRUE, getEjbcaWebBean().getText("CERT_EXPIRATION_RESTRICTION_BEFORE")));
        result.add(new SelectItem(Boolean.FALSE, getEjbcaWebBean().getText("CERT_EXPIRATION_RESTRICTION_AFTER")));
        return result;
    }

    public void toggleUseBasicConstraints() throws IOException {
        getCertificateProfile().setUseBasicConstraints(!getCertificateProfile().getUseBasicConstraints());
        redirectToComponent("header_x509v3extensions");
    }

    public void toggleUsePathLengthConstraint() throws IOException {
        getCertificateProfile().setUsePathLengthConstraint(!getCertificateProfile().getUsePathLengthConstraint());
        if (getCertificateProfile().getUsePathLengthConstraint()) {
            getCertificateProfile().setPathLengthConstraint(1);
        } else {
            getCertificateProfile().setPathLengthConstraint(0);
        }
        redirectToComponent("header_x509v3extensions");
    }

    public void toggleUseKeyUsage() throws IOException {
        getCertificateProfile().setUseKeyUsage(!getCertificateProfile().getUseKeyUsage());
        redirectToComponent("header_x509v3extensions_usages");
    }

    public boolean isKeyUsageDigitalSignature() { return getCertificateProfile().getKeyUsage(CertificateConstants.DIGITALSIGNATURE); }
    public boolean isKeyUsageNonRepudiation() { return getCertificateProfile().getKeyUsage(CertificateConstants.NONREPUDIATION); }
    public boolean isKeyUsageKeyEncipherment() { return getCertificateProfile().getKeyUsage(CertificateConstants.KEYENCIPHERMENT); }
    public boolean isKeyUsageDataEncipherment() { return getCertificateProfile().getKeyUsage(CertificateConstants.DATAENCIPHERMENT); }
    public boolean isKeyUsageKeyAgreement() { return getCertificateProfile().getKeyUsage(CertificateConstants.KEYAGREEMENT); }
    public boolean isKeyUsageKeyCertSign() { return getCertificateProfile().getKeyUsage(CertificateConstants.KEYCERTSIGN); }
    public boolean isKeyUsageKeyCrlSign() { return getCertificateProfile().getKeyUsage(CertificateConstants.CRLSIGN); }
    public boolean isKeyUsageEncipherOnly() { return getCertificateProfile().getKeyUsage(CertificateConstants.ENCIPHERONLY); }
    public boolean isKeyUsageDecipherOnly() { return getCertificateProfile().getKeyUsage(CertificateConstants.DECIPHERONLY); }
    public void setKeyUsageDigitalSignature(final boolean enabled) { getCertificateProfile().setKeyUsage(CertificateConstants.DIGITALSIGNATURE, enabled); }
    public void setKeyUsageNonRepudiation(final boolean enabled) { getCertificateProfile().setKeyUsage(CertificateConstants.NONREPUDIATION, enabled); }
    public void setKeyUsageKeyEncipherment(final boolean enabled) { getCertificateProfile().setKeyUsage(CertificateConstants.KEYENCIPHERMENT, enabled); }
    public void setKeyUsageDataEncipherment(final boolean enabled) { getCertificateProfile().setKeyUsage(CertificateConstants.DATAENCIPHERMENT, enabled); }
    public void setKeyUsageKeyAgreement(final boolean enabled) { getCertificateProfile().setKeyUsage(CertificateConstants.KEYAGREEMENT, enabled); }
    public void setKeyUsageKeyCertSign(final boolean enabled) { getCertificateProfile().setKeyUsage(CertificateConstants.KEYCERTSIGN, enabled); }
    public void setKeyUsageKeyCrlSign(final boolean enabled) { getCertificateProfile().setKeyUsage(CertificateConstants.CRLSIGN, enabled); }
    public void setKeyUsageEncipherOnly(final boolean enabled) { getCertificateProfile().setKeyUsage(CertificateConstants.ENCIPHERONLY, enabled); }
    public void setKeyUsageDecipherOnly(final boolean enabled) { getCertificateProfile().setKeyUsage(CertificateConstants.DECIPHERONLY, enabled); }
    public boolean isNonOverridableExtensionOIDs() { return !getCertificateProfile().getNonOverridableExtensionOIDs().isEmpty(); }
    /** Toggles which Set is populated, the one for overridable, or the one for non-overridable
     * true to populate non-overridable extension list, false for overridable
     */
    public void toggleAllowExtensionOverride() throws IOException {
        getCertificateProfile().setAllowExtensionOverride(!getCertificateProfile().getAllowExtensionOverride());
        redirectToComponent("checkallowextensionoverridegroup");
    }
    public void setNonOverridableExtensionOIDs(final boolean enabled) {
        final CertificateProfile profile = getCertificateProfile();
        Set<String> extensions = getOverridableExtensionOIDs();
        if (enabled) {
            profile.setNonOverridableExtensionOIDs(extensions);
            profile.setOverridableExtensionOIDs(new LinkedHashSet<String>());
        } else {
            profile.setOverridableExtensionOIDs(extensions);
            profile.setNonOverridableExtensionOIDs(new LinkedHashSet<String>());
        }
    }
    public Set<String> getOverridableExtensionOIDs() {
        final CertificateProfile profile = getCertificateProfile();
        if (isNonOverridableExtensionOIDs()) {
            return profile.getNonOverridableExtensionOIDs();
        } else {
            return profile.getOverridableExtensionOIDs();
        }
    }
    public void setOverridableExtensionOIDs(Set<String> oids) {
        final CertificateProfile profile = getCertificateProfile();
        if (isNonOverridableExtensionOIDs()) {
            profile.setNonOverridableExtensionOIDs(oids);
        } else {
            profile.setOverridableExtensionOIDs(oids);
        }

    }

    public void toggleUseExtendedKeyUsage() throws IOException {
        getCertificateProfile().setUseExtendedKeyUsage(!getCertificateProfile().getUseExtendedKeyUsage());
        redirectToComponent("header_x509v3extensions_usages");
    }

    public List<SelectItem> getExtendedKeyUsageOidsAvailable() {
        final List<SelectItem> ret = new ArrayList<>();
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

    public void toggleUseSubjectAlternativeName() throws IOException {
        getCertificateProfile().setUseSubjectAlternativeName(!getCertificateProfile().getUseSubjectAlternativeName());
        // Default store to enabled when extension is first enabled and vice versa
        getCertificateProfile().setStoreSubjectAlternativeName(getCertificateProfile().getUseSubjectAlternativeName());
        redirectToComponent("header_x509v3extensions_names");
    }

    public void toggleUseIssuerAlternativeName() throws IOException {
        getCertificateProfile().setUseIssuerAlternativeName(!getCertificateProfile().getUseIssuerAlternativeName());
        redirectToComponent("header_x509v3extensions_names");
    }

    public void toggleUseNameConstraints() throws IOException {
        getCertificateProfile().setUseNameConstraints(!getCertificateProfile().getUseNameConstraints());
        redirectToComponent("header_x509v3extensions_names");
    }

    public void toggleUseCRLDistributionPoint() throws IOException {
        getCertificateProfile().setUseCRLDistributionPoint(!getCertificateProfile().getUseCRLDistributionPoint());
        redirectToComponent("header_x509v3extensions_valdata");
    }

    public void toggleUseDefaultCRLDistributionPoint() throws IOException {
        getCertificateProfile().setUseDefaultCRLDistributionPoint(!getCertificateProfile().getUseDefaultCRLDistributionPoint());
        redirectToComponent("header_x509v3extensions_valdata");
    }

    public void toggleUseCADefinedFreshestCRL() throws IOException {
        getCertificateProfile().setUseCADefinedFreshestCRL(!getCertificateProfile().getUseCADefinedFreshestCRL());
        redirectToComponent("header_x509v3extensions_valdata");
    }

    public void toggleUseFreshestCRL() throws IOException {
        getCertificateProfile().setUseFreshestCRL(!getCertificateProfile().getUseFreshestCRL());
        redirectToComponent("header_x509v3extensions_valdata");
    }

    public void toggleUseCertificatePolicies() throws IOException {
        getCertificateProfile().setUseCertificatePolicies(!getCertificateProfile().getUseCertificatePolicies());
        redirectToComponent("header_x509v3extensions_usages");
    }

    public ListDataModel<CertificatePolicy> getCertificatePolicies() {
        if (certificatePoliciesModel==null) {
            final List<CertificatePolicy> certificatePolicies = getCertificateProfile().getCertificatePolicies();
            if (certificatePolicies!=null) {
                certificatePoliciesModel = new ListDataModel<>(certificatePolicies);
            } else {
                certificatePoliciesModel = new ListDataModel<>();
            }
        }
        return certificatePoliciesModel;
    }

    public boolean isCurrentCertificatePolicyQualifierIdNone() {
        return "".equals(getCertificatePolicies().getRowData().getQualifierId());
    }
    public boolean isCurrentCertificatePolicyQualifierIdCpsUri() {
        return CertificatePolicy.id_qt_cps.equals(getCertificatePolicies().getRowData().getQualifierId());
    }
    public boolean isCurrentCertificatePolicyQualifierIdUserNotice() {
        return CertificatePolicy.id_qt_unotice.equals(getCertificatePolicies().getRowData().getQualifierId());
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

    public String addCertificatePolicy() throws IOException {
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

    public String deleteCertificatePolicy() throws IOException {
        final CertificatePolicy certificatePolicy = getCertificatePolicies().getRowData();
        getCertificateProfile().removeCertificatePolicy(certificatePolicy);
        newCertificatePolicy = certificatePolicy;
        certificatePoliciesModel = null;
        redirectToComponent("header_x509v3extensions_usages");
        return "";
    }

    public ListDataModel<String> getCaIssuers() {
        if (caIssuersModel==null) {
            final List<String> caIssuers = getCertificateProfile().getCaIssuers();
            if (caIssuers!=null) {
                caIssuersModel = new ListDataModel<>(caIssuers);
            } else {
                caIssuersModel = new ListDataModel<>();
            }
        }
        return caIssuersModel;
    }

    public void toggleUseAuthorityInformationAccess() throws IOException {
        getCertificateProfile().setUseAuthorityInformationAccess(!getCertificateProfile().getUseAuthorityInformationAccess());
        redirectToComponent("header_x509v3extensions_valdata");
    }

    public void toggleUseDefaultCAIssuer() throws IOException {
        getCertificateProfile().setUseDefaultCAIssuer(!getCertificateProfile().getUseDefaultCAIssuer());
        redirectToComponent("header_x509v3extensions_valdata");
    }

    public void toggleUseDefaultOCSPServiceLocator() throws IOException {
        getCertificateProfile().setUseDefaultOCSPServiceLocator(!getCertificateProfile().getUseDefaultOCSPServiceLocator());
        redirectToComponent("header_x509v3extensions_valdata");
    }

    public String getNewCaIssuer() { return newCaIssuer; }
    public void setNewCaIssuer(String newCaIssuer) { this.newCaIssuer = newCaIssuer.trim(); }

    public String addCaIssuer() throws IOException {
        getCertificateProfile().addCaIssuer(newCaIssuer);
        newCaIssuer = "";
        caIssuersModel = null;
        redirectToComponent("header_x509v3extensions_valdata");
        return "";
    }

    public String deleteCaIssuer() throws IOException {
        final String caIssuer = getCaIssuers().getRowData();
        getCertificateProfile().removeCaIssuer(caIssuer);
        newCaIssuer = caIssuer;
        caIssuersModel = null;
        redirectToComponent("header_x509v3extensions_valdata");
        return "";
    }

    public void toggleUsePrivateKeyUsagePeriodNotBefore() throws IOException {
        getCertificateProfile().setUsePrivateKeyUsagePeriodNotBefore(!getCertificateProfile().isUsePrivateKeyUsagePeriodNotBefore());
        redirectToComponent("header_x509v3extensions_valdata");
    }

    public String getPrivateKeyUsagePeriodStartOffset() {
        final CertificateProfile certificateProfile = getCertificateProfile();
        if (certificateProfile.isUsePrivateKeyUsagePeriodNotBefore()) {
            return SimpleTime.toString(certificateProfile.getPrivateKeyUsagePeriodStartOffset() * 1000, SimpleTime.TYPE_DAYS);
        } else {
            return "";
        }
    }
    public void setPrivateKeyUsagePeriodStartOffset(String value) {
        if (null != value) {
            final long millis = SimpleTime.getSecondsFormat().parseMillis(value);
            if (millis >= 0) {
                getCertificateProfile().setPrivateKeyUsagePeriodStartOffset(millis / 1000);
            }
        }
    }

    public void toggleUsePrivateKeyUsagePeriodNotAfter() throws IOException {
        getCertificateProfile().setUsePrivateKeyUsagePeriodNotAfter(!getCertificateProfile().isUsePrivateKeyUsagePeriodNotAfter());
        redirectToComponent("header_x509v3extensions_valdata");
    }

    public String getPrivateKeyUsagePeriodLength() {
        final CertificateProfile certificateProfile = getCertificateProfile();
        if (certificateProfile.isUsePrivateKeyUsagePeriodNotAfter()) {
            return SimpleTime.toString(certificateProfile.getPrivateKeyUsagePeriodLength() * 1000, SimpleTime.TYPE_DAYS);
        } else {
            return "";
        }
    }
    public void setPrivateKeyUsagePeriodLength(String value) {
        if (null != value) {
            final long millis = SimpleTime.getSecondsFormat().parseMillis(value);
            if (millis > 0) {
                getCertificateProfile().setPrivateKeyUsagePeriodLength(millis / 1000);
            }
        }
    }

    public void toggleUseQCStatement() throws IOException {
        getCertificateProfile().setUseQCStatement(!getCertificateProfile().getUseQCStatement());
        redirectToComponent("header_qcStatements");
    }

    private List<PKIDisclosureStatement> getQCEtsiPdsList() {
        List<PKIDisclosureStatement> pdsList = getCertificateProfile().getQCEtsiPds();
        if (pdsList == null) {
            pdsList = new ArrayList<>();
            // Add a blank line, so the user can fill it in quickly (and blank lines are
            // automatically deleted when saving, so this will never end up in certificates)
            pdsList.add(new PKIDisclosureStatement("", "en"));
        }
        return pdsList;
    }

    public ListDataModel<PKIDisclosureStatement> getQCEtsiPds() {
        if (pdsListModel == null) {
            final List<PKIDisclosureStatement> pdsList = getQCEtsiPdsList();
            pdsListModel = new ListDataModel<>(pdsList);
            // Listener that sends back changes into the cert profile
            pdsListModel.addDataModelListener(new DataModelListener() {
                @Override
                public void rowSelected(final DataModelEvent event) {
                    final PKIDisclosureStatement pds = (PKIDisclosureStatement) event.getRowData();
                    final int index = event.getRowIndex();
                    if (index != -1 && index < pdsList.size()) {
                        pdsList.set(index, pds);
                        getCertificateProfile().setQCEtsiPds(pdsList);
                    }
                }
            });
        }
        return pdsListModel;
    }

    /** Called when the user presses the "Add" button to add a new PDS URL field */
    public String addQCEtsiPds() throws IOException {
        final List<PKIDisclosureStatement> pdsList = getQCEtsiPdsList();
        pdsList.add(new PKIDisclosureStatement("", "en")); // start with blank values, that the user can fill in
        getCertificateProfile().setQCEtsiPds(pdsList);
        pdsListModel = null;
        redirectToComponent("header_qcStatements");
        return "";
    }

    public String deleteQCEtsiPds() throws IOException {
        final List<PKIDisclosureStatement> pdsList = getQCEtsiPdsList();
        int index = getQCEtsiPds().getRowIndex();
        pdsList.remove(index);
        getCertificateProfile().setQCEtsiPds(pdsList);
        pdsListModel = null;
        redirectToComponent("header_qcStatements");
        return "";
    }

    /** Returns true if there's a PDS URL filled in that can be deleted */
    public boolean isAbleToDeletePDSUrl() {
        final List<PKIDisclosureStatement> pdsList = getQCEtsiPdsList();
        if (pdsList.size() == 1) {
            // Note that when we reach zero items, there will be a blank placeholder where the user can fill in an URL.
            if (pdsList.get(0) == null || pdsList.get(0).getUrl() == null) {
            	// can't delete the placeholder itself
                return false;
            }
            return !pdsList.get(0).getUrl().isEmpty(); // can't delete the placeholder itself
        } else {
            return true;
        }
    }

    public void toggleUseQCEtsiValueLimit() throws IOException {
        getCertificateProfile().setUseQCEtsiValueLimit(!getCertificateProfile().getUseQCEtsiValueLimit());
        redirectToComponent("header_qcStatements");
    }

    public void toggleUseQCEtsiRetentionPeriod() throws IOException {
        getCertificateProfile().setUseQCEtsiRetentionPeriod(!getCertificateProfile().getUseQCEtsiRetentionPeriod());
        redirectToComponent("header_qcStatements");
    }

    public void toggleUseQCCustomString() throws IOException {
        getCertificateProfile().setUseQCCustomString(!getCertificateProfile().getUseQCCustomString());
        redirectToComponent("header_qcStatements");
    }

    public void toggleUseCertificateTransparencyInCerts() throws IOException {
        getCertificateProfile().setUseCertificateTransparencyInCerts(!getCertificateProfile().isUseCertificateTransparencyInCerts());
        redirectToComponent("header_certificatetransparency");
    }

    public void toggleUseCertificateTransparencyInOCSP() throws IOException {
        getCertificateProfile().setUseCertificateTransparencyInOCSP(!getCertificateProfile().isUseCertificateTransparencyInOCSP());
        redirectToComponent("header_certificatetransparency");
    }

    public void toggleUseCertificateTransparencyInPublishers() throws IOException {
        getCertificateProfile().setUseCertificateTransparencyInPublishers(!getCertificateProfile().isUseCertificateTransparencyInPublishers());
        redirectToComponent("header_certificatetransparency");
    }
    
    public void toggleNumberOfSctBy() throws IOException {
        getCertificateProfile().setNumberOfSctByCustom(!getCertificateProfile().isNumberOfSctByCustom());
        getCertificateProfile().setNumberOfSctByValidity(!getCertificateProfile().isNumberOfSctByValidity());
        redirectToComponent("header_certificatetransparency");
    }
        
    public void toggleMaxNumberOfSctBy() throws IOException {
        getCertificateProfile().setMaxNumberOfSctByCustom(!getCertificateProfile().isMaxNumberOfSctByCustom());
        getCertificateProfile().setMaxNumberOfSctByValidity(!getCertificateProfile().isMaxNumberOfSctByValidity());
        redirectToComponent("header_certificatetransparency");
    }
    
    public boolean isCtAvailable() { return CertificateTransparencyFactory.isCTAvailable(); }
    public boolean isCtEnabled() { return getCertificateProfile().isCtEnabled(); }

    public boolean isCtInCertsOrOCSPEnabled() {
        return getCertificateProfile().isUseCertificateTransparencyInCerts() ||
            getCertificateProfile().isUseCertificateTransparencyInOCSP();
    }

    public boolean isCtInOCSPOrPublishersEnabled() {
        return getCertificateProfile().isUseCertificateTransparencyInOCSP() ||
            getCertificateProfile().isUseCertificateTransparencyInPublishers();
    }
    
    public boolean isNumberOfSctsByValidity() {
        return getCertificateProfile().isNumberOfSctByValidity();
    }

    public boolean isNumberOfSctsByCustom() {
        return getCertificateProfile().isNumberOfSctByCustom();
    }
    
    public boolean isMaxNumberOfSctsByValidity() {
        return getCertificateProfile().isMaxNumberOfSctByValidity();
    }
    
    public boolean isMaxNumberOfSctsByCustom() {
        return getCertificateProfile().isMaxNumberOfSctByCustom();
    }
    
    public List<SelectItem> getDistinctCtLabelsAvailable() {
        // Since labels are members of CTlogs (and not the other way around due to legacy design) we select distinct labels this way
        final List<SelectItem> ret = new ArrayList<>();
        final Map<String, String> distinctLables = new HashMap<>();
        for (final CTLogInfo current : getEjbcaWebBean().getGlobalConfiguration().getCTLogs().values()) {
            if (!distinctLables.containsKey(current.getLabel())) {
                ret.add(new SelectItem(current.getLabel()));
                distinctLables.put(current.getLabel(), current.getLabel());
            }
        }
        Collections.sort(ret, new Comparator<SelectItem>() {
            @Override
            public int compare(SelectItem label1, SelectItem label2) {
                return label1.getLabel().compareToIgnoreCase(label2.getLabel());
            }
        });
        return ret;
    }
    
    /** @returns the size of the select box */ 
    public int getDistinctCTLabelsAvailableSize() { return Math.max(3, Math.min(6, getDistinctCtLabelsAvailable().size())); }

    public List<String> getEnabledCtLabels() {
        return new ArrayList<>(getCertificateProfile().getEnabledCtLabels());
    }
    
    public void setEnabledCtLabels(final List<String> selectedLabels) {
        getCertificateProfile().setEnabledCTLabels(new LinkedHashSet<>(selectedLabels));
    }
    
    public void toggleUseMicrosoftTemplate() throws IOException {
        getCertificateProfile().setUseMicrosoftTemplate(!getCertificateProfile().getUseMicrosoftTemplate());
        redirectToComponent("otherextensions");
    }

    public List<SelectItem/*<String,String*/> getMicrosoftTemplateAvailable() {
        final List<SelectItem> ret = new ArrayList<>();
        for (final String current : CertificateProfile.AVAILABLE_MSTEMPLATES) {
            ret.add(new SelectItem(current, current));
        }
        return ret;
    }

    public void toggleUseDocumentTypeList() throws IOException {
        getCertificateProfile().setUseDocumentTypeList(!getCertificateProfile().getUseDocumentTypeList());
        redirectToComponent("cvc_epassport");
    }

    public String getDocumentTypeListNew() { return documentTypeListNew; }
    public void setDocumentTypeListNew(String documentTypeListNew) { this.documentTypeListNew = documentTypeListNew.trim(); }

    public void documentTypeListRemove() throws IOException {
        final String current = getDocumentTypeList().getRowData();
        ArrayList<String> documentTypeListValue = getCertificateProfile().getDocumentTypeList();
        documentTypeListValue.remove(current);
        getCertificateProfile().setDocumentTypeList(documentTypeListValue);
        documentTypeListNew = current;
        documentTypeList = null;    // Trigger reload of model
        redirectToComponent("cvc_epassport");
    }
    public void documentTypeListAdd() throws IOException {
        if (documentTypeListNew.length()>0) {
            ArrayList<String> documentTypeListValue = getCertificateProfile().getDocumentTypeList();
            documentTypeListValue.add(documentTypeListNew);
            getCertificateProfile().setDocumentTypeList(documentTypeListValue);
            documentTypeListNew = "";
            documentTypeList = null;    // Trigger reload of model
        }
        redirectToComponent("cvc_epassport");
    }
    public ListDataModel<String> getDocumentTypeList() {
        if (documentTypeList==null) {
            documentTypeList = new ListDataModel<>(getCertificateProfile().getDocumentTypeList());
        }
        return documentTypeList;
    }

    public boolean isCvcAvailable() {
        return CvcCA.getImplementationClasses().iterator().hasNext();
    }

    public boolean isCvcTerminalTypeIs() { return getCertificateProfile().isCvcTerminalTypeIs(); }
    public boolean isCvcTerminalTypeAt() { return getCertificateProfile().isCvcTerminalTypeAt(); }
    public boolean isCvcTerminalTypeSt() { return getCertificateProfile().isCvcTerminalTypeSt(); }

    public void setCvcTerminalTypeIs() throws IOException {
        getCertificateProfile().setCVCTerminalType(CertificateProfile.CVC_TERMTYPE_IS);
        getCertificateProfile().setCVCAccessRights(CertificateProfile.CVC_ACCESS_NONE);
        getCertificateProfile().setCVCLongAccessRights(null);
        redirectToComponent("cvc_epassport");
    }
    public void setCvcTerminalTypeAt() throws IOException {
        getCertificateProfile().setCVCTerminalType(CertificateProfile.CVC_TERMTYPE_AT);
        getCertificateProfile().setCVCAccessRights(CertificateProfile.CVC_ACCESS_NONE);
        getCertificateProfile().setCVCLongAccessRights(null);
        redirectToComponent("cvc_epassport");
    }
    public void setCvcTerminalTypeSt() throws IOException {
        getCertificateProfile().setCVCTerminalType(CertificateProfile.CVC_TERMTYPE_ST);
        getCertificateProfile().setCVCAccessRights(CertificateProfile.CVC_ACCESS_NONE);
        getCertificateProfile().setCVCLongAccessRights(null);
        redirectToComponent("cvc_epassport");
    }

    public List<SelectItem/*<Integer,String*/> getCvcSignTermDVTypeAvailable() {
        final List<SelectItem> ret = new ArrayList<>();
        ret.add(new SelectItem(CertificateProfile.CVC_SIGNTERM_DV_AB, getEjbcaWebBean().getText("CVCACCREDITATIONBODY")));
        ret.add(new SelectItem(CertificateProfile.CVC_SIGNTERM_DV_CSP, getEjbcaWebBean().getText("CVCCERTIFICATIONSERVICEPROVIDER")));
        return ret;
    }

    // Translation between UI and CertificateProfile's format
    public List<Integer> getCvcLongAccessRights() {
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
        final List<Integer> ret = new ArrayList<>();
        for (int i=0; i<=37; i++) {
            if (arlflags.getFlag(i)) {
                ret.add(Integer.valueOf(i));
            }
        }
        return ret;
    }
    // Translation between UI and CertificateProfile's format
    public void setCvcLongAccessRights(List<Integer> in) {
        final AccessRightAuthTerm arlflags = new AccessRightAuthTerm(CertificateProfile.DEFAULT_CVC_RIGHTS_AT);
        for (final Integer current : in) {
            arlflags.setFlag(current, true);
        }
        getCertificateProfile().setCVCAccessRights(CertificateProfile.CVC_ACCESS_NONE);
        getCertificateProfile().setCVCLongAccessRights(arlflags.getEncoded());
    }

    public boolean isCvcAccessRightDg3() { return isCvcAccessRight(CertificateProfile.CVC_ACCESS_DG3); }
    public boolean isCvcAccessRightDg4() { return isCvcAccessRight(CertificateProfile.CVC_ACCESS_DG4); }
    public boolean isCvcAccessRightSign() { return isCvcAccessRight(CertificateProfile.CVC_ACCESS_SIGN); }
    public boolean isCvcAccessRightQualSign() { return isCvcAccessRight(CertificateProfile.CVC_ACCESS_QUALSIGN); }
    public void setCvcAccessRightDg3(final boolean enabled) { setCvcAccessRight(CertificateProfile.CVC_ACCESS_DG3, enabled); }
    public void setCvcAccessRightDg4(final boolean enabled) { setCvcAccessRight(CertificateProfile.CVC_ACCESS_DG4, enabled); }
    public void setCvcAccessRightSign(final boolean enabled) { setCvcAccessRight(CertificateProfile.CVC_ACCESS_SIGN, enabled); }
    public void setCvcAccessRightQualSign(final boolean enabled) { setCvcAccessRight(CertificateProfile.CVC_ACCESS_QUALSIGN, enabled); }

    private boolean isCvcAccessRight(final int accessRight) {
        return (getCertificateProfile().getCVCAccessRights() & accessRight) != 0;
    }
    private void setCvcAccessRight(final int accessRight, final boolean enabled) {
        if (enabled) {
            getCertificateProfile().setCVCAccessRights(getCertificateProfile().getCVCAccessRights() | accessRight);
        } else {
            getCertificateProfile().setCVCAccessRights(getCertificateProfile().getCVCAccessRights() & ~accessRight);
        }
    }

    public List<SelectItem/*<Integer,String*/> getCvcAccessRightsAtAvailable() {
        final List<SelectItem> ret = new ArrayList<>();
        ret.add(new SelectItem(String.valueOf(0), getEjbcaWebBean().getText("CVCACCESSAGEVERIFICATION")));
        ret.add(new SelectItem(String.valueOf(1), getEjbcaWebBean().getText("CVCACCESSCOMMUNITYIDVERIFICATION")));
        ret.add(new SelectItem(String.valueOf(2), getEjbcaWebBean().getText("CVCACCESSRESTRICTEDIDENTIFICATION")));
        ret.add(new SelectItem(String.valueOf(3), getEjbcaWebBean().getText("CVCACCESSPRIVILEGEDTERMINAL")));
        ret.add(new SelectItem(String.valueOf(4), getEjbcaWebBean().getText("CVCACCESSCANALLOWED")));
        ret.add(new SelectItem(String.valueOf(5), getEjbcaWebBean().getText("CVCACCESSPINMANAGEMENT")));
        ret.add(new SelectItem(String.valueOf(6), getEjbcaWebBean().getText("CVCACCESSINSTALLCERT")));
        ret.add(new SelectItem(String.valueOf(7), getEjbcaWebBean().getText("CVCACCESSINSTALLQUALIFIEDCERT")));
        for (int i=8; i<=28; i++) {
            ret.add(new SelectItem(String.valueOf(i), getEjbcaWebBean().getText("CVCACCESSREADDG", false, i-8+1)));
        }
        ret.add(new SelectItem(String.valueOf(37), getEjbcaWebBean().getText("CVCACCESSWRITEDG", false, 17)));
        ret.add(new SelectItem(String.valueOf(36), getEjbcaWebBean().getText("CVCACCESSWRITEDG", false, 18)));
        ret.add(new SelectItem(String.valueOf(35), getEjbcaWebBean().getText("CVCACCESSWRITEDG", false, 19)));
        ret.add(new SelectItem(String.valueOf(34), getEjbcaWebBean().getText("CVCACCESSWRITEDG", false, 20)));
        ret.add(new SelectItem(String.valueOf(33), getEjbcaWebBean().getText("CVCACCESSWRITEDG", false, 21)));
        return ret;
    }

    public void toggleUseCustomDnOrder() throws IOException {
        getCertificateProfile().setUseCustomDnOrder(!getCertificateProfile().getUseCustomDnOrder());
        redirectToComponent("otherdata");
    }

    public void toggleUseCustomDnOrderLdap() throws IOException {
        getCertificateProfile().setUseCustomDnOrderWithLdap(!getCertificateProfile().getUseCustomDnOrderWithLdap());
        redirectToComponent("otherdata");
    }

    public void toggleUseCNPostfix() throws IOException {
        getCertificateProfile().setUseCNPostfix(!getCertificateProfile().getUseCNPostfix());
        redirectToComponent("otherdata");
    }

    public void toggleUseSubjectDNSubSet() throws IOException {
        getCertificateProfile().setUseSubjectDNSubSet(!getCertificateProfile().getUseSubjectDNSubSet());
        redirectToComponent("otherdata");
    }

    public List<SelectItem/*<Integer,String*/> getSubjectDNSubSetAvailable() {
        final List<SelectItem> ret = new ArrayList<>();
        final List<Integer> useSubjectDNFields = DNFieldExtractor.getUseFields(DNFieldExtractor.TYPE_SUBJECTDN);
        for (int i=0; i<useSubjectDNFields.size(); i++) {
            ret.add(new SelectItem(useSubjectDNFields.get(i), getEjbcaWebBean().getText(DnComponents.getDnLanguageTexts().get(i))));
        }
        return ret;
    }

    public void toggleUseSubjectAltNameSubSet() throws IOException {
        getCertificateProfile().setUseSubjectAltNameSubSet(!getCertificateProfile().getUseSubjectAltNameSubSet());
        redirectToComponent("otherdata");
    }

    public List<SelectItem/*<Integer,String*/> getSubjectAltNameSubSetAvailable() {
        final List<SelectItem> ret = new ArrayList<>();
        final List<Integer> useSubjectANFields = DNFieldExtractor.getUseFields(DNFieldExtractor.TYPE_SUBJECTALTNAME);
        for (int i=0; i<useSubjectANFields.size(); i++) {
            ret.add(new SelectItem(useSubjectANFields.get(i), getEjbcaWebBean().getText(DnComponents.getAltNameLanguageTexts().get(i))));
        }
        return ret;
    }

    public List<SelectItem> getAvailableCertificateExtensionsAvailable() {
        final List<SelectItem> ret = new ArrayList<>();

        AvailableCustomCertificateExtensionsConfiguration cceConfig = getEjbcaWebBean().getAvailableCustomCertExtensionsConfiguration();

        List<Integer> usedExtensions = getCertificateProfile().getUsedCertificateExtensions();
        if (certProfilesBean.getViewOnly()) {
            //If in view mode, only display used values.
            for(int id : usedExtensions) {
                if (!cceConfig.isCustomCertExtensionSupported(id)) {
                    String note = "ID #" + id + " (No longer used. Please unselect this option)";
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
                    String note = "ID #" + id + " (No longer used. Please unselect this option)";
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

    public static class ApprovalRequestItem {
        private final ApprovalRequestType requestType;
        private int approvalProfileId;

        public ApprovalRequestItem(final ApprovalRequestType requestType, final int approvalProfileId) {
            this.requestType = requestType;
            this.approvalProfileId = approvalProfileId;
        }

        public ApprovalRequestType getRequestType() {
            return requestType;
        }

        public int getApprovalProfileId() {
            return approvalProfileId;
        }

        public void setApprovalProfileId(int approvalProfileId) {
            this.approvalProfileId = approvalProfileId;
        }

        public String getDisplayText() {
            return EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(requestType.getLanguageString());
        }

    }

    public List<ApprovalRequestItem> getApprovalRequestItems() {
        if (approvalRequestItems == null) {
            approvalRequestItems = new ArrayList<>();
            Map<ApprovalRequestType, Integer> approvals = certificateProfile.getApprovals();
            for (ApprovalRequestType approvalRequestType : ApprovalRequestType.values()) {
                int approvalProfileId;
                if (approvals.containsKey(approvalRequestType)) {
                    approvalProfileId = approvals.get(approvalRequestType);
                } else {
                    approvalProfileId = -1;
                }
                // In certificate profiles we don't want to display the "CA Service Activation" approval type, 
                // because it is not relevant for certificate profiles But if we have a configuration here, we'll display it
                if (!approvalRequestType.equals(ApprovalRequestType.ACTIVATECA) || approvalProfileId != -1) {
                    approvalRequestItems.add(new ApprovalRequestItem(approvalRequestType, approvalProfileId));                    
                }
            }
        }
        return approvalRequestItems;
    }

    public int getAvailableCertificateExtensionsAvailableSize() {
        return Math.max(1, Math.min(6, getAvailableCertificateExtensionsAvailable().size()));
    }

    public List<SelectItem/*<Integer,String*/> getAvailableCAsAvailable() {
        final List<SelectItem> ret = new ArrayList<>();
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
        final List<SelectItem> ret = new ArrayList<>();
        final Collection<Integer> authorizedPublisherIds = getEjbcaWebBean().getEjb().getCaAdminSession().getAuthorizedPublisherIds(getAdmin());
        final Map<Integer, String> publisherIdToNameMap = getEjbcaWebBean().getEjb().getPublisherSession().getPublisherIdToNameMap();
        for (final Integer publisherId : authorizedPublisherIds) {
            ret.add(new SelectItem(publisherId, publisherIdToNameMap.get(publisherId)));
        }
        Collections.sort(ret, new Comparator<SelectItem>() {
            @Override
            public int compare(SelectItem first, SelectItem second) {
                return first.getLabel().compareToIgnoreCase(second.getLabel());
            }
        });
        return ret;
    }
    public int getPublisherListAvailableSize() { return Math.max(1, Math.min(5, getPublisherListAvailable().size())); };

    /** Redirect the client browser to the relevant section of certificate profile page */
    private void redirectToComponent(final String componentId) throws IOException {
        final ExternalContext ec = FacesContext.getCurrentInstance().getExternalContext();
        ec.redirect(getEjbcaWebBean().getBaseUrl()+getEjbcaWebBean().getGlobalConfiguration().getAdminWebPath()+"ca/editcertificateprofiles/editcertificateprofile.jsf#cpf:"+componentId);
    }

    public String getQcEtsiTypeEsign() {
        return CertificateProfileConstants.QC_ETSI_TYPE_ESIGN;
    }
    public String getQcEtsiTypeEseal() {
        return CertificateProfileConstants.QC_ETSI_TYPE_ESEAL;
    }
    public String getQcEtsiTypeWebauth() {
        return CertificateProfileConstants.QC_ETSI_TYPE_WEBAUTH;
    }
}
