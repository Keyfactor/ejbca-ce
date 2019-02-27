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
package org.ejbca.ra;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.ejbca.core.model.ra.EndEntityInformationFiller;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/** 
 * UI representation of a certificate preview to be confirmed before enrollment.
 * 
 * @version $Id$
 */
public class RaRequestPreview {
    
    //private static final Logger log = Logger.getLogger(RaRequestPreview.class);
    private String issuerDn = "";
    private String subjectDn = "";
    private String publicKeyAlgorithm = "";
    private String subjectAlternativeName = "";
    private String subjectDirectoryAttributes = "";
    private String validity = "";
    private List<String> keyUsages = new ArrayList<>();
    private List<String> extendedKeyUsages = new ArrayList<>();

    private boolean more = false;
    private int styleRowCallCounter = 0;
    

    public RaRequestPreview(){
    }
    
    public final void updateCertificateProfile(CertificateProfile certificateProfile){
        if(certificateProfile == null){
            return;
        }
        validity = certificateProfile.getEncodedValidity();
        keyUsages.clear();
        final boolean[] keyUsageArray = certificateProfile.getKeyUsage();
        for (int i=0; i<keyUsageArray.length; i++) {
            if (keyUsageArray[i]) {
                keyUsages.add(String.valueOf(i));
            }
        }
        extendedKeyUsages.clear();
        final List<String> extendedKeyUsages = certificateProfile.getExtendedKeyUsageOids();
        if (extendedKeyUsages != null) {
            this.extendedKeyUsages.addAll(extendedKeyUsages);
        }
    }
    
    public final void updateCA(CAInfo caInfo){
        if(caInfo == null){
            return;
        }
        issuerDn = caInfo.getSubjectDN();
    }
    
    public final void updateSubjectDn(SubjectDn subjectDn){
        if(subjectDn == null){
            return;
        }
        this.subjectDn = subjectDn.getUpdatedValue();
    }
    
    public final void updateSubjectAlternativeName(SubjectAlternativeName subjectAlternativeName, final EndEntityProfile profile){
        if(subjectAlternativeName == null){
            return;
        }
        if(profile ==null) {
            this.subjectAlternativeName =subjectAlternativeName.getUpdatedValue();
        } else {
            this.subjectAlternativeName = getAddDnsFromCnToAltName(subjectDn, subjectAlternativeName.getUpdatedValue(), profile);
        }
    }

    /**
     * Update subjectAltName with dns fields with value from CN
     * @param subjectDn subjectDn
     * @param altName altName
     * @param profile EEProfile
     * @return altName updated with dns copied from CN
     */
    private String getAddDnsFromCnToAltName(final String subjectDn, String altName, final EndEntityProfile profile) {
        String dnsNameValueFromCn = EndEntityInformationFiller.copyDnsNameValueFromCn(profile, subjectDn);
        if (altName == null) {
            altName = "";
        }
        if (StringUtils.isNotEmpty(altName) && StringUtils.isNotEmpty(dnsNameValueFromCn)) {
            altName += ", ";
        }
        altName += dnsNameValueFromCn;
        return altName;
    }
    
    public final void updateSubjectDirectoryAttributes(SubjectDirectoryAttributes subjectDirectoryAttributes){
        if(subjectDirectoryAttributes == null){
            return;
        }
        this.subjectDirectoryAttributes = subjectDirectoryAttributes.getUpdatedValue();
    }

    /** @return true if more details should be shown */
    public final boolean isMore() {
        return more;
    }

    public final void setMore(boolean more) {
        this.more = more;
        styleRowCallCounter = 0; // Reset
    }

    /** @return true every twice starting with every forth call */
    public final boolean isEven() {
        styleRowCallCounter++;
        return (styleRowCallCounter+1) / 2 % 2 == 0;
    }

    public final String getSubjectDn() {
        return subjectDn;
    }

    /**
     * @param value String to enescape
     * @return value in unescaped RDN format
     */
    public final String getUnescapedRdnValue(final String value){
        if (StringUtils.isNotEmpty(value)) {
            return org.ietf.ldap.LDAPDN.unescapeRDN(value);
        } else {
            return value;
        }
    }

    public void setSubjectDn(String subjectDn) {
        this.subjectDn = subjectDn;
    }

    public String getPublicKeyAlgorithm() {
        return publicKeyAlgorithm;
    }

    public void setPublicKeyAlgorithm(String publicKeyAlgorithm) {
        this.publicKeyAlgorithm = publicKeyAlgorithm;
    }

    public String getSubjectAlternativeName() {
        return subjectAlternativeName;
    }

    public void setSubjectAlternativeName(String subjectAlternativeName) {
        this.subjectAlternativeName = subjectAlternativeName;
    }

    public String getSubjectDirectoryAttributes() {
        return subjectDirectoryAttributes;
    }

    public void setSubjectDirectoryAttributes(String subjectDirectoryAttributes) {
        this.subjectDirectoryAttributes = subjectDirectoryAttributes;
    }

    public int getStyleRowCallCounter() {
        return styleRowCallCounter;
    }

    public void setStyleRowCallCounter(int styleRowCallCounter) {
        this.styleRowCallCounter = styleRowCallCounter;
    }

    public boolean isSubjectDirectoryAttributesUsed() {
        return !subjectDirectoryAttributes.isEmpty() && isMore();
    }

    public boolean isSubjectAlternativeNameUsed() {
        return !subjectAlternativeName.isEmpty();
    }

    public boolean isAnyRequestDataPresent() {
        return !subjectDn.isEmpty() || !subjectAlternativeName.isEmpty() || !subjectDirectoryAttributes.isEmpty();
    }

    /**
     * @return the issuerDn
     */
    public String getIssuerDn() {
        return issuerDn;
    }

    /**
     * @param issuerDn the issuerDn to set
     */
    public void setIssuerDn(String issuerDn) {
        this.issuerDn = issuerDn;
    }

    /**
     * @return the validity
     */
    public String getValidity() {
        return validity;
    }

    /**
     * @param validity the validity to set
     */
    public void setValidity(String validity) {
        this.validity = validity;
    }

    public List<String> getKeyUsages() {
        return keyUsages;
    }

    public void setKeyUsages(List<String> keyUsages) {
        this.keyUsages = keyUsages;
    }

    public List<String> getExtendedKeyUsages() {
        return extendedKeyUsages;
    }

    public void setExtendedKeyUsages(List<String> extendedKeyUsages) {
        this.extendedKeyUsages = extendedKeyUsages;
    }
    
    
}
