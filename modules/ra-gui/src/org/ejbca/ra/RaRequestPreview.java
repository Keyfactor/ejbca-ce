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

import org.cesecore.certificates.ca.CAInfo;

/** 
 * UI representation of a certificate preview to be confirmed before enrollment.
 * 
 * @version $Id: RaCertificatePreview.java 23738 2016-06-28 14:22:39Z marko $
 */
public class RaRequestPreview {
    
    private String issuerDn = "";
    private String subjectDn = "";
    private String publicKeyAlgorithm = "";
    private String subjectAlternativeName = "";
    private String subjectDirectoryAttributes = "";

    private boolean more = false;
    private int styleRowCallCounter = 0;
    

    public RaRequestPreview(){
    }
    
    public void updateCA(CAInfo caInfo){
        issuerDn = caInfo.getSubjectDN();
    }
    
    public void updateSubjectDn(SubjectDn subjectDn){
        this.subjectDn = subjectDn.getUpdatedValue();
    }
    
    public void updateSubjectAlternativeName(SubjectAlternativeName subjectAlternativeName){
        this.subjectAlternativeName = subjectAlternativeName.getUpdatedValue();
    }
    
    public void updateSubjectDirectoryAttributes(SubjectDirectoryAttributes subjectDirectoryAttributes){
        this.subjectDirectoryAttributes = subjectDirectoryAttributes.getUpdatedValue();
    }

    /** @return true if more details should be shown */
    public boolean isMore() { return more; }
    public void actionToggleMore() {
        more = !more;
        styleRowCallCounter = 0;    // Reset
    }

    /** @return true every twice starting with every forth call */
    public boolean isEven() {
        styleRowCallCounter++;
        return (styleRowCallCounter+1) / 2 % 2 == 0;
    }

    public String getSubjectDn() {
        return subjectDn;
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
        return !subjectDirectoryAttributes.isEmpty();
    }

    public boolean isSubjectAlternativeNameUsed() {
        return !subjectAlternativeName.isEmpty();
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
}
