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
package org.cesecore.config;

import java.io.Serializable;

public class MSAutoEnrollmentSettingsTemplate implements Serializable {
    private static final long serialVersionUID = 1L;

    private boolean isUsed;
    private String oid;
    private String minorRevision;
    private String MajorRevision;
    private String displayName;
    private String name;
    private String certificateProfile;
    private String endEntityProfile;
    private String subjectNameFormat; // TODO: Enum?
    private boolean includeEmailInSubjectDN;
    private boolean includeEmailInSubjectSAN;
    private boolean includeUPNInSubjectSAN;
    private boolean includeSPNInSubjectSAN;
    private boolean includeNetBiosInSubjectSAN;
    private boolean includeDomainInSubjectSAN;
    private boolean includeObjectGuidInSubjectSAN;
    private String additionalSubjectDNAttributes;
    private boolean publishToActiveDirectory;
    
    private boolean excludeObjectSidInNtdsSecurityExtension;

    public MSAutoEnrollmentSettingsTemplate() {
        init();
    }

    private void init() {
        setUsed(false);
        setOid("");
        setMinorRevision("");
        setMajorRevision("");
        setDisplayName("");
        setName("");
        setCertificateProfile("");
        setEndEntityProfile("");
        setSubjectNameFormat("");
        setIncludeEmailInSubjectDN(false);
        setIncludeEmailInSubjectSAN(false);
        setIncludeUPNInSubjectSAN(false);
        setIncludeSPNInSubjectSAN(false);
        setIncludeNetBiosInSubjectSAN(false);
        setIncludeDomainInSubjectSAN(false);
        setIncludeObjectGuidInSubjectSAN(false);
        setAdditionalSubjectDNAttributes("");
        setPublishToActiveDirectory(false);
        setExcludeObjectSidInNtdsSecurityExtension(false);
    }



    // Getters and Setters
    public boolean isUsed() {
        return isUsed;
    }

    public void setUsed(boolean used) {
        isUsed = used;
    }

    public String getOid() {
        return oid;
    }

    public void setOid(String oid) {
        this.oid = oid;
    }
    
    public String getMinorRevision() {
        return minorRevision;
    }

    public void setMinorRevision(String minorRevision) {
        this.minorRevision = minorRevision;
    }

    public String getMajorRevision() {
        return MajorRevision;
    }

    public void setMajorRevision(String majorRevision) {
        MajorRevision = majorRevision;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getCertificateProfile() {
        return certificateProfile;
    }

    public void setCertificateProfile(String certificateProfile) {
        this.certificateProfile = certificateProfile;
    }

    public String getEndEntityProfile() {
        return endEntityProfile;
    }

    public void setEndEntityProfile(String endEntityProfile) {
        this.endEntityProfile = endEntityProfile;
    }

    public String getSubjectNameFormat() {
        return subjectNameFormat;
    }

    public void setSubjectNameFormat(String subjectNameFormat) {
        this.subjectNameFormat = subjectNameFormat;
    }

    public boolean isIncludeEmailInSubjectDN() {
        return includeEmailInSubjectDN;
    }

    public void setIncludeEmailInSubjectDN(boolean includeEmailInSubjectDN) {
        this.includeEmailInSubjectDN = includeEmailInSubjectDN;
    }

    public boolean isIncludeEmailInSubjectSAN() {
        return includeEmailInSubjectSAN;
    }

    public void setIncludeEmailInSubjectSAN(boolean includeEmailInSubjectSAN) {
        this.includeEmailInSubjectSAN = includeEmailInSubjectSAN;
    }

    public boolean isIncludeUPNInSubjectSAN() {
        return includeUPNInSubjectSAN;
    }

    public void setIncludeUPNInSubjectSAN(boolean includeUPNInSubjectSAN) {
        this.includeUPNInSubjectSAN = includeUPNInSubjectSAN;
    }

    public boolean isIncludeSPNInSubjectSAN() {
        return includeSPNInSubjectSAN;
    }

    public void setIncludeSPNInSubjectSAN(boolean includeSPNInSubjectSAN) {
        this.includeSPNInSubjectSAN = includeSPNInSubjectSAN;
    }

    public boolean isIncludeNetBiosInSubjectSAN() {
        return includeNetBiosInSubjectSAN;
    }

    public void setIncludeNetBiosInSubjectSAN(boolean includeNetBiosInSubjectSAN) {
        this.includeNetBiosInSubjectSAN = includeNetBiosInSubjectSAN;
    }

    public boolean isIncludeDomainInSubjectSAN() {
        return includeDomainInSubjectSAN;
    }

    public void setIncludeDomainInSubjectSAN(boolean includeDomainInSubjectSAN) {
        this.includeDomainInSubjectSAN = includeDomainInSubjectSAN;
    }

    public boolean isIncludeObjectGuidInSubjectSAN() {
        return includeObjectGuidInSubjectSAN;
    }

    public void setIncludeObjectGuidInSubjectSAN(boolean includeObjectGuidInSubjectSAN) {
        this.includeObjectGuidInSubjectSAN = includeObjectGuidInSubjectSAN;
    }
    
    public String getAdditionalSubjectDNAttributes() {
        return additionalSubjectDNAttributes;
    }

    public void setAdditionalSubjectDNAttributes(String additionalSubjectDNAttributes) {
        this.additionalSubjectDNAttributes = additionalSubjectDNAttributes;
    }

    public boolean isPublishToActiveDirectory() {
        return publishToActiveDirectory;
    }

    public void setPublishToActiveDirectory(boolean publishToActiveDirectory) {
        this.publishToActiveDirectory = publishToActiveDirectory;
    }

    public boolean isExcludeObjectSidInNtdsSecurityExtension() {
        return excludeObjectSidInNtdsSecurityExtension;
    }

    public void setExcludeObjectSidInNtdsSecurityExtension(boolean excludeObjectSidInNtdsSecurityExtension) {
        this.excludeObjectSidInNtdsSecurityExtension = excludeObjectSidInNtdsSecurityExtension;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((oid == null) ? 0 : oid.hashCode());
        result = prime * result + ((oid == null) ? 0 : oid.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        MSAutoEnrollmentSettingsTemplate other = (MSAutoEnrollmentSettingsTemplate) obj;
        return oid.equals(other.oid);
    }

    @Override
    public String toString() {
        return "OID: " + getOid() + 
        "\nDisplayName: " + getDisplayName() + 
        "\nCertificateProfile: " + getCertificateProfile() + 
        "\nEndEntityProfile: " + getEndEntityProfile() + 
        "\nSubjectNameFormat: " + getSubjectNameFormat() + 
        "\nIncludeEmailInSubjectDN: " + isIncludeEmailInSubjectDN() + 
        "\nIncludeEmailInSubjectSAN: " + isIncludeEmailInSubjectSAN() + 
        "\nIncludeUPNInSubjectSAN: " + isIncludeUPNInSubjectSAN() + 
        "\nIncludeSPNInSubjectSAN: " + isIncludeSPNInSubjectSAN() + 
        "\nIncludeNetBiosInSubjectSAN: " + isIncludeNetBiosInSubjectSAN() + 
        "\nIncludeDomainInSubjectSAN: " + isIncludeDomainInSubjectSAN() + 
        "\nIncludeObjectGuidInSubjectSAN: " + isIncludeObjectGuidInSubjectSAN() +
        "\nAdditionalSubjectDNAttributes: " + getAdditionalSubjectDNAttributes() + 
        "\nPublishToActiveDirectory: " + isPublishToActiveDirectory() +
        "\nExcludeObjectSidInNtdsSecurityExtension: " + isExcludeObjectSidInNtdsSecurityExtension();
    }
}
