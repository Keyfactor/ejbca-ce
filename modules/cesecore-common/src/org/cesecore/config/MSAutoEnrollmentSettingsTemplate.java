package org.cesecore.config;

import java.io.Serializable;

public class MSAutoEnrollmentSettingsTemplate implements Serializable {
    private static final long serialVersionUID = 1L;

    private boolean isUsed;
    private String oid;
    private String certificationProfile;
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

    public MSAutoEnrollmentSettingsTemplate() {
        init();
    }

    private void init() {
        setUsed(false);
        setOid("");
        setCertificationProfile("");
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

    public String getCertificationProfile() {
        return certificationProfile;
    }

    public void setCertificationProfile(String certificationProfile) {
        this.certificationProfile = certificationProfile;
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

    public String isAdditionalSubjectDNAttributes() {
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
        if (!oid.equals(other.oid)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return getOid();
    }
}
