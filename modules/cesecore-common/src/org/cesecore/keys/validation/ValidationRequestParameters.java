package org.cesecore.keys.validation;

import org.cesecore.certificates.certificateprofile.CertificateProfile;

public class ValidationRequestParameters {
    
    public CertificateProfile certificateProfile;
    
    void setCertificateProfile(CertificateProfile certProfile) {
        certificateProfile = certProfile;
    }
    
    public CertificateProfile getCertificateProfile() {
        return certificateProfile;
    }

}
