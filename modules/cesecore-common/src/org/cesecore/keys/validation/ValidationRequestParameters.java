package org.cesecore.keys.validation;

import org.cesecore.certificates.certificateprofile.CertificateProfile;

public class ValidationRequestParameters {
    
    public CertificateProfile certificateProfile;
    
    public void setCertificateProfile(CertificateProfile certProfile) {
        certificateProfile = certProfile;
    }
    
    public CertificateProfile getCertificateProfile() {
        return certificateProfile;
    }

}
