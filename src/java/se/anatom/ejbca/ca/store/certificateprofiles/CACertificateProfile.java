/*
 * CACertificateProfile.java
 *
 * Created on den 29 juli 2002, 22:08
 */
package se.anatom.ejbca.ca.store.certificateprofiles;

import java.util.ArrayList;

/**
 * CACertificateProfile is a class defining the fixed characteristics of a CA certificate profile.
 *
 * @author  TomSelleck
 */
public class CACertificateProfile extends CertificateProfile{

    // Public Constants

    public final static  String CERTIFICATEPROFILENAME =  "CA";

    // Public Methods
    /** Creates a certificate with the characteristics of an end user. */
    public CACertificateProfile() {

      setCertificateVersion(VERSION_X509V3);
      setValidity(730);

      setUseBasicConstraints(true);
      setBasicConstraintsCritical(true);

      setUseKeyUsage(true);
      setKeyUsageCritical(true);

      setUseSubjectKeyIdentifier(true);
      setSubjectKeyIdentifierCritical(false);

      setUseAuthorityKeyIdentifier(true);
      setAuthorityKeyIdentifierCritical(false);

      setUseSubjectAlternativeName(true);
      setSubjectAlternativeNameCritical(false);

      setUseCRLDistributionPoint(false);
      setCRLDistributionPointCritical(false);
      setCRLDistributionPointURI("");

      setUseCertificatePolicies(false);
      setCertificatePoliciesCritical(false);
      setCertificatePolicyId("2.5.29.32.0");      
      setType(TYPE_CA); 
      

      int[] bitlengths = {512,1024,2048,4096};
      setAvailableBitLengths(bitlengths);

      setKeyUsage(new boolean[9]);
      setKeyUsage(KEYCERTSIGN,true);
      setKeyUsage(CRLSIGN,true);
      
      setUseExtendedKeyUsage(false);
      setExtendedKeyUsage(new ArrayList());

    }

    // Public Methods.
    public void upgrade(){        
      if(LATEST_VERSION != getVersion()){
        // New version of the class, upgrade

        data.put(VERSION, new Float(LATEST_VERSION));
        if(data.get(ALLOWKEYUSAGEOVERRIDE) == null)
          data.put(ALLOWKEYUSAGEOVERRIDE, Boolean.TRUE);
        if(data.get(USEEXTENDEDKEYUSAGE) ==null)
          data.put(USEEXTENDEDKEYUSAGE, Boolean.FALSE);
        if(data.get(EXTENDEDKEYUSAGE) ==null)       
          data.put(EXTENDEDKEYUSAGE, new ArrayList());
      }
    }

    // Private fields.
}
