package se.anatom.ejbca.ca.store.certificateprofiles;

import java.util.ArrayList;

/**
 * EndUserCertificateProfile is a class defining the fixed characteristics of an enduser certificate type
 *
* @version $Id: EndUserCertificateProfile.java,v 1.5 2003-02-20 09:00:57 herrvendil Exp $
  */
public class EndUserCertificateProfile extends CertificateProfile{

    // Public Constants

    public final static String CERTIFICATEPROFILENAME =  "ENDUSER";

    // Public Methods
    /** Creates a certificate with the characteristics of an end user. */
    public EndUserCertificateProfile() {

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

      setType(TYPE_ENDENTITY);

      int[] bitlengths = {512,1024,2048,4096};
      setAvailableBitLengths(bitlengths);

      // Standard key usages for end users are: digitalSignature | keyEncipherment or nonRepudiation
      // Default key usage is digitalSignature | keyEncipherment
      // Create an array for KeyUsage acoording to X509Certificate.getKeyUsage()
      setKeyUsage(new boolean[9]);
      setKeyUsage(DIGITALSIGNATURE,true);
      setKeyUsage(KEYENCIPHERMENT,true);
      
      setUseExtendedKeyUsage(true);
      ArrayList eku = new ArrayList();
      eku.add(new Integer(CLIENTAUTH));
      eku.add(new Integer(EMAILPROTECTION));
      eku.add(new Integer(IPSECUSER));  
      setExtendedKeyUsage(eku);
      
    }

    // Public Methods.
    public void upgrade(){    
      if(LATEST_VERSION != getVersion()){
        // New version of the class, upgrade

        data.put(VERSION, new Float(LATEST_VERSION));
        if(data.get(ALLOWKEYUSAGEOVERRIDE) == null)
          data.put(ALLOWKEYUSAGEOVERRIDE, Boolean.TRUE);
        if(data.get(USEEXTENDEDKEYUSAGE) ==null)
          data.put(USEEXTENDEDKEYUSAGE, Boolean.TRUE);
        if(data.get(EXTENDEDKEYUSAGE) ==null){
           ArrayList eku = new ArrayList();
           eku.add(new Integer(CLIENTAUTH));
           eku.add(new Integer(EMAILPROTECTION));
           eku.add(new Integer(IPSECUSER));             
           data.put(EXTENDEDKEYUSAGE, eku);
        }
      }
    }    


    // Private fields.
    
}
