package se.anatom.ejbca.ca.store.certificateprofiles;

import java.util.ArrayList;

/**
 * HardTokenEncCertificateProfile is a class defining the fixed characteristics of a hard token authentication certificate.
 *
 * @version $Id: HardTokenEncCertificateProfile.java,v 1.1 2003-12-05 14:50:26 herrvendil Exp $
 */
public class HardTokenEncCertificateProfile extends CertificateProfile{

    // Public Constants

    public final static String CERTIFICATEPROFILENAME =  "HARDTOKEN_ENC";

    // Public Methods
    /** Creates a certificate with the characteristics of an end user. */
    public HardTokenEncCertificateProfile() {

      setCertificateVersion(VERSION_X509V3);
      setValidity(730);

      setUseBasicConstraints(true);
      setBasicConstraintsCritical(true);


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

      setUseKeyUsage(true);
      setKeyUsage(new boolean[9]);
      setKeyUsage(KEYENCIPHERMENT,true);      
      setKeyUsageCritical(true);

      setUseExtendedKeyUsage(true);
      ArrayList eku = new ArrayList();      
      setExtendedKeyUsage(eku);
      setExtendedKeyUsageCritical(false);
      
      ArrayList availablecas = new ArrayList();
      availablecas.add(new Integer(ANYCA));
      setAvailableCAs(availablecas);      
      setPublisherList(new ArrayList());
    }

    // Public Methods.
    public void upgrade(){
      if(LATEST_VERSION != getVersion()){
        // New version of the class, upgrade

        super.upgrade();         
      }
    }


    // Private fields.
}
