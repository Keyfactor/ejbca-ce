/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.core.model.ca.certificateprofiles;

import java.util.ArrayList;

/**
 * EndUserCertificateProfile is a class defining the fixed characteristics of an enduser certificate type
 *
* @version $Id: EndUserCertificateProfile.java,v 1.1 2006-01-17 20:31:51 anatom Exp $
  */
public class EndUserCertificateProfile extends CertificateProfile{

    // Public Constants

    public static final String CERTIFICATEPROFILENAME =  "ENDUSER";

    // Public Methods
    /** Creates a certificate with the characteristics of an end user. */
    public EndUserCertificateProfile() {

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

      // Standard key usages for end users are: digitalSignature | keyEncipherment or nonRepudiation
      // Default key usage is digitalSignature | keyEncipherment
      // Create an array for KeyUsage acoording to X509Certificate.getKeyUsage()
      setUseKeyUsage(true);
      setKeyUsage(new boolean[9]);
      setKeyUsage(DIGITALSIGNATURE,true);
      setKeyUsage(KEYENCIPHERMENT,true);
      setKeyUsageCritical(true);

      setUseExtendedKeyUsage(true);
      ArrayList eku = new ArrayList();
      eku.add(new Integer(SERVERAUTH));
      eku.add(new Integer(CLIENTAUTH));
      eku.add(new Integer(EMAILPROTECTION));
      eku.add(new Integer(IPSECENDSYSTEM));
      eku.add(new Integer(IPSECUSER));
      setExtendedKeyUsage(eku);
      setExtendedKeyUsageCritical(false);
      
      ArrayList availablecas = new ArrayList();
      availablecas.add(new Integer(ANYCA));
      setAvailableCAs(availablecas);      
      setPublisherList(new ArrayList());
    }

    // Public Methods.
    public void upgrade(){
      super.upgrade();  
      if(LATEST_VERSION != getVersion()){
        // New version of the class, upgrade    
      }
    }


    // Private fields.

}
