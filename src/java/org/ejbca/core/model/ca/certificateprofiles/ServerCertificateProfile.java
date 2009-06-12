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

import org.bouncycastle.asn1.x509.KeyPurposeId;

/**
 * ServerCertificateProfile is a class defining the fixed characteristics of a SSL/TLS server certificate type
 *
 * @version $Id: ServerCertificateProfile.java, dcarella $
 */
public class ServerCertificateProfile extends CertificateProfile{

    // Public Constants

    public static final String CERTIFICATEPROFILENAME =  "SERVER";

    // Public Methods
    /** Creates a certificate with the characteristics of a SSL/TLS server.
     * General options are set in the superclass's default contructor that is called automatically.
     * You can override the general options by defining them again with different parameters here.
     */
    public ServerCertificateProfile() {

      setType(TYPE_ENDENTITY);

      // Standard key usages for server are: digitalSignature | (keyEncipherment or keyAgreement)
      // Default key usage is digitalSignature | keyEncipherment
      // Create an array for KeyUsage acoording to X509Certificate.getKeyUsage()
      setUseKeyUsage(true);
      setKeyUsage(new boolean[9]);
      setKeyUsage(DIGITALSIGNATURE,true);
      setKeyUsage(KEYENCIPHERMENT,true);
      setKeyUsageCritical(true);

      setUseExtendedKeyUsage(true);
      ArrayList eku = new ArrayList();
      eku.add(KeyPurposeId.id_kp_serverAuth.getId());
      setExtendedKeyUsage(eku);
      setExtendedKeyUsageCritical(false);

    }

    // Public Methods.
    public void upgrade(){
    	if(Float.compare(getLatestVersion(), getVersion()) != 0) {
    		// New version of the class, upgrade    
    		super.upgrade();  
    	}
    }


    // Private fields.

}
