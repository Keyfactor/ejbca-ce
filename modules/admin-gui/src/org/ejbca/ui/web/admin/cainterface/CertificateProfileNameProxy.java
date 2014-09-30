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
 
package org.ejbca.ui.web.admin.cainterface;


import java.util.HashMap;

import org.cesecore.certificates.certificateprofile.CertificateProfileSession;

/**
 * A class used to improve performance by proxying certificateprofile id to certificate name mappings by minimizing the number of needed lockups over rmi.
 * 
 * @version $Id$
 */
public class CertificateProfileNameProxy implements java.io.Serializable {
    
    private static final long serialVersionUID = -8362730983248532144L;
    private HashMap<Integer, String> certificateprofilenamestore;
    private CertificateProfileSession certificateProfileSession;

    /** Creates a new instance of ProfileNameProxy */
    public CertificateProfileNameProxy(CertificateProfileSession certificateProfileSession){
      this.certificateProfileSession = certificateProfileSession;
      certificateprofilenamestore = new HashMap<Integer, String>(); 
    }
    
    /**
     * Method that first tries to find certificateprofile name in local hashmap and if it does not exist looks it up over RMI.
     *
     * @param certificateprofileid the certificateprofile id number to look up.
     * @return the certificateprofilename or null if no certificateprofilename is relatied to the given id
     */
    public String getCertificateProfileName(int certificateprofileid)  {
      String returnval = null;  
      // Check if name is in hashmap
      returnval = (String) certificateprofilenamestore.get(Integer.valueOf(certificateprofileid));
      
      if(returnval==null){
        // Retreive profilename 
        returnval = certificateProfileSession.getCertificateProfileName(certificateprofileid);
        if(returnval != null) {
          certificateprofilenamestore.put(Integer.valueOf(certificateprofileid),returnval);
        }
      }    
      return returnval;
    }
}
