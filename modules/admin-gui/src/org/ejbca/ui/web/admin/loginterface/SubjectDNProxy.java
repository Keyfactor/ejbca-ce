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
 
package org.ejbca.ui.web.admin.loginterface;

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.cert.Certificate;
import java.util.HashMap;

import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.CertTools;

/**
 * A class used to improve performance by proxying certificatesnr to subjectdn mappings by minimizing the number of needed lockups over rmi.
 *
 * @version $Id$
 */
public class SubjectDNProxy implements java.io.Serializable {

    private HashMap subjectdnstore;
    private CertificateStoreSession certificatesession;
    private Admin admin;

    /** Creates a new instance of SubjectDNProxy with remote access to CA part */
    public SubjectDNProxy(Admin admin, CertificateStoreSession certificatesession){
              // Get the RaAdminSession instance.
      this.certificatesession = certificatesession;
      this.subjectdnstore = new HashMap();
      this.admin = admin;
    }

    /**
     * Method that first tries to find subjectDN in local hashmap and if it doesn't exists looks it up over RMI.
     *
     * @param certificatesnr the certificate serial number number to look up.
     * @return the subjectDN or null if no subjectDN is relatied to the given id
     */
    public String getSubjectDN(String admindata) throws RemoteException {
      String returnval = null;
      Certificate result = null;

      // Check if name is in hashmap
      returnval = (String) subjectdnstore.get(admindata);

      if(returnval==null && admindata.indexOf(':') != -1){
        // Try to find the certificate in database

        String data[] = admindata.split(":");  
        String certificatesnr = data[0].trim();
        String issuerdn = data[2].substring(data[2].indexOf('"')+1, data[2].lastIndexOf('"'));
        result = certificatesession.findCertificateByIssuerAndSerno(admin, issuerdn, new BigInteger(certificatesnr, 16));
        if(result != null){
          returnval = CertTools.getSubjectDN(result);
          subjectdnstore.put(admindata,returnval);
        } else {
          if((data.length > 3) && ("CertDN".equals(data[3].trim()))){
                returnval = data[4].substring(data[4].indexOf('"')+1, data[4].lastIndexOf('"'));
                subjectdnstore.put(admindata,returnval);
          }
        }
      }

      return returnval;
    }
}
