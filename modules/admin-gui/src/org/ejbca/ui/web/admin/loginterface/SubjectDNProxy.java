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

import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.CertTools;

/**
 * A class used to improve performance by proxying certificatesnr to subjectdn mappings by minimizing the number of needed lockups over rmi.
 *
 * @version $Id$
 */
public class SubjectDNProxy implements java.io.Serializable {

    /** Creates a new instance of SubjectDNProxy with remote access to CA part */
    public SubjectDNProxy(Admin admin, ICertificateStoreSessionRemote certificatesession){
              // Get the RaAdminSession instance.
      this.local = false;
      this.certificatesessionremote = certificatesession;
      this.subjectdnstore = new HashMap();
      this.admin = admin;

    }

    /** Creates a new instance of SubjectDNProxy with local access to CA part */
    public SubjectDNProxy(Admin admin, ICertificateStoreSessionLocal certificatesession){
              // Get the RaAdminSession instance.
      this.local = true;
      this.certificatesessionlocal = certificatesession;
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

      if(returnval==null && admindata.indexOf(',') != -1){
        // Try to find the certificate in database
        String certificatesnr = admindata.substring(0,admindata.indexOf(','));
        String issuerdn = admindata.substring(admindata.indexOf(',')+1);
        if(local) {
          result = certificatesessionlocal.findCertificateByIssuerAndSerno(admin, issuerdn, new BigInteger(certificatesnr));
        } else {
          result = certificatesessionremote.findCertificateByIssuerAndSerno(admin, issuerdn, new BigInteger(certificatesnr));
        }
        if(result != null){
          returnval = CertTools.getSubjectDN(result);
          subjectdnstore.put(admindata,returnval);
        }
      }

      return returnval;
    }

    // Private fields
    private boolean local;
    private HashMap subjectdnstore;
    private ICertificateStoreSessionLocal  certificatesessionlocal;
    private ICertificateStoreSessionRemote certificatesessionremote;
    private Admin                          admin;

}
