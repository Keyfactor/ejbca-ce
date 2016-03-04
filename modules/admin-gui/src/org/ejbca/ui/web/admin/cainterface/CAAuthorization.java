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

import java.io.Serializable;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;

/**
 * A class that looks up the which CA:s and certificate profiles the administrator is authorized to view.
 * 
 * @version $Id$
 */
public class CAAuthorization implements Serializable {

    private static final long serialVersionUID = -7397428143642714604L;

    private List<Integer> authcas = null;
    private TreeMap<String, Integer> profilenamesendentity = null;
    private TreeMap<String, Integer> profilenamessubca = null;
    private TreeMap<String, Integer> profilenamesrootca = null;
    private TreeMap<String, Integer> allcanames = null;
    private AuthenticationToken admin;
    private CaSessionLocal caSession;
    private CertificateProfileSession certificateProfileSession;
    
    /** Creates a new instance of CAAuthorization. */
    public CAAuthorization(AuthenticationToken admin, CaSessionLocal caSession, CertificateProfileSession certificateProfileSession) {
        this.admin=admin;
        this.caSession=caSession;      
        this.certificateProfileSession = certificateProfileSession;
    }

    /**
     * Method returning a List of authorized CA id's (Integer).
     *
     */
    public List<Integer> getAuthorizedCAIds() {         
    	if(authcas == null || authcas.size() == 0){
    		authcas = caSession.getAuthorizedCaIds(admin);
    	}
    	return authcas;
    } 
    
    
    
    public TreeMap<String, Integer> getAuthorizedEndEntityCertificateProfileNames(boolean usehardtokenprofiles){
      if(profilenamesendentity==null){
        profilenamesendentity = new TreeMap<String, Integer>();  
        Iterator<Integer> iter = null;
        if(usehardtokenprofiles) {         
          iter = certificateProfileSession.getAuthorizedCertificateProfileIds(admin, CertificateConstants.CERTTYPE_HARDTOKEN).iterator();
        } else {
		  iter = certificateProfileSession.getAuthorizedCertificateProfileIds(admin, CertificateConstants.CERTTYPE_ENDENTITY).iterator();
        }
        Map<Integer, String> idtonamemap = certificateProfileSession.getCertificateProfileIdToNameMap();
        while(iter.hasNext()){
          Integer id = (Integer) iter.next();
          profilenamesendentity.put(idtonamemap.get(id),id);
        }
      }
      return profilenamesendentity;  
    }
            
    public TreeMap<String, Integer> getAuthorizedSubCACertificateProfileNames(){
      if(profilenamessubca==null){
        profilenamessubca = new TreeMap<String, Integer>();  
        Iterator<Integer> iter = certificateProfileSession.getAuthorizedCertificateProfileIds(admin, CertificateConstants.CERTTYPE_SUBCA).iterator();      
        Map<Integer, String> idtonamemap = certificateProfileSession.getCertificateProfileIdToNameMap();
        while(iter.hasNext()){
          Integer id = (Integer) iter.next();
          profilenamessubca.put(idtonamemap.get(id),id);
        }
      }
      return profilenamessubca;  
    }
    
    
    public TreeMap<String, Integer> getAuthorizedRootCACertificateProfileNames(){
      if(profilenamesrootca==null){
        profilenamesrootca = new TreeMap<String, Integer>();  
        Map<Integer, String> idtonamemap = certificateProfileSession.getCertificateProfileIdToNameMap();
            for (Integer id : certificateProfileSession.getAuthorizedCertificateProfileIds(admin, CertificateConstants.CERTTYPE_ROOTCA)) {
                profilenamesrootca.put(idtonamemap.get(id), id);
            }
        }
      return profilenamesrootca;  
    }
    
    public TreeMap<String, Integer> getAllCANames() {
        allcanames = new TreeMap<String, Integer>(new Comparator<String>() {
            @Override
            public int compare(String o1, String o2) {              
                return o1.compareToIgnoreCase(o2);
            }
        });
        HashMap<Integer, String> idtonamemap = this.caSession.getCAIdToNameMap();
        for (Integer id : idtonamemap.keySet()) {
            allcanames.put(idtonamemap.get(id), id);
        }
        return allcanames;
    }
 
    public void clear(){
      authcas=null;
      profilenamesendentity = null;
      profilenamessubca = null;
      profilenamesrootca = null;
      allcanames=null;
    }

}
