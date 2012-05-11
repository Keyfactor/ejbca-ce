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
 
package org.ejbca.core.model.ca.caadmin.extendedcaservices;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceResponse;

/**
 * Class used when delivering OCSP service response from a CA.  
 *
 * @version $Id$
 */
public class OCSPCAServiceResponse extends ExtendedCAServiceResponse implements Serializable {    
             
    private static final long serialVersionUID = 6902833915867802344L;
    private List<X509CertificateHolder> ocspcertificatechain = null;
    private BasicOCSPResp basicResp = null;
    
        
    public OCSPCAServiceResponse(BasicOCSPResp basicResp, List<X509CertificateHolder> ocspsigningcertificatechain) {
        this.basicResp = basicResp;
        this.ocspcertificatechain = ocspsigningcertificatechain;
    }    
           
    public X509CertificateHolder getOCSPSigningCertificate() { return  this.ocspcertificatechain.get(0); }
	public Collection<X509CertificateHolder> getOCSPSigningCertificateChain() { 
        if (ocspcertificatechain != null) {
            return this.ocspcertificatechain;
        }
        return new ArrayList<X509CertificateHolder>();
    }
    public BasicOCSPResp getBasicOCSPResp() { return this.basicResp; }
        
}
