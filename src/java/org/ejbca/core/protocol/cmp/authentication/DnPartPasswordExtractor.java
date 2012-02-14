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


package org.ejbca.core.protocol.cmp.authentication;

import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.protocol.cmp.CmpPKIBodyConstants;

import com.novosec.pkix.asn1.cmp.PKIMessage;
import com.novosec.pkix.asn1.crmf.CertReqMsg;

/**
 * Extracts password from the request DN of a CMRF request message
 *
 * @version $Id$
 *
 */
public class DnPartPasswordExtractor implements ICMPAuthenticationModule {

    private static final Logger log = Logger.getLogger(DnPartPasswordExtractor.class);

    private String dnPart;
    private String password;
    private String errorMessage;
    
    public DnPartPasswordExtractor(String dnpart) {
        this.dnPart = dnpart;
        this.password = null;
        this.errorMessage = null;
    }
    
    /**
     * Extracts the value of 'dnPart' from the subjectDN of the certificate request template.
     * 
     * @param msg
     * @param username
     * @param authenticated
     * @return
     */
    public boolean verifyOrExtract(final PKIMessage msg, final String username, boolean authenticated) {
        
        CertReqMsg req = getReq(msg);
        if(req == null) {
            return false;
        }
        
        boolean ret = false;        
            String pwd = null;
            
            final String dnString = req.getCertReq().getCertTemplate().getSubject().toString();
            if(log.isDebugEnabled()) {
                log.debug("Extracting password from SubjectDN '" + dnString + "' and DN part '" + dnPart + "'");
            }
            if (dnString != null) {
                pwd = CertTools.getPartFromDN(dnString, dnPart);
            }
            
            if(pwd != null) {
                this.password = pwd;
                ret = true;
            } else {
                this.errorMessage = "Could not extract password from CRMF request using the " + getName() + " authentication module";
            }
        
        return ret;
    }
    
    private CertReqMsg getReq(PKIMessage msg) {
        CertReqMsg req = null;
        if(msg.getBody().getTagNo() == CmpPKIBodyConstants.INITIALIZATIONREQUEST) {
            req = msg.getBody().getIr().getCertReqMsg(0);
        } else if(msg.getBody().getTagNo() == CmpPKIBodyConstants.CERTIFICATAIONREQUEST) {
            req = msg.getBody().getCr().getCertReqMsg(0);
        }
        return req;
    }

    @Override
    public String getAuthenticationString() {
        return this.password;
    }

    @Override
    public String getErrorMessage() {
        return this.errorMessage;
    }

    @Override
    public String getName() {
        return CmpConfiguration.AUTHMODULE_DN_PART_PWD;
    }

}
