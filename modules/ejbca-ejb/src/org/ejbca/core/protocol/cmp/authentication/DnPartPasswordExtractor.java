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

package org.ejbca.core.protocol.cmp.authentication;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.protocol.cmp.CmpPKIBodyConstants;

import com.keyfactor.util.CertTools;

/**
 * Extracts password from the request DN of a CMRF/PKCS#10 request message
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
    
    /*
     * Extracts the value of 'dnPart' from the subjectDN of the certificate request template or 
     * PKC#10 subject part based on the message type.
     */
    @Override
    public boolean verifyOrExtract(final PKIMessage msg, final String username) {
        
        Object req = getReq(msg);
        if(req == null) {
            this.errorMessage = "No request was found in the PKIMessage";
            return false;
        }

        String dnString = null;
        if(req instanceof CertReqMsg) {
            dnString = ((CertReqMsg)req).getCertReq().getCertTemplate().getSubject().toString();
        } else if (req instanceof CertificationRequest) {
            dnString = ((CertificationRequest)req).getCertificationRequestInfo().getSubject().toString();
        }
        
        if(log.isDebugEnabled()) {
            log.debug("Extracting password from SubjectDN '" + dnString + "' and DN part '" + dnPart + "'");
        }
        if (dnString != null) {
            password = CertTools.getPartFromDN(dnString, dnPart);
        }
            
        if(password == null) {
            this.errorMessage = "Could not extract password from certificate request using the " + getName() + " authentication module";
            return false;
        }
        
        return true;    
    }
    
    private Object getReq(PKIMessage msg) {
        Object req = null;
        int tagnr = msg.getBody().getType();
        if(tagnr == CmpPKIBodyConstants.INITIALIZATIONREQUEST || tagnr == CmpPKIBodyConstants.CERTIFICATAIONREQUEST) {
            req = ((CertReqMessages) msg.getBody().getContent()).toCertReqMsgArray()[0];
        } else if (tagnr == CmpPKIBodyConstants.IMPORTEDFROMPKCS10) {
            req = msg.getBody().getContent();
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

    @Override
    public AuthenticationToken getAuthenticationToken() {
        return null;
    }

}
