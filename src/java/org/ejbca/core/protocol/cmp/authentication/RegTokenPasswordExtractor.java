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

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERUTF8String;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.protocol.cmp.CmpPKIBodyConstants;

import com.novosec.pkix.asn1.cmp.PKIMessage;
import com.novosec.pkix.asn1.crmf.AttributeTypeAndValue;
import com.novosec.pkix.asn1.crmf.CRMFObjectIdentifiers;
import com.novosec.pkix.asn1.crmf.CertReqMsg;

/**
 * Extracts password from the CMRF request message parameters
 * 
 * @version $Id$
 *
 */
public class RegTokenPasswordExtractor implements ICMPAuthenticationModule {
    
    private static final Logger log = Logger.getLogger(RegTokenPasswordExtractor.class);

    private String password;
    private String errorMessage;
    
    public RegTokenPasswordExtractor() {
        this.password = null;
        this.errorMessage = null;
    }
    
    /**
     * Extracts password from the CMRF request message parameters
     * 
     * @param msg
     * @param username
     * @param authenticated
     * @return the password extracted from the CRMF request. Null if no such password was found.
     */
    public boolean verifyOrExtract(final PKIMessage msg, final String username, boolean authenticated) {
        CertReqMsg req = getReq(msg);
        if(req == null) {
            return false;
        }
        
        boolean ret = false;
        String pwd = null;
            
            // If there is "Registration Token Control" in the CertReqMsg regInfo containing a password, we can use that
            AttributeTypeAndValue av = null;
            int i = 0;
            do {
                av = req.getRegInfo(i);
                if (av != null) {
                    if (log.isTraceEnabled()) {
                        log.trace("Found AttributeTypeAndValue (in CertReqMsg): "+av.getObjectId().getId());
                    }
                    if (StringUtils.equals(CRMFObjectIdentifiers.regCtrl_regToken.getId(), av.getObjectId().getId())) {
                        final DEREncodable enc = av.getParameters();
                        final DERUTF8String str = DERUTF8String.getInstance(enc);
                        pwd = str.getString();
                        if (log.isDebugEnabled()) {
                            log.debug("Found a request password in CRMF request regCtrl_regToken");
                        }
                    }
                }
                i++;
            } while ( (av != null) && (pwd == null) );
        
            if (pwd == null) {
                // If there is "Registration Token Control" in the CertRequest controls containing a password, we can use that
                // Note, this is the correct way to use the regToken according to RFC4211, section "6.1.  Registration Token Control"
                av = null;
                i = 0;
                do {
                    av = req.getCertReq().getControls(i);
                    if (av != null) {
                        if (log.isTraceEnabled()) {
                            log.trace("Found AttributeTypeAndValue (in CertReq): "+av.getObjectId().getId());
                        }
                        if (StringUtils.equals(CRMFObjectIdentifiers.regCtrl_regToken.getId(), av.getObjectId().getId())) {
                            final DEREncodable enc = av.getParameters();
                            final DERUTF8String str = DERUTF8String.getInstance(enc);
                            pwd = str.getString();
                            if (log.isDebugEnabled()) {
                                log.debug("Found a request password in CRMF request regCtrl_regToken");
                            }
                        }
                    }
                    i++;
                } while ( (av != null) && (pwd == null) );
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
        return CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD;
    }

}
