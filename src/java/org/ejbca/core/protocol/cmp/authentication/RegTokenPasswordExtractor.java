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

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.protocol.cmp.CmpMessageHelper;
import org.ejbca.core.protocol.cmp.CmpPKIBodyConstants;

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
    
    @Override
    /*
     * Extracts password from the CMRF request message parameters
     */
    public boolean verifyOrExtract(final PKIMessage msg, final String username) {
        CertReqMsg req = getReq(msg);
        if(req == null) {
            this.errorMessage = "No request was found in the PKIMessage";
            return false;
        }
        
        String pwd = null;
            
        // If there is "Registration Token Control" in the CertReqMsg regInfo containing a password, we can use that
        AttributeTypeAndValue[] avs = req.getRegInfo();
        if(avs != null) {
            AttributeTypeAndValue av = null;
            int i = 0;
            do {
                av = avs[i];
                if (av != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Found AttributeTypeAndValue (in CertReqMsg): "+av.getType().getId());
                    }
                    if (StringUtils.equals(CRMFObjectIdentifiers.id_regCtrl_regToken.getId(), av.getType().getId())) {
                        final ASN1Encodable enc = av.getValue();
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
        
        if (pwd == null) {
            // If there is "Registration Token Control" in the CertRequest controls containing a password, we can use that
            // Note, this is the correct way to use the regToken according to RFC4211, section "6.1.  Registration Token Control"
            if(req.getCertReq().getControls() != null) {
                avs = req.getCertReq().getControls().toAttributeTypeAndValueArray();
                AttributeTypeAndValue av = null;
                int i = 0;
                do {
                    av = avs[i];
                    if (av != null) {
                        if (log.isDebugEnabled()) {
                            log.debug("Found AttributeTypeAndValue (in CertReq): "+av.getType().getId());
                        }
                        if (StringUtils.equals(CRMFObjectIdentifiers.id_regCtrl_regToken.getId(), av.getType().getId())) {
                            final ASN1Encodable enc = av.getValue();
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
        }

        if(pwd == null) {
            this.errorMessage = "Could not extract password from CRMF request using the " + getName() + " authentication module";
            return false;
        }
        
        this.password = pwd;
        return this.password != null;
    }
    
    private CertReqMsg getReq(PKIMessage msg) {
        CertReqMsg req = null;
        int tagnr = msg.getBody().getType();
        if(tagnr == CmpPKIBodyConstants.INITIALIZATIONREQUEST || tagnr == CmpPKIBodyConstants.CERTIFICATAIONREQUEST) {
            CertReqMessages msgs = (CertReqMessages) msg.getBody().getContent();
            try {
                req = msgs.toCertReqMsgArray()[0];
            } catch(Exception e) {
                log.debug("Could not parse the revocation request. Trying to parse it as novosec generated message.");
                req = CmpMessageHelper.getNovosecCertReqMsg(msgs);
                log.debug("Succeeded in parsing the novosec generated request.");
            }
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
