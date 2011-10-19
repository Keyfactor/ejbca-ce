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
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.control.AccessControlSession;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;

import com.novosec.pkix.asn1.cmp.PKIMessage;

/**
 * Verifies a CMP message using a suitable authentication module. The authentication modules 
 * are specified in the properties file.
 * 
 * @version $Id$
 *
 */
public class VerifyPKIMessage {
    
    private static final Logger log = Logger.getLogger(VerifyPKIMessage.class);
    
    private CAInfo cainfo;
    private ICMPAuthenticationModule authModule;
    
    private AuthenticationToken admin;
    private CaSession caSession;
    private EndEntityAccessSession eeAccessSession;
    private CertificateStoreSession certificateStoreSession;
    private AccessControlSession authorizationSessoin;
    private EndEntityProfileSession eeProfileSession;
    private WebAuthenticationProviderSessionLocal authenticationProviderSession;
    
    private String errMsg;

    public VerifyPKIMessage() {
        this.cainfo = null;
        this.authModule = null;
        
        this.admin = null;
        this.caSession = null;
        this.eeAccessSession = null;
        this.certificateStoreSession = null;
        this.authorizationSessoin = null;
        this.eeProfileSession = null;
        this.authenticationProviderSession = null;
        
        this.errMsg = null;
    }
    
    public VerifyPKIMessage(final CAInfo cainfo, final AuthenticationToken admin, final CaSession casession, final EndEntityAccessSession userSession, final CertificateStoreSession certSession,
            final AccessControlSession authSession, final EndEntityProfileSession eeprofSession, final WebAuthenticationProviderSessionLocal authProvSession) {
        this.cainfo = cainfo;
        this.authModule = null;
        
        this.admin = admin;
        this.caSession = casession;
        this.eeAccessSession = userSession;
        this.certificateStoreSession = certSession;
        this.authorizationSessoin = authSession;
        this.eeProfileSession = eeprofSession;
        this.authenticationProviderSession = authProvSession;
        
    }
    
    
    /**
     * Returns the error message resulted in failing to verify the PKIMessage
     * 
     * The error message is set if verify() returns false.
     * 
     * @return the error message as String. Null if the verification succeeded.
     */
    public String getErrorMessage() {
        return this.errMsg;
    }
    
    /**
     * Returns the name of the authentication module that was successfully used to authenticate the message.
     * 
     * The authentication module is set if verify() returns true.
     * 
     * @return the name of the successful authentication module. Null if message verification failed.
     */
    public ICMPAuthenticationModule getUsedAuthenticationModule() {
        return this.authModule;
    }
    
    /**
     * Verifies the authenticity of msg
     * 
     * @param msg
     * @return True if verification is successful. False otherwise
     */
    public boolean verify(final PKIMessage msg) {
        if (log.isTraceEnabled()) {
            log.trace(">verify");
        }
        boolean ret = false;
        final String authModules = CmpConfiguration.getAuthenticationModule();
        final String authparameters = CmpConfiguration.getAuthenticationParameters();
        final String modules[] = authModules.split(";");
        final String params[] = authparameters.split(";");
                
        ICMPAuthenticationModule module = null;
        int i=0;
        while(i<modules.length) {
            if(log.isDebugEnabled()) {
                log.debug("Trying to verify the message authentication by using '" + modules[i] + "' authentication module and authentication parameter '" + ((params[i]==null)?"null":"not null")+"'."); 
            }

            module = getAuthModule(modules[i].trim(), params[i].trim(), msg);
            if((module != null) && module.verifyOrExtract(msg)) {
                this.authModule = module;
                ret = true;
                break;
            }
            if((module != null) && (module.getErrorMessage() != null)) {
                errMsg = module.getErrorMessage();
            }
            i++;
        }
        if (log.isTraceEnabled()) {
            log.trace("<verify: "+ret);
        }
        return ret;
    }
    
    /**
     * Returns the authentication module whose name is 'module'
     * 
     * @param module
     * @param parameter
     * @param pkimsg
     * @return The authentication module whose name is 'module'. Null if no such module is implemented.
     */
    private ICMPAuthenticationModule getAuthModule(final String module, final String parameter, final PKIMessage pkimsg) {
        if(StringUtils.equals(module, CmpConfiguration.AUTHMODULE_HMAC)) {
            final HMACAuthenticationModule hmacmodule = new HMACAuthenticationModule(parameter);
            hmacmodule.setSession(this.admin, this.eeAccessSession, this.certificateStoreSession);
            hmacmodule.setCaInfo(this.cainfo);
            return hmacmodule;
        } else if(StringUtils.equals(module, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE)) {
            final EndEntityCertificateAuthenticationModule eemodule = new EndEntityCertificateAuthenticationModule(parameter);
            eemodule.setSession(this.admin, this.caSession, this.certificateStoreSession, this.authorizationSessoin, this.eeProfileSession, authenticationProviderSession);
            return eemodule;
        }
        if(!CmpConfiguration.getRAOperationMode()) {
            if(StringUtils.equals(module, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD)){
                return new RegTokenPasswordExtractor();
            } else if(StringUtils.equals(module, CmpConfiguration.AUTHMODULE_DN_PART_PWD)) {
                return new DnPartPasswordExtractor(parameter);
            }
        }           
        errMsg = "Unrecognized authentication module '" + module + "'";
        return null;
    }

}
