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
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.control.AccessControlSession;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;

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
    private String errorMessage;
    private String confAlias;
    private CmpConfiguration cmpConfiguration;
    private AuthenticationToken admin;
    
    private CaSession caSession;
    private EndEntityAccessSession eeAccessSession;
    private CertificateStoreSession certificateStoreSession;
    private AccessControlSession authorizationSessoin;
    private EndEntityProfileSession eeProfileSession;
    private WebAuthenticationProviderSessionLocal authenticationProviderSession;
    private EndEntityManagementSession eeManagementSession;
    

    public VerifyPKIMessage() {
        this.cainfo = null;
        this.errorMessage = null;
        this.confAlias = null;
        this.cmpConfiguration = null;
        this.admin = null;
        
        this.caSession = null;
        this.eeAccessSession = null;
        this.certificateStoreSession = null;
        this.authorizationSessoin = null;
        this.eeProfileSession = null;
        this.authenticationProviderSession = null;
        this.eeManagementSession = null;
        
    }
    
    public VerifyPKIMessage(final CAInfo cainfo, final String confAlias, final AuthenticationToken admin, final CaSession casession, final EndEntityAccessSession userSession, 
            final CertificateStoreSession certSession, final AccessControlSession authSession, final EndEntityProfileSession eeprofSession, 
            final WebAuthenticationProviderSessionLocal authProvSession, final EndEntityManagementSession endEntityManagementSession, 
            final CmpConfiguration cmpConfig) {
        this.cainfo = cainfo;
        this.errorMessage = null;
        this.confAlias = confAlias;
        this.admin = admin;
        
        this.caSession = casession;
        this.eeAccessSession = userSession;
        this.certificateStoreSession = certSession;
        this.authorizationSessoin = authSession;
        this.eeProfileSession = eeprofSession;
        this.authenticationProviderSession = authProvSession;
        this.eeManagementSession = endEntityManagementSession;
        
        this.cmpConfiguration = cmpConfig;
    }
    
    /**
     * Returns the error message resulted in failing to verify the PKIMessage. The error message  is set in the 
     * getUsedAuthenticationModule() method.
     * 
     * @return the error message as String. Null if the verification succeeded.
     */
    public String getErrorMessage() {
        return this.errorMessage;
    }
    
    /**
     * Verifies the authenticity of msg
     * 
     * @param msg PKIMessage to verify
     * @param username that the PKIMessage should match or null
     * @param authenticated if the CMP message has already been authenticated in another way or not
     * @return The authentication module that succeeded in authenticating msg. Null if message authentication failed using all 
     * configured authentication modules.
     */
    public ICMPAuthenticationModule getUsedAuthenticationModule(final PKIMessage msg, final String username, boolean authenticated) {
        
        final String authModules = this.cmpConfiguration.getAuthenticationModule(this.confAlias);
        final String authparameters = this.cmpConfiguration.getAuthenticationParameters(this.confAlias);
        final String modules[] = authModules.split(";");
        final String params[] = authparameters.split(";");
        
        if(modules.length > params.length) {
            log.error("The number of authentication modules does not match the number of authentication parameters. " +
                    modules.length + " modules - " + params.length + " paramters");
            this.errorMessage = "Configuration error. Please contact the CA administrator";
            return null;
        }
        
        ICMPAuthenticationModule module = null;
        for(int i=0; i<modules.length; i++) {
            if(log.isDebugEnabled()) {
                log.debug("Trying to verify the message using: " + modules[i] );
                log.debug("Authentication module parameter: " + params[i] ); 
            }

            module = getAuthModule(modules[i].trim(), params[i].trim(), msg, authenticated);
            if(module == null) {
                continue;
            }
            
            if(module.verifyOrExtract(msg, username)) {
                log.info("PKIMessage was successfully authenticated using " + module.getName());
                return module;
            } else {
                if(module.getErrorMessage() != null) {
                    errorMessage = module.getErrorMessage();
                }
            }
        }
        
        if(this.errorMessage == null) {
            this.errorMessage = "Failed to authentication PKIMessage using authentication modules: " + authModules;
        }
        
        return null;
    }
    
    /**
     * Returns the authentication module whose name is 'module'
     * 
     * @param module
     * @param parameter
     * @param pkimsg
     * @return The authentication module whose name is 'module'. Null if no such module is implemented.
     */
    private ICMPAuthenticationModule getAuthModule(final String module, final String parameter, final PKIMessage pkimsg, final boolean authenticated) {
        
        if(this.cmpConfiguration.getRAMode(this.confAlias) && (StringUtils.equals(module, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD) || StringUtils.equals(module, CmpConfiguration.AUTHMODULE_DN_PART_PWD))) {
            this.errorMessage = "The authentication module '" + module + "' cannot be used in RA mode";
            log.info(this.errorMessage);
            return null;
        }
        
        if(StringUtils.equals(module, CmpConfiguration.AUTHMODULE_HMAC)) {
            return new HMACAuthenticationModule(admin, parameter, confAlias, cmpConfiguration, cainfo, eeAccessSession);
        } else if(StringUtils.equals(module, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE)) {
            return new EndEntityCertificateAuthenticationModule(admin, parameter, confAlias, cmpConfiguration, authenticated,
                            caSession, certificateStoreSession, authorizationSessoin, eeProfileSession, 
                            eeAccessSession, authenticationProviderSession, eeManagementSession);
        } else if(StringUtils.equals(module, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD)){
            return new RegTokenPasswordExtractor();
        } else if(StringUtils.equals(module, CmpConfiguration.AUTHMODULE_DN_PART_PWD)) {
            return new DnPartPasswordExtractor(parameter);
        }
        
        this.errorMessage = "Unrecognized authentication module: " + module;
        log.info(this.errorMessage);
        return null;
    }

}
