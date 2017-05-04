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
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationSession;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;

/**
 * Verifies a CMP message using a suitable authentication module.
 * 
 * The authentication modules are specified as properties in the CmpConfiguration.
 * 
 * @version $Id$
 */
public class VerifyPKIMessage {
    
    private static final Logger log = Logger.getLogger(VerifyPKIMessage.class);
    
    private final CAInfo caInfo;
    private String errorMessage = null;
    private final String confAlias;
    private final CmpConfiguration cmpConfiguration;
    private final AuthenticationToken authenticationToken;
    
    private final CaSession caSession;
    private final EndEntityAccessSession endEntityAccessSession;
    private final CertificateStoreSession certificateStoreSession;
    private final AuthorizationSession authorizationSession;
    private final EndEntityProfileSession endEntityProfileSession;
    private final CertificateProfileSession certificateProfileSession;
    private final WebAuthenticationProviderSessionLocal authenticationProviderSession;
    private final EndEntityManagementSession endEntityManagementSession;

    public VerifyPKIMessage(final CAInfo cainfo, final String confAlias, final AuthenticationToken admin, final CaSession caSession, final EndEntityAccessSession endEntityAccessSession, 
            final CertificateStoreSession certificateStoreSession, final AuthorizationSession authorizationSession, final EndEntityProfileSession endEntityProfileSession, final CertificateProfileSession certificateProfileSession,  
            final WebAuthenticationProviderSessionLocal authenticationProviderSession, final EndEntityManagementSession endEntityManagementSession, 
            final CmpConfiguration cmpConfiguration) {
        this.caInfo = cainfo;
        this.confAlias = confAlias;
        this.authenticationToken = admin;
        this.caSession = caSession;
        this.endEntityAccessSession = endEntityAccessSession;
        this.certificateStoreSession = certificateStoreSession;
        this.authorizationSession = authorizationSession;
        this.endEntityProfileSession = endEntityProfileSession;
        this.certificateProfileSession = certificateProfileSession;
        this.authenticationProviderSession = authenticationProviderSession;
        this.endEntityManagementSession = endEntityManagementSession;
        this.cmpConfiguration = cmpConfiguration;
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
     * Verifies the authenticity of the PKIMessage
     * 
     * @param pkiMessage PKIMessage to verify
     * @param username that the PKIMessage should match or null
     * @param authenticated if the CMP message has already been authenticated in another way or not
     * @return The authentication module that succeeded in authenticating msg. Null if message authentication failed using all 
     * configured authentication modules.
     */
    public ICMPAuthenticationModule getUsedAuthenticationModule(final PKIMessage pkiMessage, final String username, boolean authenticated) {
        final String authModules = this.cmpConfiguration.getAuthenticationModule(this.confAlias);
        final String authparameters = this.cmpConfiguration.getAuthenticationParameters(this.confAlias);
        final String modules[] = authModules.split(";");
        final String params[] = authparameters.split(";");
        if (modules.length != params.length) {
            log.error("The number of authentication modules does not match the number of authentication parameters. " +
                    modules.length + " modules - " + params.length + " paramters");
            this.errorMessage = "CMP module configuration error.";
            return null;
        }
        boolean raMode = this.cmpConfiguration.getRAMode(this.confAlias);
        for (int i=0; i<modules.length; i++) {
            final String moduleName = modules[i].trim();
            final String moduleParameter = params[i].trim();
            if (log.isDebugEnabled()) {
                log.debug("Trying to verify the message using CMP authentication module '" + moduleName + "' with parameter '" + moduleParameter + "'");
            }
            final ICMPAuthenticationModule module = getAuthModule(raMode, moduleName, moduleParameter, pkiMessage, authenticated);
            if (module != null) {
                if (module.verifyOrExtract(pkiMessage, username)) {
                    log.info("PKIMessage was successfully authenticated using " + module.getName());
                    return module;
                } else {
                    if (module.getErrorMessage() != null) {
                        errorMessage = module.getErrorMessage();
                    }
                }
            }
        }
        if (this.errorMessage == null) {
            this.errorMessage = "Failed to authentication PKIMessage using authentication modules: " + authModules;
        }
        return null;
    }
    
    /** @return The requested authentication module or null if no such module is implemented. */
    private ICMPAuthenticationModule getAuthModule(final boolean raMode, final String module, final String parameter, final PKIMessage pkiMessage, final boolean authenticated) {
        switch (module) {
        case CmpConfiguration.AUTHMODULE_HMAC:
            return new HMACAuthenticationModule(authenticationToken, parameter, confAlias, cmpConfiguration, caInfo, endEntityAccessSession);
        case CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE:
            return new EndEntityCertificateAuthenticationModule(authenticationToken, parameter, confAlias, cmpConfiguration, authenticated,
                    caSession, certificateStoreSession, authorizationSession, endEntityProfileSession, certificateProfileSession,
                    endEntityAccessSession, authenticationProviderSession, endEntityManagementSession);
        case CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD:
            if (raMode) {
                this.errorMessage = "The authentication module '" + module + "' cannot be used in RA mode";
                break;
            }
            return new RegTokenPasswordExtractor();
        case CmpConfiguration.AUTHMODULE_DN_PART_PWD:
            if (raMode) {
                this.errorMessage = "The authentication module '" + module + "' cannot be used in RA mode";
                break;
            }
            return new DnPartPasswordExtractor(parameter);
        default:
            this.errorMessage = "Unrecognized authentication module: " + module;
        }
        log.info(this.errorMessage);
        return null;
    }
}
