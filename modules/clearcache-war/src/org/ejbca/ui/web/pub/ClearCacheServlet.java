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
 
package org.ejbca.ui.web.pub;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.ejb.EJB;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.certificatetransparency.CertificateTransparencyFactory;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorSessionLocal;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keybind.InternalKeyBindingDataSessionLocal;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.keys.validation.KeyValidatorSessionLocal;
import org.cesecore.roles.management.RoleDataSessionLocal;
import org.cesecore.roles.member.RoleMemberDataSessionLocal;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;

/**
 * Servlet used to clear all caches (Global Configuration Cache, End Entity Profile Cache, 
 * Certificate Profile Cache, Log Configuration Cache, Authorization Cache and CA Cache).
 *
 * @version $Id$
 */
public class ClearCacheServlet extends HttpServlet {

	private static final long serialVersionUID = -8563174167843989458L;
	private static final Logger log = Logger.getLogger(ClearCacheServlet.class);
	
	private static final Set<String> LOCALHOST_IPS = new HashSet<>(Arrays.asList("127.0.0.1", "0:0:0:0:0:0:0:1", "::1"));
	
	@EJB
	private ApprovalProfileSessionLocal approvalprofilesession;
	@EJB
	private AuthorizationSessionLocal authorizationSession;
	@EJB
	private CaSessionLocal caSession;
	@EJB
	private CAAdminSessionLocal caAdminSession;
	@EJB
	private CertificateProfileSessionLocal certificateprofilesession;
	@EJB
	private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CryptoTokenSessionLocal cryptoTokenSession;
    @EJB
    private EndEntityProfileSessionLocal endentitysession;
    @EJB
    private GlobalConfigurationSessionLocal globalconfigurationsession;
    @EJB
    private InternalKeyBindingDataSessionLocal internalKeyBindingDataSession;
    @EJB
    private KeyValidatorSessionLocal keyValidatorSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private OcspResponseGeneratorSessionLocal ocspResponseGeneratorSession;
    @EJB
    private RoleDataSessionLocal roleDataSession;
    @EJB
    private RoleMemberDataSessionLocal roleMemberDataSession;
	
    public void doPost(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse)	throws IOException, ServletException {
    	doGet(httpServletRequest,httpServletResponse);
    }

    public void doGet(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse) throws IOException, ServletException {
        if (log.isTraceEnabled()) {
            log.trace(">doGet()");
        }
        if (StringUtils.equals(httpServletRequest.getParameter("command"), "clearcaches")) {
            final boolean excludeActiveCryptoTokens = StringUtils.equalsIgnoreCase("true", httpServletRequest.getParameter("excludeactivects"));
            if (isLocalhostAddress(httpServletRequest.getRemoteAddr()) || acceptedHost(httpServletRequest.getRemoteHost())) {
                clearCaches(excludeActiveCryptoTokens);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Clear cache request denied from host "+httpServletRequest.getRemoteHost());
                }
                httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "The remote host "+httpServletRequest.getRemoteHost()+" is unknown");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("No clearcaches command (?command=clearcaches) received, returning bad request.");
            }
            httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "No command.");
        }
        if (log.isTraceEnabled()) {
            log.trace("<doGet()");
        }
    }

	private void clearCaches(final boolean excludeActiveCryptoTokens) {
	    // Clear all known global configuration caches
	    for (final String globalConfigurationId : globalconfigurationsession.getIds()) {
	        globalconfigurationsession.flushConfigurationCache(globalConfigurationId);
	        if(log.isDebugEnabled()){
	            if (GlobalConfiguration.GLOBAL_CONFIGURATION_ID.equals(globalConfigurationId)) {
	                log.debug("Global Configuration cache cleared.");
	            } else if (CmpConfiguration.CMP_CONFIGURATION_ID.equals(globalConfigurationId)) {
	                log.debug("CMP Configuration cache cleared.");
	            } else if (ScepConfiguration.SCEP_CONFIGURATION_ID.equals(globalConfigurationId)) {
	                log.debug("SCEP Configuration cache cleared.");
	            } else if (AvailableExtendedKeyUsagesConfiguration.CONFIGURATION_ID.equals(globalConfigurationId)) {
	                log.debug("Available Extended Key Usages Configuration cache cleared.");
	            } else if (AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID.equals(globalConfigurationId)) {
	                log.debug("Available Custom Certificate Extensions Configuration cache cleared.");
	            } else {
	                log.debug(globalConfigurationId + " Configuration cache cleared.");
	            }
	        }
	    }
	    endentitysession.flushProfileCache();
	    if(log.isDebugEnabled()) {
	        log.debug("RA Profile cache cleared");
	    }

	    certificateprofilesession.flushProfileCache();
	    if(log.isDebugEnabled()) {
	        log.debug("Certificate Profile cache cleared");
	    }

	    approvalprofilesession.forceProfileCacheRebuild();
	    if(log.isDebugEnabled()) {
	        log.debug("Approval Profile cache cleared");
	    }

	    authorizationSession.forceCacheExpire();
	    if(log.isDebugEnabled()) {
	        log.debug("Authorization Rule cache cleared");
	    }
	    caSession.flushCACache();
	    if(log.isDebugEnabled()) {
	        log.debug("CA cache cleared");
	    }

	    flushCryptoTokenCache(excludeActiveCryptoTokens);

	    publisherSession.flushPublisherCache();
	    if(log.isDebugEnabled()) {
	        log.debug("Publisher cache cleared");
	    }
	    keyValidatorSession.flushKeyValidatorCache();
	    if(log.isDebugEnabled()) {
	        log.debug("Key Validator cache cleared");
	    }
	    internalKeyBindingDataSession.flushCache();
	    if(log.isDebugEnabled()) {
	        log.debug("InternalKeyBinding cache cleared");
	    }
	    ocspResponseGeneratorSession.reloadOcspSigningCache();
	    if(log.isDebugEnabled()) {
	        log.debug("OCSP signing cache cleared.");
	    }
	    ocspResponseGeneratorSession.reloadOcspExtensionsCache(); // clear CT OCSP response extension cache
	    log.debug("OCSP extensions cache cleared.");
	    if (CertificateTransparencyFactory.isCTAvailable()) {
	        ocspResponseGeneratorSession.clearCTFailFastCache();
	        log.debug("CT caches cleared");
	    }
	    ocspResponseGeneratorSession.clearOcspRequestSignerRevocationStatusCache();
	    if (log.isDebugEnabled()) {
	        log.debug("OCSP request signer revocation status cache cleared.");
	    }
	    certificateStoreSession.reloadCaCertificateCache(); 
	    if(log.isDebugEnabled()) {
	        log.debug("Certificate Store cache cleared and reloaded.");
	    }
	    roleDataSession.forceCacheExpire();
	    if(log.isDebugEnabled()) {
	        log.debug("Role cache cleared.");
	    }
	    roleMemberDataSession.forceCacheExpire();
	    if(log.isDebugEnabled()) {
	        log.debug("Role member cache cleared.");
	    }
    }
	
	private void flushCryptoTokenCache(boolean withExclusion) {
        if (withExclusion) {
            final List<Integer> excludeIDs = new ArrayList<Integer>();
            for (final Integer cryptoTokenId : cryptoTokenSession.getCryptoTokenIds()) {
                final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(cryptoTokenId);
                if (cryptoToken.getTokenStatus()==CryptoToken.STATUS_ACTIVE && !cryptoToken.isAutoActivationPinPresent()) {
                    excludeIDs.add(cryptoTokenId);
                }
            }
            cryptoTokenSession.flushExcludingIDs(excludeIDs);
            if(log.isDebugEnabled()) {
                log.debug("CryptoToken cache cleared except for " + excludeIDs.size() + " specific entries.");
            }
        } else {
            cryptoTokenSession.flushCache();
            if(log.isDebugEnabled()) {
                log.debug("CryptoToken cache cleared");
            }
        }
	}
	
	/** @return true if the provided IP address matches one of commonly knwon localhost IP addresses */
	private boolean isLocalhostAddress(final String remoteAddress) {
        if (log.isTraceEnabled()) {
            log.trace(">isAcceptedAddress: "+remoteAddress);
        }
        if (remoteAddress!=null && LOCALHOST_IPS.contains(remoteAddress)) {
            // Always allow requests from localhost, 127.0.0.1 may not be added in the list
            if (log.isDebugEnabled()) {
                log.debug("Always allowing request from '" + remoteAddress + "'");
            }
            return true;
        }
	    return false;
	}

	private boolean acceptedHost(String remotehost) {
		if (log.isTraceEnabled()) {
			log.trace(">acceptedHost: "+remotehost);
		}    	
		boolean ret = false;
		final GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalconfigurationsession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
		for (final String nodename : globalConfiguration.getNodesInCluster()) {
			try {
			    // Perform reverse DNS lookup.
			    // (In a DDoS scenario, a performance assumption is that these lookups are cached by a local resolver or similar or that this URL path is shielded from hostile networks..)
				String nodeip = InetAddress.getByName(nodename).getHostAddress();
				if (log.isDebugEnabled()) {
					log.debug("Checking remote host against host in list: "+nodename+", "+nodeip);
				}
				// Assume that automatic reverse DNS lookup is disabled in the Servlet container and compare "remotehost" with the IP address we got
				if (StringUtils.equals(remotehost, nodeip)) {
					ret = true;
					break;
				}
			} catch (UnknownHostException e) {
				if (log.isDebugEnabled()) {
					log.debug("Unknown host '"+nodename+"': "+e.getMessage());
				}
			}
		}
		if (log.isTraceEnabled()) {
			log.trace("<acceptedHost: "+ret);
		}
		return ret;
	}
}
