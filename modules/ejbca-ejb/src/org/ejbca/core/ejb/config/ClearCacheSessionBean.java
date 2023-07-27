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
package org.ejbca.core.ejb.config;

import java.util.ArrayList;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.certificatetransparency.CertificateTransparencyFactory;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keybind.InternalKeyBindingDataSessionLocal;
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
import org.ejbca.core.ejb.ocsp.OcspResponseGeneratorSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;

import com.keyfactor.util.keys.token.CryptoToken;

/**
 * Session bean for clearing all caches of the local EJBCA instance.
 * 
 * @version $Id$
 */
@Stateless//(mappedName = JndiConstants.APP_JNDI_PREFIX + "ClearCacheSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class ClearCacheSessionBean implements ClearCacheSessionLocal {

    private final static Logger log = Logger.getLogger(ClearCacheSessionBean.class);
    
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

    @Override
    public void clearCaches(final boolean excludeActiveCryptoTokens) {
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
}
