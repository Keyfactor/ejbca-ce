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
package org.ejbca.core.model.services.workers;

import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.audit.log.InternalSecurityEventsLoggerSessionLocal;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;

/**
 * Worker that keeps HSM sessions active.
 * 
 * @version $Id$
 *
 */
public class HsmKeepAliveWorker extends BaseWorker {

    private static final Logger log = Logger.getLogger(HsmKeepAliveWorker.class);

    @Override
    public void work(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        // Health checking will be done in three steps: 
        if (log.isDebugEnabled()) {
            log.debug("Performing HSM Keepalive operation.");
        }
        // 1. If we use Audit log integrity protection, make a test integrity protection calculation
        InternalSecurityEventsLoggerSessionLocal logSession = (InternalSecurityEventsLoggerSessionLocal)ejbs.get(InternalSecurityEventsLoggerSessionLocal.class);
        logSession.auditLogCryptoTest(this.getClass().getSimpleName());

        // 2. Call testKeyPair on all active crypto tokens that has an alias named testKey
        CryptoTokenManagementSessionLocal tokenSession = (CryptoTokenManagementSessionLocal)ejbs.get(CryptoTokenManagementSessionLocal.class);
        List<CryptoTokenInfo> infos = tokenSession.getCryptoTokenInfos(admin);
        if (log.isDebugEnabled()) {
            log.debug("Performing keepalive on all active crypto tokens ("+infos.size()+"), but skipping soft tokens.");
        }
        for (CryptoTokenInfo info : infos) {
            // Only test active, PKCS11, crypto tokens. o need to do keepalive on soft tokens, they will not time out
            if (info.isActive() && StringUtils.isNotEmpty(info.getP11Library())) {
                CryptoToken token = tokenSession.getCryptoToken(info.getCryptoTokenId());
                try {
                    List<String> aliases = token.getAliases();
                    boolean tested = false;
                    for(final String alias : aliases) {
                        if ("testKey".equals(alias)) {
                            if (log.isDebugEnabled()) {
                                log.debug("Keepalive testing crypto token '"+info.getName()+"' with id "+info.getCryptoTokenId());
                            }
                            token.testKeyPair("testKey");
                            tested = true;
                        }
                    }
                    if (!tested) {
                        if (log.isDebugEnabled()) {
                            log.debug("No testKey on crypto token '"+info.getName()+"' with id "+info.getCryptoTokenId());
                        }                        
                    }
                } catch (InvalidKeyException e) {
                    log.info("Error testing crypto token that suppposedly was active: ", e);
                } catch (CryptoTokenOfflineException e) {
                    log.info("Error testing crypto token that suppposedly was active: ", e);
                } catch (KeyStoreException e) {
                    log.info("Error testing crypto token that suppposedly was active: ", e);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Not testing inactive, or soft, crypto token '"+info.getName()+"' with id "+info.getCryptoTokenId());
                }
            }
        }
        
    }
}
