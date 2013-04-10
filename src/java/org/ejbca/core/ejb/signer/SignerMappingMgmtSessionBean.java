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
package org.ejbca.core.ejb.signer;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;

/**
 * Generic Management implementation for SignerMappings.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "SignerMappingMgmtSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class SignerMappingMgmtSessionBean implements SignerMappingMgmtSessionLocal, SignerMappingMgmtSessionRemote {

    //private static final Logger log = Logger.getLogger(SignerMappingDataSessionBean.class);
    private static final InternalResources intres = InternalResources.getInstance();
    
    @EJB
    private AccessControlSessionLocal accessControlSessionSession;
    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLoggerSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private SignerMappingDataSessionLocal signerMappingDataSession;
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<Integer> getSignerMappingIds(AuthenticationToken authenticationToken, String signerMappingType) {
        final List<Integer> allIds = signerMappingDataSession.getSignerMappingIds(signerMappingType);
        final List<Integer> authorizedIds = new ArrayList<Integer>();
        for (final Integer current : allIds) {
            if (accessControlSessionSession.isAuthorizedNoLogging(authenticationToken, SignerMappingRules.VIEW.resource()+"/"+current.toString())) {
                authorizedIds.add(current);
            }
        }
        return authorizedIds;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public SignerMapping getSignerMapping(AuthenticationToken authenticationToken, int signerMappingId) throws AuthorizationDeniedException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, SignerMappingRules.VIEW.resource()+"/"+signerMappingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", SignerMappingRules.VIEW.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        return signerMappingDataSession.getSignerMapping(signerMappingId);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Integer getIdFromName(String signerMappingName) {
        if (signerMappingName==null) {
            return null;
        }
        final Map<String, Integer> cachedNameToIdMap = signerMappingDataSession.getCachedNameToIdMap();
        Integer signerMappingId = cachedNameToIdMap.get(signerMappingName);
        if (signerMappingId == null) {
            // Ok.. so it's not in the cache.. look for it the hard way..
            for (final Integer currentId : signerMappingDataSession.getSignerMappingIds(null)) {
                // Don't lookup CryptoTokens we already have in the id to name cache
                if (!cachedNameToIdMap.keySet().contains(currentId)) {
                    final SignerMapping current = signerMappingDataSession.getSignerMapping(currentId.intValue());
                    final String currentName = current == null ? null : current.getName();
                    if (signerMappingName.equals(currentName)) {
                        signerMappingId = currentId;
                        break;
                    }
                }
            }
        }
        return signerMappingId;
    }

    @Override
    public int persistSignerMapping(AuthenticationToken authenticationToken, SignerMapping signerMapping)
            throws AuthorizationDeniedException, SignerMappingNameInUseException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, SignerMappingRules.MODIFY.resource()+"/"+signerMapping.getId(),
                CryptoTokenRules.USE.resource()+"/"+signerMapping.getCryptoTokenId())) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", SignerMappingRules.MODIFY.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        return signerMappingDataSession.mergeSignerMapping(signerMapping);
    }

    @Override
    public boolean deleteSignerMapping(AuthenticationToken authenticationToken, int signerMappingId) throws AuthorizationDeniedException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, SignerMappingRules.DELETE.resource() + "/" + signerMappingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", SignerMappingRules.DELETE.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        return signerMappingDataSession.removeSignerMapping(signerMappingId);
    }

    // TODO: Support next key alias + counter
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public byte[] getNextPublicKeyForSignerMapping(AuthenticationToken authenticationToken, int signerMappingId) throws AuthorizationDeniedException, CryptoTokenOfflineException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, SignerMappingRules.VIEW.resource() + "/" + signerMappingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", SignerMappingRules.VIEW.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        final SignerMapping signerMapping = signerMappingDataSession.getSignerMapping(signerMappingId);
        final int cryptoTokenId = signerMapping.getCryptoTokenId();
        final String currentKeyPairAlias = signerMapping.getKeyPairAlias();
        final PublicKey publicKey = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, currentKeyPairAlias);
        // TODO: DERify it for remote calls..
        throw new UnsupportedOperationException("Not yet fully implemented!");
    }

    @Override
    public void importCertificateForSignerMapping(AuthenticationToken authenticationToken, int signerMappingId, byte[] derEncodedCertificate)
            throws AuthorizationDeniedException, CertificateImportException {
        if (!accessControlSessionSession.isAuthorized(authenticationToken, SignerMappingRules.MODIFY.resource() + "/" + signerMappingId)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", SignerMappingRules.MODIFY.resource(), authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        final SignerMapping signerMapping = signerMappingDataSession.getSignerMapping(signerMappingId);
        signerMapping.assertCertificateCompatability(derEncodedCertificate);
        // UnDERify
        // Check if current key matches current public key -> import + update signerMapping.certificateId
        // Check if current key matches next public key -> import and update nextKey + signerMapping.certificateId
        throw new UnsupportedOperationException("Not yet fully implemented!");
    }
}
