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
 
package org.cesecore.keybind;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.keybind.impl.AuthenticationKeyBinding;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.KeyAndCertFinder;
import org.cesecore.keys.token.KeyAndCertificateInfo;
import org.ejbca.core.model.util.EjbLocalHelper;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 * Gives a way to find keys and certs given a binding ID using EJBs.
 */
public class KeyBindingFinder implements KeyAndCertFinder {
    private static final Logger log = Logger.getLogger(KeyAndCertFinder.class);
    private final InternalKeyBindingMgmtSessionLocal internalKeyBindings;
    private final CertificateStoreSessionLocal certificateStoreSession;
    private final CryptoTokenManagementSessionLocal cryptoTokenSession;
    private final CaSessionLocal caSession;

    public KeyBindingFinder() {
        this.internalKeyBindings = new EjbLocalHelper().getInternalKeyBindingMgmtSession();
        this.certificateStoreSession = new EjbLocalHelper().getCertificateStoreSession();
        this.cryptoTokenSession = new EjbLocalHelper().getCryptoTokenManagementSession();
        this.caSession = new EjbLocalHelper().getCaSession();
        
    }

    public Optional<KeyAndCertificateInfo> find(final int keyBindingId) throws CryptoTokenOfflineException {
        log.debug("Searching for internal key binding " + keyBindingId);
        if (log.isDebugEnabled()) {
            internalKeyBindings.getAllInternalKeyBindingInfos(AuthenticationKeyBinding.IMPLEMENTATION_ALIAS).forEach(b -> {
                log.debug(String.format("Key binding -> name:$s cert:$s token:$d", b.getName(), b.getCertificateId(), b.getCryptoTokenId()));
            });
        }
        final Optional<InternalKeyBindingInfo> keyBindingInfo = internalKeyBindings
                .getAllInternalKeyBindingInfos(AuthenticationKeyBinding.IMPLEMENTATION_ALIAS).stream().filter(i -> i.getId() == keyBindingId)
                .findFirst();
        if (!keyBindingInfo.isPresent()) {
            return Optional.empty();
        }

        final X509Certificate certificate = (X509Certificate) certificateStoreSession
                .findCertificateByFingerprint(keyBindingInfo.get().getCertificateId());
        final CryptoToken token = cryptoTokenSession.getCryptoToken(keyBindingInfo.get().getCryptoTokenId());
        final PrivateKey privateKey = token.getPrivateKey(keyBindingInfo.get().getKeyPairAlias());
        
        final CAInfo caInfo = caSession.getCAInfoInternal(CertTools.getIssuerDN(certificate).hashCode());
        final List<X509Certificate> chain = caInfo.getCertificateChain().stream().map(element -> (X509Certificate) element)
                .collect(Collectors.toList());

        return Optional.of(new KeyAndCertificateInfo(privateKey, certificate, chain));
    }
}
