package org.cesecore.keybind;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Optional;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.keybind.impl.AuthenticationKeyBinding;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.KeyAndCertFinder;

import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 * I implement a way to find keys and certs given a binding ID using EJBs.
 */
public class KeyBindingFinder implements KeyAndCertFinder {
    private static final Logger log = Logger.getLogger(KeyAndCertFinder.class);
    private InternalKeyBindingMgmtSessionLocal internalKeyBindings;
    private CertificateStoreSessionLocal certificateStoreSession;
    private CryptoTokenManagementSessionLocal cryptoToken;

    public KeyBindingFinder(final InternalKeyBindingMgmtSessionLocal internalKeyBindings, final CertificateStoreSessionLocal certificateStoreSession,
            final CryptoTokenManagementSessionLocal cryptoToken) {
        this.internalKeyBindings = internalKeyBindings;
        this.certificateStoreSession = certificateStoreSession;
        this.cryptoToken = cryptoToken;
    }

    @Override
    public Optional<Pair<X509Certificate, PrivateKey>> find(final int keyBindingId) throws CryptoTokenOfflineException {
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
        final CryptoToken token = cryptoToken.getCryptoToken(keyBindingInfo.get().getCryptoTokenId());
        final PrivateKey privateKey = token.getPrivateKey(keyBindingInfo.get().getKeyPairAlias());

        return Optional.of(Pair.of(certificate, privateKey));
    }
}
