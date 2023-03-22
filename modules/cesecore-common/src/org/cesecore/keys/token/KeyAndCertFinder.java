package org.cesecore.keys.token;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Optional;

import org.apache.commons.lang3.tuple.Pair;

import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/** I represent a generic way to find a certificate and key given an ID. */
public interface KeyAndCertFinder {

    Optional<Pair<X509Certificate, PrivateKey>> find(int id) throws CryptoTokenOfflineException;

}
