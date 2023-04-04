/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons - Proprietary Modules:                             *
 *                                                                       *
 *  Copyright (c), Keyfactor Inc. All rights reserved.                   *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package com.keyfactor.commons.p11ng.provider;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.LongRef;

import com.keyfactor.commons.p11ng.jacknj11.ExtendedCryptokiE;

import static java.util.stream.Collectors.toList;

/**
 * An implementation of {@link CryptokiFacade} dispatching PKCS#11 calls to JackNJI.
 *
 * @see <a href="https://github.com/joelhockey/jacknji11">JackNJI on GitHub</a>
 */
class CryptokiWithoutCache implements CryptokiFacade {
    private final ExtendedCryptokiE api;

    /**
     * @param api the underlying PKCS#11 API
     */
    CryptokiWithoutCache(final ExtendedCryptokiE api) {
        this.api = api;
    }

    @Override
    public void clear() {
    }

    @Override
    public List<Long> findObjects(final long session, final CKA... ckas) {
        return Arrays.stream(api.FindObjects(session, ckas)).boxed().collect(toList());
    }

    @Override
    public Optional<List<Long>> findObjectsInCache(final long session, final CKA... ckas) {
        // This does not do caching at all
        return Optional.of(new ArrayList<>());
    }

    @Override
    public void destroyObject(long session, long objectRef) {
        api.DestroyObject(session, objectRef);
    }

    @Override
    public CKA getAttributeValue(final long session, final long objectRef, final long cka) {
        return api.GetAttributeValue(session, objectRef, cka);
    }

    @Override
    public void logout(long session) {
        api.Logout(session);
    }

    @Override
    public void generateKeyPair(long session, CKM mechanism, CKA[] publicKeyTemplate, CKA[] privateKeyTemplate, LongRef publicKey, LongRef privateKey) {
        api.GenerateKeyPair(session, mechanism, publicKeyTemplate, privateKeyTemplate, publicKey, privateKey);
    }

    @Override
    public void generateKey(long session, CKM mechanism, CKA[] secretKeyTemplate, LongRef secretKey) {
        api.GenerateKey(session, mechanism, secretKeyTemplate, secretKey);
    }

    @Override
    public long createObject(long session, CKA... template) {
        return api.CreateObject(session, template);
    }
}
