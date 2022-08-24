/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.token.p11ng.provider;

import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.LongRef;

import java.util.List;
import java.util.Optional;

/**
 * <p>An interface for the Cryptoki API.
 *
 * <p>Makes it possible to plug in different implementations of PKCS#11.
 *
 * @see <a href="http://docs.oasis-open.org/pkcs11/">PKCS #11 Cryptographic Token Interface Base Specification</a>
 */
interface CryptokiFacade {
    /**
     * Clears any caches that the CryptokiFacade implementation may have
     */
    void clear();
    
    /**
     * C_FindObjects, first removes expired cache entries, then looks for objects in the cache and if expired look in the underlying API, updating the cache.
     *
     * @param session session handle.
     * @param ckas the attributes to use when searching for objects in the HSM.
     * @return a list of object handles to objects with the specified attributes.
     */
    List<Long> findObjects(long session, CKA... ckas);

    /**
     * C_FindObjects, In Cache, looks for objects in the object cache only, does not pass on to underlying API and does not expire cache entries.
     *
     * @param session session handle.
     * @param ckas the attributes to use when searching for objects in the HSM.
     * @return an <code>Optional</code> list of object handles to objects with the specified attributes,
     * if <code>Optional.isPresent</code> a value was present in the cache (even if it's an empty list) and
     * if <code>!Optional.isPresent</code>, nothing was available in the cache.
     */
    Optional<List<Long>> findObjectsInCache(long session, CKA... ckas);

    /** 
     * C_DestroyObject.
     *
     * @param session session handle.
     * @param objectRef object handle.
     */
    void destroyObject(long session, long objectRef);

    /**
     * C_GetAttributeValue.
     * 
     * @param session session handle.
     * @param objectRef object handle of an object for which you want to get the attribute value.
     * @param cka the attribute to read.
     * @return the attribute.
     */
    CKA getAttributeValue(final long session, final long objectRef, final long cka);

    /**
     * C_Logout.
     *
     * @param session session handle for the session you want to log out from.
     */
    void logout(long session);

    /**
     * C.GenerateKeyPair.
     *
     * @param session session handle.
     * @param mechanism the mechanism to use for key generation
     * @param publicKeyTemplate attribute template for the public key.
     * @param privateKeyTemplate attribute template for the private key.
     * @param publicKey reference to the public key which will be generated inside the HSM.
     * @param privateKey reference to the private key which will be generated inside the HSM.
     */
    void generateKeyPair(long session, CKM mechanism, CKA[] publicKeyTemplate, CKA[] privateKeyTemplate, LongRef publicKey, LongRef privateKey);

    /**
     * C.GenerateKey.
     *
     * @param session session handle.
     * @param mechanism the mechanism to use for key generation
     * @param secretKeyTemplate template for the new key
     * @param secretKey reference to the secret key which will be generated inside the HSM.
     */
    void generateKey(long session, CKM mechanism, CKA[] secretKeyTemplate, LongRef secretKey);

    /**
     * C_CreateObject
     *
     * @param session session handle.
     * @param template attribute template for the new object
     * @return an object handle for the new object
     */
    long createObject(long session, CKA... template);
}

