package org.cesecore.certificates.ocsp.standalone;

import org.cesecore.certificates.ocsp.OcspResponseGeneratorSession;

public interface StandAloneOcspResponseGeneratorSession extends OcspResponseGeneratorSession {

    /**
     * Unlike the standard reloadTokenAndChainCache, this method also takes a password parameter. It's used in the case when the setting
     * ocsp.activation.doNotStorePasswordsInMemory is true, and the cache hence needs to be manually updated. If
     * ocsp.activation.doNotStorePasswordsInMemory, no automatic updating will occur.
     * 
     * @param password Password the keystore.
     */
    void reloadTokenAndChainCache(String password);

}
