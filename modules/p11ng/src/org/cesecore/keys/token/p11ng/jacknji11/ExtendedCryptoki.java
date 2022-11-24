/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token.p11ng.jacknji11;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.LongByReference;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.Cryptoki;
import org.pkcs11.jacknji11.LongRef;

/**
 * Cryptoki class extended with additional vendor specific functions like
 * Utimaco CP5.
 */
public class ExtendedCryptoki extends Cryptoki {

    private final ExtendedJNA jna;

    public ExtendedCryptoki(ExtendedJNA extendedJna) {
        super(extendedJna);
        this.jna = extendedJna;
    }

    public long authorizeKeyInit(long session, CKM mechanism, long key, byte[] hash, LongRef pulHashLen) {
        long rv = jna.CP5_KeyAuthorizationInit(session, mechanism, key, hash, pulHashLen);
        return rv;
    }

    public long authorizeKey(long hSession, byte[] pSignature, long ulSignatureLen) {
        long rv = jna.CP5_KeyAuthorization(hSession, pSignature, ulSignatureLen);
        return rv;
    }

    public long UnblockKey(long session, long hKey) {
        long rv =jna.CP5_UnblockKey(session, hKey);
        return rv;
    }

    public long backupObject(long hSession, long objectHandle, Pointer ppBackupObj, LongByReference pulBackupObj) {
        long rv =jna.CP5_BackupObject(hSession, objectHandle, ppBackupObj, pulBackupObj);
        return rv;
    }

    public long restoreObject(long session, long flags, byte[] backupObj, LongRef objectHandle) {
        long rv =jna.CP5_RestoreObject(session, flags, backupObj, backupObj.length, objectHandle);
        return rv;
    }
}
