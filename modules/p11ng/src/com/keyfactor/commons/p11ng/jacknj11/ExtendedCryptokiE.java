/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons - Proprietary Modules:                             *
 *                                                                       *
 *  Copyright (c), Keyfactor Inc. All rights reserved.                   *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.commons.p11ng.jacknj11;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.LongByReference;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.CKRException;
import org.pkcs11.jacknji11.CryptokiE;
import org.pkcs11.jacknji11.LongRef;

/**
 * CryptokiE class extended with additional vendor specific functions like
 * Utimaco CP5.
 */
public class ExtendedCryptokiE extends CryptokiE {

    private final ExtendedCryptoki c;

    public ExtendedCryptokiE(ExtendedCryptoki extendedCryptoki) {
        super(extendedCryptoki);
        this.c = extendedCryptoki;
    }

    public long authorizeKeyInit(long session, CKM mechanism, long key, byte[] hash, LongRef pulHashLen) {
        return c.authorizeKeyInit(session, mechanism, key, hash, pulHashLen);
    }

    public long authorizeKey(long session, byte[] pSignature, long ulSignatureLen) {
        return c.authorizeKey(session, pSignature, ulSignatureLen);
    }

    public long unblockKey(long session, long hKey) {
        return c.UnblockKey(session, hKey);
    }

    public void backupObject(long session, long objectHandle, Pointer ppBackupObj, LongByReference pulBackupObj) {
        long rv = c.backupObject(session, objectHandle, ppBackupObj, pulBackupObj);
        if (rv != CKR.OK) throw new CKRException(rv);
    }

    public void restoreObject(long session, long flags, byte[] backupObj, long objectHandle) {
        long rv = c.restoreObject(session, flags, backupObj, new LongRef(objectHandle));
        if (rv != CKR.OK) throw new CKRException(rv);
    }

}
