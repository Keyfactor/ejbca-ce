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

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.NativeLongByReference;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.LongRef;
import org.pkcs11.jacknji11.jna.JNA;
import org.pkcs11.jacknji11.jna.JNA_CKM;

/**
 * JNA class extended with additional vendor specific functions like Utimaco
 * CP5.
 */
public class ExtendedJNA extends JNA {
    
    private final ExtendedJNANativeI theNative;
    
    public ExtendedJNA(ExtendedJNANativeI theNative) {
        super(theNative);
        this.theNative = theNative;
    }
    
    private static NativeLong NL(long l) { return new NativeLong(l); }
    private static NativeLongByReference NLP(long l) { return new NativeLongByReference(new NativeLong(l)); }
    
    public long CP5_KeyAuthorizationInit(long hSession, CKM pMechanism, long hKey, byte[] pHash, LongRef pulHashLen) {
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        long rv = theNative.CP5_KeyAuthorizationInit(NL(hSession), jna_pMechanism, NL(hKey), pHash, NLP(pulHashLen.value));
        return rv;
    }

    public long CP5_UnblockKey(long hSession, long hKey) {
        return theNative.CP5_UnblockKey(NL(hSession), NL(hKey));
    }

    public long CP5_KeyAuthorization(long hSession, byte[] pSignature, long ulSignatureLen) {
        return theNative.CP5_KeyAuthorization(NL(hSession), pSignature, NL(ulSignatureLen));
    }

    public long CP5_BackupObject(long session, long objectHandle, Pointer ppBackupObj, LongByReference pulBackupObj) {
        return theNative.CP5_BackupObject(NL(session), NL(objectHandle), ppBackupObj, pulBackupObj);
    }

    public long CP5_RestoreObject(long session, long flags, byte[] bytes, long backupObjLen, LongRef outKindOfInput) {
        return theNative.CP5_RestoreObject(NL(session), NL(flags), bytes, NL(backupObjLen), NLP(outKindOfInput.value));
    }
}
