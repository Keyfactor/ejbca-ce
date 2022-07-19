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
import org.pkcs11.jacknji11.jna.JNANativeI;
import org.pkcs11.jacknji11.jna.JNA_CKM;

/**
 * JNANativevI interface extended with additional vendor specific functions like
 * Utimaco CP5.
 */
public interface ExtendedJNANativeI extends JNANativeI {
    public int CP5_KeyAuthorizationInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey, byte[] pHash, NativeLongByReference pulHashLen);
    public int CP5_UnblockKey(NativeLong hSession, NativeLong hKey);
    public long CP5_BackupObject(NativeLong session, NativeLong objectHandle, Pointer backupObj, LongByReference pulBackupObj);
    public long CP5_RestoreObject(NativeLong session, NativeLong flags, byte[] bytes, NativeLong backupObjLen, NativeLongByReference outKindOfInput);
    public long CP5_KeyAuthorization(NativeLong session, byte[] pSignature, NativeLong ulSignatureLen);
}
