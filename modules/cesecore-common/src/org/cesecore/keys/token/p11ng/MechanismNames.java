/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token.p11ng;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.pkcs11.jacknji11.C;
import org.pkcs11.jacknji11.CKG;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.ULong;

/**
 * Handles mapping between PKCS#11 mechanism constant names and values.
 */
public class MechanismNames {

    private static final Map<Long, String> L2S = C.createL2SMap(CKM.class);
    private static final Map<String, Long> S2L;
    private static final Map<String, Long> SIGALGOS2L;
    public static final Map<Long, byte[]> CKM_PARAMS;
    private static final Map<String, Long> ENCALGOS2L;
    
    static {
        S2L = new HashMap<>(L2S.size());
        for (Map.Entry<Long, String> entry : L2S.entrySet()) {
            S2L.put(entry.getValue(), entry.getKey());
        }

        SIGALGOS2L = new HashMap<>();
        SIGALGOS2L.put("NONEwithRSA", CKM.RSA_PKCS);
        SIGALGOS2L.put("MD5withRSA", CKM.MD5_RSA_PKCS);
        SIGALGOS2L.put("SHA1withRSA", CKM.SHA1_RSA_PKCS);
        SIGALGOS2L.put("SHA224withRSA", CKM.SHA224_RSA_PKCS);
        SIGALGOS2L.put("SHA256withRSA", CKM.SHA256_RSA_PKCS);
        SIGALGOS2L.put("SHA384withRSA", CKM.SHA384_RSA_PKCS);
        SIGALGOS2L.put("SHA512withRSA", CKM.SHA512_RSA_PKCS);
        SIGALGOS2L.put("NONEwithDSA", CKM.DSA);
        SIGALGOS2L.put("SHA1withDSA", CKM.DSA_SHA1);
        SIGALGOS2L.put("SHA1withRSAandMGF1", CKM.SHA1_RSA_PKCS_PSS);
        SIGALGOS2L.put("SHA256withRSAandMGF1", CKM.SHA256_RSA_PKCS_PSS);
        SIGALGOS2L.put("SHA384withRSAandMGF1", CKM.SHA384_RSA_PKCS_PSS);
        SIGALGOS2L.put("SHA512withRSAandMGF1", CKM.SHA512_RSA_PKCS_PSS);
        SIGALGOS2L.put("SHA224withECDSA", CKM.ECDSA);
        SIGALGOS2L.put("SHA256withECDSA", CKM.ECDSA);
        SIGALGOS2L.put("SHA384withECDSA", CKM.ECDSA);
        SIGALGOS2L.put("SHA512withECDSA", CKM.ECDSA);
        SIGALGOS2L.put("Ed25519", CKM.EDDSA);
        SIGALGOS2L.put("Ed448", CKM.EDDSA);
        
        CKM_PARAMS = new HashMap<>();
        CKM_PARAMS.put(CKM.SHA1_RSA_PKCS_PSS, ULong.ulong2b(new long[]{CKM.SHA_1, CKG.MGF1_SHA1, 20}));
        CKM_PARAMS.put(CKM.SHA256_RSA_PKCS_PSS, ULong.ulong2b(new long[]{CKM.SHA256, CKG.MGF1_SHA256, 32}));
        CKM_PARAMS.put(CKM.SHA384_RSA_PKCS_PSS, ULong.ulong2b(new long[]{CKM.SHA384, CKG.MGF1_SHA384, 48}));
        CKM_PARAMS.put(CKM.SHA512_RSA_PKCS_PSS, ULong.ulong2b(new long[]{CKM.SHA512, CKG.MGF1_SHA512, 64}));

        ENCALGOS2L = new HashMap<>();
        ENCALGOS2L.put(PKCSObjectIdentifiers.rsaEncryption.getId(), CKM.RSA_PKCS);

    }

    /**
     * Convert long constant value to name.
     * @param l constant value
     * @return name of constant or hexadecimal value if unknown
     */
    public static String nameFromLong(long l) {
        String s = L2S.get(l);
        if (s == null) {
            return String.format("0x%08x", l);
        } else {
            return "CKM_" + s;
        }
    }

    /**
     * The the long value from the name.
     * @param name to get long value for
     * @return long value or null if unknown
     */
    public static Long longFromName(String name) {
        return S2L.get(name);
    }

    /**
     * Provides the long value for signature algorithm name.
     *
     * @param name to get long value for
     * @return long value or empty if unknown
     */
    public static Optional<Long> longFromSigAlgoName(final String name) {
        if (SIGALGOS2L.get(name) != null) {
            return Optional.of(SIGALGOS2L.get(name));
        } else {
            return Optional.empty();
        }
    }

    /**
     * Provides the long value for encryption algorithm name/oid.
     *
     * @param name to get long value for
     * @return long value or empty if unknown
     */
    public static Optional<Long> longFromEncAlgoName(final String name) {
        if (ENCALGOS2L.get(name) != null) {
            return Optional.of(ENCALGOS2L.get(name));
        } else {
            return Optional.empty();
        }
    }

}
