/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package sun.security.pkcs11;

import static sun.security.pkcs11.wrapper.PKCS11Constants.CKA_SENSITIVE;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKA_ALWAYS_SENSITIVE;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKA_PRIVATE;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKA_EXTRACTABLE;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKA_NEVER_EXTRACTABLE;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKA_DERIVE;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKA_MODIFIABLE;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKR_ATTRIBUTE_READ_ONLY;
import static sun.security.pkcs11.wrapper.PKCS11Constants.FALSE;

import java.security.Key;
import java.security.Provider;
import java.security.Security;

import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;

/**
 * Extra utilities extending the sun PKCS#11 implementation.
 * @version $Id$
 *
 */
public class CESeCoreUtils {
    /**
     * Sets the CKA_MODIFIABLE attribute of a key object to false.
     * @param providerName The registered name of the provider. If the provider is not an instance of {@link SunPKCS11} then nothing will be done.
     * @param key The key object. If the object is not an instance of {@link P11Key} then nothing will be done.
     * @return true if {@link SunPKCS11} provider and {@link P11Key} key and CKA_MODIFIABLE is not already modified and was actually modified.
     * @throws PKCS11Exception
     */
    public static boolean makeKeyUnmodifiable(final String providerName, final Key key) throws PKCS11Exception {
        final KeyData d = KeyData.getIt(providerName, key);
        if ( d==null ) {
            return false;
        }
        if ( isModifiable(d) ) {
            return setUnModifiable(d); // Returns false if the value could not be modified
        }
        return true;
    }
    /**
     * Check if the attribute CKA_MODIFIABLE is true.
     * @param providerName The registered name of the provider. If the provider is not an instance of {@link SunPKCS11} then false is returned.
     * @param key The key object. If the object is not an instance of {@link P11Key} then false is returned.
     * @return true if the attribute is false.
     * @throws PKCS11Exception
     */
    public static boolean isKeyModifiable(final String providerName, final Key key) throws PKCS11Exception {
        final KeyData d = KeyData.getIt(providerName, key);
        if ( d==null ) {
            return true;
        }
        return isModifiable(d);
    }
    /**
     * Writes info about security related attributes.
     * @param providerName The registered name of the provider. If the provider is not an instance of {@link SunPKCS11} then false is returned.
     * @param key The key object. If the object is not an instance of {@link P11Key} then false is returned.
     * @param sb Buffer to write to.
     * @throws PKCS11Exception
     */
    public static void securityInfo(final String providerName, final Key key, final StringBuilder sb) throws PKCS11Exception {
        final KeyData d = KeyData.getIt(providerName, key);
        if ( d==null ) {
            sb.append("Not a PKCS#11 key.");
            return;
        }
        final CK_ATTRIBUTE attrs[] = {
                new CK_ATTRIBUTE(CKA_SENSITIVE),
                new CK_ATTRIBUTE(CKA_ALWAYS_SENSITIVE),
                new CK_ATTRIBUTE(CKA_EXTRACTABLE),
                new CK_ATTRIBUTE(CKA_NEVER_EXTRACTABLE),
                new CK_ATTRIBUTE(CKA_PRIVATE),
                new CK_ATTRIBUTE(CKA_DERIVE),
                new CK_ATTRIBUTE(CKA_MODIFIABLE)
                };
        d.p11.C_GetAttributeValue(d.sessionID, d.keyID, attrs);
        for ( final CK_ATTRIBUTE attr : attrs ) {
            sb.append("  ");
            sb.append(attr.toString());
        }
    }
    private static class KeyData {
        final public long keyID;
        final public long sessionID;
        final public PKCS11 p11;
        private KeyData( final long _keyID, final long _sessionID, final PKCS11 _p11) {
            this.keyID = _keyID;
            this.sessionID = _sessionID;
            this.p11 = _p11;
        }
        public static KeyData getIt(final String providerName, final Key key) throws PKCS11Exception {
            if ( providerName==null || key==null || !(key instanceof P11Key) ) {
                return null;
            }
            final SunPKCS11 sunP11Provider;
            {
                final Provider provider = Security.getProvider(providerName);
                if ( provider==null || !(provider instanceof SunPKCS11) ) {
                    return null;
                }
                sunP11Provider = (SunPKCS11)provider;
            }
            final P11Key sunP11Key = (P11Key)key;
            final Token token = sunP11Provider.getToken();
            final long keyID = sunP11Key.keyID;
            final long sessionID = token.getObjSession().id();
            final PKCS11 p11 = token.p11;
            return new KeyData( keyID, sessionID, p11);
        }
    }
    private static boolean isModifiable(final KeyData d) throws PKCS11Exception {
        final CK_ATTRIBUTE attrs[] = { new CK_ATTRIBUTE(CKA_MODIFIABLE) };
        d.p11.C_GetAttributeValue(d.sessionID, d.keyID, attrs);
        return attrs[0].getBoolean();
    }
    private static boolean setUnModifiable(final KeyData d) throws PKCS11Exception {
        final CK_ATTRIBUTE attrs[] = { new CK_ATTRIBUTE(CKA_MODIFIABLE, FALSE) };
        try {
            d.p11.C_SetAttributeValue(d.sessionID, d.keyID, attrs);
        } catch (PKCS11Exception e) {
            if ( e.getErrorCode()==CKR_ATTRIBUTE_READ_ONLY ) {
                return false;// Unfortunate not possible to set attribute with p11
            }
            throw e;
        }
        return true;
    }
}
