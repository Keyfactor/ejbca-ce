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
package org.cesecore.certificates.ca;

/**
 * Constants for CAs.
 *
 * @version $Id$
 */
public final class CAConstants {
    /**
     * The state of a node-local CA with a keypair which is neither expired nor revoked.
     * An active CA should be able to create signatures unless the crypto token associated
     * with the CA is offline, in which case healthcheck will fail. A CA stays in this
     * state until the certificate expires or is revoked.
     */
    public static final int CA_ACTIVE = 1;
    /**
     * The state of an external CA where a CSR has been created but the signed
     * certificate has not yet been imported into EJBCA.
     */
    public static final int CA_WAITING_CERTIFICATE_RESPONSE = 2;
    /**
     * The state of a node-local or external CA whose certificate has expired. Once
     * a CA's certificate has expired, it will stay in this state indefinitely.
     */
    public static final int CA_EXPIRED = 3;
    /**
     * The state of a node-local CA with a certificate which has been revoked.
     */
    public static final int CA_REVOKED = 4;
    /**
     * The state of a node-local CA which has been purposely put offline by the user, i.e
     * a CA whose "CA Service State" is "Offline". Healthcheck will be disabled for CAs
     * in this state.
     */
    public static final int CA_OFFLINE = 5;
    /**
     * An external CA without a private key. A CA stays in this state until
     * the certificate expires.
     */
    public static final int CA_EXTERNAL = 6;
    /**
     * The initial state of a CA imported using Statedump. In this state, the CA does not have a keypair. The CA can advance to the
     * CA_WAITING_CERTIFICATE_RESPONSE state if a CSR is created for the CA, or it can advance to the CA_ACTIVE state directly, if
     * a keypair is associated with it.
     */
    public static final int CA_UNINITIALIZED = 7;

    private static final String[] statustexts = {"", "ACTIVE", "WAITINGFORCERTRESPONSE", "EXPIRED", "REVOKED", "OFFLINE","EXTERNALCA", "UNINITIALIZED"};

    /**
     * Prevents creation of new CAConstants
     */
    private CAConstants() {
    }

    /**
     * Constants used in the SignSessionBean indicating the userdata defined CA should be used.
     */
    public static final int CAID_USEUSERDEFINED = 0;

    /** Used in profiles and service workers to make the catch all every CA instead of listing individual CAs when operating on them
     * This is duplicated in SecConst */
    public static final int ALLCAS = 1;

    public static String getStatusText(int status) {
        return statustexts[status];
    }

}