/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.cli;

import java.lang.reflect.InvocationTargetException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;

import sun.security.x509.CertAndKeyGen;
import sun.security.x509.X500Name;

/**
 * @author lars
 * @version $Id: KeyTool.java,v 1.3 2006-08-28 06:46:12 primelars Exp $
 *
 */
public class KeyTool {
    private static String GENERATE_SWITCH = "generate";
    private static String DELETE_SWITCH = "delete";
    /**
     * @param args
     */
    public static void main(String[] args) {
        // Initialize the TokenManager class
        /*
           This class is used for general access to the Luna HSM and is not
           part of the normal JCE/JCA.  This class is required to access the
           HSM as it contains the methods for logging in and out of the HSM
           and slot/token management.

           See the Luna developers reference guide for information on
           alternatives to using the LunaTokenManager class.
        */
        if ( args.length > 1 && args[1].toLowerCase().trim().equals(GENERATE_SWITCH)) {
            if ( args.length < 6 )
                System.err.println(args[0] + " " + args[1] + " <key entry name> <key size>");
            else
                generate(args[2], args[3], args[4], Integer.parseInt(args[5].trim()));
        } else if ( args.length > 1 && args[1].toLowerCase().trim().equals(DELETE_SWITCH)) {
            if ( args.length < 5 )
                System.err.println(args[0] + " " + args[1] + " <key entry name>");
            else
                delete(args[2], args[3], args[4]);
        } else
            System.err.println("Use \"" + args[0]+" "+GENERATE_SWITCH+"\" or \"" +
                               args[0]+" "+DELETE_SWITCH+"\".");
     }
    private static String loadProvider( String className ) throws IllegalArgumentException, SecurityException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException, ClassNotFoundException {
        final Provider provider = (Provider)Class.forName(className).getConstructor(new Class[0]).newInstance(new Class[0]);
        Security.addProvider(provider);
        return provider.getName();
    }
    private static void generate(final String providerClassName,
                                 final String keyStoreName,
                                 final String keyEntryName,
                                 final int keySize) {
        try {
            // Generate the RSA Keypair
            final String keyAlgName = "RSA";
            final String sigAlgName = "SHA1withRSA";
            final String providerName = loadProvider(providerClassName);
            final CertAndKeyGen keyPair = new CertAndKeyGen(keyAlgName, sigAlgName, providerName);
            keyPair.generate(keySize);
            X509Certificate[] chain = new X509Certificate[1];
            chain[0] = keyPair.getSelfCertificate(new X500Name("CN=some guy, L=around, C=US"), (long)30*24*60*60*365);
            final KeyStore ks = KeyStore.getInstance(keyStoreName, providerName);
            System.err.println("Storing certificate with entry "+keyEntryName+" via KeyStore.");
            ks.setKeyEntry(keyEntryName, keyPair.getPrivateKey(), null, chain);
            ks.store(System.out, null);
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }
    }
    private static void delete(final String providerClassName,
                               final String keyStoreName,
                               final String keyEntryName) {
        try {
            final String providerName = loadProvider(providerClassName);
            final KeyStore ks = KeyStore.getInstance(keyStoreName, providerName);
            ks.load(System.in, null);
            // Save the Certificate to the Luna KeyStore
            System.err.println("Deleting certificate with entry "+keyEntryName+" via KeyStore");
            ks.deleteEntry(keyEntryName);
            ks.store(System.out, null);
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }
    }
}
