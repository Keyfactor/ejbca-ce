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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.x509.X509V3CertificateGenerator;

/**
 * @author lars
 * @version $Id: KeyTool.java,v 1.4 2006-08-28 14:00:59 primelars Exp $
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
        if ( args.length > 1 && args[1].toLowerCase().trim().equals(GENERATE_SWITCH)) {
            if ( args.length < 5 )
                System.err.println(args[0] + " " + args[1] + " <key size> [<key entry name>]");
            else
                generate(args[2], args[3], Integer.parseInt(args[4].trim()), args.length>6 ? args[5] :null, args.length>6 ? args[6] : "myKey");
        } else if ( args.length > 1 && args[1].toLowerCase().trim().equals(DELETE_SWITCH)) {
            if ( args.length < 4 )
                System.err.println(args[0] + " " + args[1] + " <key entry name>");
            else
                delete(args[2], args[3]);
        } else
            System.err.println("Use \"" + args[0]+" "+GENERATE_SWITCH+"\" or \"" +
                               args[0]+" "+DELETE_SWITCH+"\".");
     }
    private static String getProviderName( String className ) throws IllegalArgumentException, SecurityException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException, ClassNotFoundException {
        Provider provider = (Provider)Class.forName(className).getConstructor(new Class[0]).newInstance(new Class[0]);
        Security.addProvider(provider);
        return provider.getName();
    }
    private static X509Certificate getSelfCertificate (String myname,
                                                       long validity,
                                                       String sigAlg,
                                                       KeyPair keyPair,
                                                       String providerName) throws CertificateException, InvalidKeyException,
                                                       SignatureException, NoSuchAlgorithmException, NoSuchProviderException {
        final long currentTime = new Date().getTime();
        final Date firstDate = new Date(currentTime-24*60*60*1000);
        final Date lastDate = new Date(currentTime + validity * 1000);
        X509V3CertificateGenerator cg = new X509V3CertificateGenerator();
        // Add all mandatory attributes
        cg.setSerialNumber(BigInteger.valueOf(firstDate.getTime()));
        cg.setSignatureAlgorithm(sigAlg);
        cg.setSubjectDN(new X500Principal(myname));
        cg.setPublicKey(keyPair.getPublic());
        cg.setNotBefore(firstDate);
        cg.setNotAfter(lastDate);
        cg.setIssuerDN(new X500Principal(myname));
        return cg.generateX509Certificate(keyPair.getPrivate(), providerName);
    }
    private static KeyPair generate( final String provider,
                                     final String algName,
                                     final int size) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algName, provider);
        kpg.initialize(size);
        return kpg.generateKeyPair();
    }
    private static void generate(final String providerClassName,
                                 final String keyStoreName,
                                 final int keySize,
                                 final String passPrase,
                                 final String keyEntryName) {
        try {
            // Generate the RSA Keypair
            final String keyAlgName = "RSA";
            final String sigAlgName = "SHA1withRSA";
            final String providerName = getProviderName(providerClassName);
            final KeyPair keyPair = generate(providerName, keyAlgName, keySize);
            X509Certificate[] chain = new X509Certificate[1];
            chain[0] = getSelfCertificate("CN=some guy, L=around, C=US",
                                          (long)30*24*60*60*365, sigAlgName, keyPair,
                                          providerName);
            final KeyStore ks = KeyStore.getInstance(keyStoreName, providerName);
            System.err.println("Creating certificate with entry "+keyEntryName+" in KeyStore of type "+keyStoreName+" with provider "+providerName+'.');
            ks.load(null, null);
            try {
                ks.setKeyEntry(keyEntryName, keyPair.getPrivate(), passPrase!=null ? passPrase.toCharArray() : null, chain);
            } catch( KeyStoreException kse ) {
                System.err.println("Give password of inserted card in slot.");
                ks.setKeyEntry(keyEntryName, keyPair.getPrivate(),
                               new BufferedReader(new InputStreamReader(System.in)).readLine().toCharArray(),
                               chain);
            }
            ks.store(System.out, null);
            System.out.println();
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }
    }
    private static void delete(final String providerClassName,
                               final String keyStoreName) {
        try {
            final String providerName = getProviderName(providerClassName);
            final KeyStore ks = KeyStore.getInstance(keyStoreName, providerName);
            ks.load(System.in, null);
            Enumeration e = ks.aliases();
            while( e.hasMoreElements() ) {
                String alias = (String)e.nextElement();
                ks.deleteEntry(alias);
                System.err.println("Deleting certificate with alias "+alias+" in KeyStore of type "+keyStoreName+" with provider "+providerName+'.');
            }
            ks.store(System.out, null);
            System.out.println();
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }
    }
}
