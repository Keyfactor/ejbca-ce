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
import java.io.ByteArrayInputStream;
import java.io.InputStream;
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
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.x509.X509V3CertificateGenerator;

class Test {
    final private String sigAlgName = "SHA1withRSA";
    final private byte signInput[] = "Lillan gick på vägen ut.".getBytes();
    final private String alias;
    final private KeyPair keyPair;
    final private String providerName;
    public Test(String a, KeyPair kp, String pn) {
        alias = a;
        keyPair = kp;
        providerName = pn;
    }
    public void doIt(int i) throws Exception {
            final byte signBA[]; {
                Signature signature = Signature.getInstance(sigAlgName, providerName);
                signature.initSign( keyPair.getPrivate() );
                signature.update( signInput );
                signBA = signature.sign();
            }
            {
                Signature signature = Signature.getInstance(sigAlgName);
                signature.initVerify(keyPair.getPublic());
                signature.update(signInput);
                boolean result = signature.verify(signBA);
                System.out.println("Signature test of key "+alias+
                                   ": signature length " + signBA.length +
                                   "; test nr " + i +
                                   "; first byte " + Integer.toHexString(0xff&signBA[0]) +
                                   "; verifying " + result);
            }
    }
}

/**
 * @author lars
 * @version $Id: HSMKeyTool.java,v 1.3 2006-08-30 09:34:45 primelars Exp $
 *
 */
public class HSMKeyTool {
    private static String GENERATE_SWITCH = "generate";
    private static String DELETE_SWITCH = "delete";
    private static String TEST_SWITCH = "test";
    /**
     * @param args
     */
    public static void main(String[] args) {
        try {
            if ( args.length > 1 && args[1].toLowerCase().trim().equals(GENERATE_SWITCH)) {
                if ( args.length < 5 )
                    System.err.println(args[0] + " " + args[1] + " <key size> [<key entry name>] [<keystore ID>] [<key password>]");
                else
                    generate(args[2], args[3], Integer.parseInt(args[4].trim()), args.length>5 ? args[5] :"myKey", args.length>6 ? args[6] : null, args.length>7 ? args[7] : null);
            } else if ( args.length > 1 && args[1].toLowerCase().trim().equals(DELETE_SWITCH)) {
                if ( args.length < 5 )
                    System.err.println(args[0] + " " + args[1] + " [<keystore ID>] [<key entry name>]");
                else
                    delete(args[2], args[3], args[4], args.length>5 ? args[5] : null);
            } else if( args.length > 1 && args[1].toLowerCase().trim().equals(TEST_SWITCH)) {
                if ( args.length < 5 )
                    System.err.println(args[0] + " " + args[1] + " <keystore ID> [<# of tests>]");
                else
                    test(args[2], args[3], args[4], args.length>5 ? Integer.parseInt(args[5].trim()) : 1);
            } else
                System.err.println("Use \"" + args[0]+" "+GENERATE_SWITCH+"\" or \"" +
                                   args[0]+" "+DELETE_SWITCH+"\" or \"" +
                                   args[0]+" "+TEST_SWITCH+"\".");
        } catch (Throwable e) {
            e.printStackTrace(System.err);
        }
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
                                 final String keyStoreType,
                                 final int keySize,
                                 final String keyEntryName,
                                 final String storeID,
                                 final String passPrase) throws Exception {
        // Generate the RSA Keypair
        final String keyAlgName = "RSA";
        final String sigAlgName = "SHA1withRSA";
        final String providerName = getProviderName(providerClassName);
        final KeyPair keyPair = generate(providerName, keyAlgName, keySize);
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = getSelfCertificate("CN=some guy, L=around, C=US",
                                      (long)30*24*60*60*365, sigAlgName, keyPair,
                                      providerName);
        final KeyStore ks = KeyStore.getInstance(keyStoreType, providerName);
        System.err.println("Creating certificate with entry "+keyEntryName+" in KeyStore of type "+keyStoreType+" with provider "+providerName+'.');
        if ( storeID!=null ) {
            InputStream is = new ByteArrayInputStream(storeID.getBytes());
            ks.load(is, null);
        } else {
            ks.load(null, null);
        }
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
    }
    private static void deleteAlias(KeyStore ks, String alias, String keyStoreName, String providerName) throws KeyStoreException {
        ks.deleteEntry(alias);
        System.err.println("Deleting certificate with alias "+alias+" in KeyStore of type "+keyStoreName+" with provider "+providerName+'.');
    }
    private static void delete(final String providerClassName,
                               final String keyStoreName,
                               final String storeID,
                               final String alias) throws Exception {
        final String providerName = getProviderName(providerClassName);
        final KeyStore ks = KeyStore.getInstance(keyStoreName, providerName);
        {
            InputStream is = new ByteArrayInputStream(storeID.getBytes());
            ks.load(is, null);
        }
        if ( alias!=null )
            deleteAlias( ks, alias, keyStoreName, providerName );
        else {
            Enumeration e = ks.aliases();
            while( e.hasMoreElements() )
                deleteAlias( ks, (String)e.nextElement(), keyStoreName, providerName );
        }
        ks.store(System.out, null);
        System.out.println();
    }
    private static Test[] getTests(final String providerName,
                                   final String keyStoreType,
                                   final String storeID) throws Exception {
        final KeyStore ks; {
            KeyStore tmp = null;
            while( tmp==null ) {
                final InputStream is = new ByteArrayInputStream(storeID.getBytes());
                tmp = KeyStore.getInstance(keyStoreType, providerName);
                try {
                    tmp.load(is, null);
                } catch( Throwable t ) {
                    tmp = null;
                    t.printStackTrace(System.err);
                    System.err.println("Card set not preloaded. Hit return when error fixed");
                    new BufferedReader(new InputStreamReader(System.in)).readLine();
                }
            }
            ks = tmp;
        }
        Enumeration e = ks.aliases();
        Set testSet = new HashSet();
        while( e.hasMoreElements() ) {
            String alias = (String)e.nextElement();
            if ( ks.isKeyEntry(alias) ) {
                PrivateKey privateKey;
                try {
                    privateKey = (PrivateKey)ks.getKey(alias, null);
                } catch (UnrecoverableKeyException e1) {
                    System.err.println("Give password for key "+alias+':');
                    privateKey = (PrivateKey)ks.getKey(alias, 
                                                       new BufferedReader(new InputStreamReader(System.in)).readLine().toCharArray() );
                }
                testSet.add(new Test(alias, new KeyPair(ks.getCertificate(alias).getPublicKey(), privateKey), providerName));
            }
        }
        return (Test[])testSet.toArray(new Test[0]);
    }
    private static void test(final String providerClassName,
                             final String keyStoreType,
                             final String storeID,
                             final int nrOfTests) throws Exception {
        String providerName = getProviderName(providerClassName);
        System.out.println("Test of keystore with ID "+storeID+" of type "+keyStoreType+" with provider "+providerName+'.');
        Test tests[] = null;
        for (int i = 0; i<nrOfTests || nrOfTests<1; i++) {
            if ( tests==null )
                tests = getTests(providerName, keyStoreType, storeID);
            try {
                for( int j = 0; j<tests.length; j++ )
                    tests[j].doIt(i);
            } catch( Throwable t ) {
                tests = null;
                t.printStackTrace(System.err);
            }
        }
    }
}
