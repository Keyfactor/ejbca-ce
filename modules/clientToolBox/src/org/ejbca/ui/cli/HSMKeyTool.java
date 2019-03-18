/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.icao.ICAOObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cms.CMSEnvelopedGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cesecore.certificates.ca.internal.SernoGeneratorRandom;
import org.cesecore.keys.token.CachingKeyStoreWrapper;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.keys.util.KeyStoreTools;
import org.cesecore.util.CertTools;
import org.ejbca.cvc.AccessRights;
import org.ejbca.cvc.AlgorithmUtil;
import org.ejbca.cvc.AuthorizationRole;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCPublicKey;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.OIDField;
import org.ejbca.util.CMS;
import org.ejbca.util.CliTools;
import org.ejbca.util.PerformanceTest.NrOfThreadsAndNrOfTests;
import org.ejbca.util.keystore.KeyStoreToolsFactory;



/**
 * Manages a key store on a HSM. This class may be extended by a class specific for a typical HSM.
 * 
 * @version $Id$
 *
 */
public class HSMKeyTool extends ClientToolBox {
//    private static String CREATE_CA_SWITCH = "createca";
    private static final String ENCRYPT_SWITCH = "encrypt";
    private static final String DECRYPT_SWITCH = "decrypt";
    private static final String VERIFY_SWITCH = "verify";
    private static final String GENERATE_SWITCH = "generate";
    private static final String GENERATE_BATCH_SWITCH = "batchgenerate";
    private static final String DELETE_SWITCH = "delete";
    private static final String TEST_SWITCH = "test";
    private static final String MOVE_SWITCH = "move";
    private static final String CERT_REQ = "certreq";
    private static final String INSTALL_CERT = "installcert";
    private static final String RENAME = "rename";
    private static final String INSTALL_TRUSTED_ROOT = "installtrusted";
    private static final String SIGN_SWITCH = "sign";
    private static final String LINKCERT_SWITCH = "linkcert";

    final static private Logger log = Logger.getLogger(HSMKeyTool.class);

    final static private String TOKEN_ID_PARAM = "<PKCS#11 token identifier>";
    static private void sunConfigFileUseDescription(){
        System.err.println("If <PKCS#11 token identifier> is omitted then <the shared library name> will specify the sun config file.");
    }
    static private void printTokenIdDescription() {
        System.err.print("The ");
        System.err.print(TOKEN_ID_PARAM);
        System.err.println(" is one of these:");
        System.err.println("    An integer referring to slot ID.");
        System.err.println("    A string starting with \'i\' followed by an integer. The integer is the index in the slot list.");
        System.err.println("    A string starting with \'TOKEN_LABEL:\' followed by a string. The string is the label of the token.");
        System.err.println();
    }
    private static String commandString(String[] sa) {
        final StringBuilder sb = new StringBuilder();
        for ( int i=0; i<sa.length; i++) {
            sb.append(sa[i]);
            if (i+1<sa.length) {
                sb.append(' ');
            }
        }
        return sb.toString();
    }
    private static void tooFewArguments(String[] args) {
        System.err.println("Too few arguments in command: '"+commandString(args)+'\'');
        System.exit(3); // NOPMD, it's not a JEE app
    }
    private static void generateBatch( final String batchFile, final KeyStoreTools keyStoreContainer ) throws Exception {
        final Properties p = new Properties();
        {
            try ( final InputStream is = new FileInputStream(batchFile) ) {
                p.load(is);
            }
        }
        for ( final Entry<Object, Object> entry : p.entrySet() ) {
            final String alias = (String)entry.getKey();
            final String keySpec = (String)entry.getValue();
            if ( alias==null || alias.trim().length()<1 ) {
                continue;
            }
            if ( keySpec==null || keySpec.trim().length()<1 ) {
                System.err.println("No key specification for alias '"+alias+"'.");
                continue;
            }
            try {
                keyStoreContainer.generateKeyPair(keySpec, alias);
                System.out.println("Key with specification '"+keySpec+"' generated for alias '"+alias+"'.");
            } catch( Exception e ) {
                final String m = "Failed to generate key for alias '"+alias+"' with key specification '"+keySpec+"'.";
                System.err.println(m);
                log.error(m, e);
            }
        }
    }
    final static String KEY_SPEC_DESC = "all decimal digits RSA key with specified length, otherwise name of ECC curve or DSA key using syntax DSAnnnn";
    private static void printCommandString( final String args[], final boolean withCharedLib, Object... objects) {
        final StringBuilder sb = new StringBuilder();
        sb.append(args[0]);
        sb.append(' ');
        sb.append(args[1]);
        sb.append(' ');
        if ( withCharedLib ) {
            sb.append("<shared library name>");
            sb.append(' ');
        }
        for ( final Object o : objects ) {
            sb.append(o);
        }
        System.err.println(sb);
    }
    private static void printCommandString( final String args[], Object... objects) {
        printCommandString(args, true, objects);
    }
    private static void printCommandStringNoSharedLib( final String args[], Object... objects) {
        printCommandString(args, false, objects);
    }
    private static boolean doIt(final String[] orgArgs) throws Exception {
        // Get and remove optional switches
        final List<String> argsList = CliTools.getAsModifyableList(orgArgs);
        final KeyStore.ProtectionParameter protectionParameter;
        final String password = CliTools.getAndRemoveParameter("-password", argsList);
        if (password != null) {
            protectionParameter = new KeyStore.PasswordProtection(password.toCharArray());
        } else {
            protectionParameter = null;
        }
        final boolean force = CliTools.getAndRemoveSwitch("--force", argsList);
        final String[] args = CliTools.getAsArgs(argsList);
        if ( args[1].toLowerCase().trim().contains(GENERATE_BATCH_SWITCH) ) {
            if ( args.length < 4 ) {
                printCommandString( args, "<name of batch file> [", TOKEN_ID_PARAM, "]");
                printTokenIdDescription();
                sunConfigFileUseDescription();
                System.err.println("The batch file is a file which specifies alias and key specification for each key to be generated.");
                System.err.println("Each row is starting with a key alias then the key specification is following.");
                System.err.println("The specification of the key is done like this: "+KEY_SPEC_DESC);
                tooFewArguments(args);
            }
            final String storeId;
            final Pkcs11SlotLabelType slotType;
            if(args.length > 4) {
                storeId = trimStoreId(args[4]);
                slotType = getTokenLabelType(args[4]);
            } else {
                storeId = null;
                slotType = Pkcs11SlotLabelType.SUN_FILE;
            }
            final KeyStoreTools store = KeyStoreToolsFactory.getInstance(args[2], storeId, slotType, null, protectionParameter, "batch-"+new Date().getTime());
            generateBatch(args[3], store);
            return true;
        }
        if ( args[1].toLowerCase().trim().contains(GENERATE_SWITCH) ) {
            if ( args.length < 4 ) {
                printCommandString( args, Character.valueOf('<'), KEY_SPEC_DESC, "> <key entry name> [", TOKEN_ID_PARAM, "]");
                printTokenIdDescription();
                sunConfigFileUseDescription();
                tooFewArguments(args);
            }
            final String keyEntryName = args.length>4 ? args[4] :"myKey";
            final String storeId;
            final Pkcs11SlotLabelType slotType;
            if(args.length > 5) {
                storeId = trimStoreId(args[5]);
                slotType = getTokenLabelType(args[5]);
            } else {
                storeId = null;
                slotType = Pkcs11SlotLabelType.SUN_FILE;
            }
            System.out.println("Using Slot Reference Type: "+slotType+'.');
            final KeyStoreTools store = KeyStoreToolsFactory.getInstance(args[2], storeId, slotType, null, protectionParameter, "priv-"+keyEntryName);
            final boolean existsKeyEntryName = KeyStoreToolsFactory.getInstance(args[2], storeId, slotType, null, 
                    protectionParameter).getKeyStore().isKeyEntry(keyEntryName);
            if (!existsKeyEntryName){
                store.generateKeyPair(args[3], keyEntryName);
                System.out.println("Created certificate with entry "+keyEntryName+'.');
            } else {
                if (force) {
                    System.err.println("Warning: Overwriting existing key with key entry name "+keyEntryName+"!");
                    store.generateKeyPair(args[3], keyEntryName);
                    System.out.println("Created certificate with entry "+keyEntryName+'.');
                } else {
                    System.out.println("Entry "+keyEntryName+" already exists. To overwrite, add --force as last argument.");
                }
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(DELETE_SWITCH)) {
            if ( args.length < 4 ) {
                printCommandString( args, TOKEN_ID_PARAM, " [<key entry name>]");
                printTokenIdDescription();
                tooFewArguments(args);
            }
            final String alias = args.length>4 ? args[4] : null;
            System.out.println("Deleting certificate with alias "+alias+'.');
            final String storeId = trimStoreId(args[3]);
            final Pkcs11SlotLabelType slotType = getTokenLabelType(args[3]);

            KeyStoreToolsFactory.getInstance(args[2], storeId, slotType, null, protectionParameter).deleteEntry(alias);
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(CERT_REQ)) {
            // First we check if we have a switch for "-explicitecc" for explicit ecc parameters used in ICAO epassports.
            final List<String> argsListLocal = CliTools.getAsModifyableList(args);
            final boolean explicitEccParameters = argsListLocal.remove("-explicitecc");
            final boolean forAllKeys = argsListLocal.remove("-all");
            final String modArgs[] = argsListLocal.toArray(new String[argsListLocal.size()]);
            if ( modArgs.length < 4 || (modArgs.length < 5 && !forAllKeys) ) {
                printCommandString( args, TOKEN_ID_PARAM, " <key entry name> [<CN>] [-explicitecc]");
                printCommandString( args, TOKEN_ID_PARAM, " [-all] [-explicitecc]");
                printTokenIdDescription();
                tooFewArguments(modArgs);
            }
            final String storeId = trimStoreId(modArgs[3]);
            final Pkcs11SlotLabelType slotType = getTokenLabelType(modArgs[3]);
            final KeyStoreTools container = KeyStoreToolsFactory.getInstance(modArgs[2], storeId, slotType, null, protectionParameter);
            final List<String> entries;
            if (forAllKeys) {
                entries = new LinkedList<>();
                final CachingKeyStoreWrapper ks = container.getKeyStore();
                final Enumeration<String> aliases = ks.aliases();
                while (aliases.hasMoreElements()) {
                    final String alias = aliases.nextElement();
                    if (ks.isKeyEntry(alias)) {
                        entries.add(alias);
                    }
                }
            } else {
                entries = Collections.singletonList(modArgs[4]);
            }

            for (String entry : entries) {
                container.generateCertReq(entry, modArgs.length>5 ? modArgs[5] : null, explicitEccParameters);
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(INSTALL_CERT)) {
            if ( args.length < 5 ) {
                printCommandString( args, TOKEN_ID_PARAM, " <certificate chain files in PEM format (one chain per file)>");
                printTokenIdDescription();
                tooFewArguments(args);
            }
            final String storeId = trimStoreId(args[3]);
            final Pkcs11SlotLabelType slotType = getTokenLabelType(args[3]);
            final KeyStoreTools container = KeyStoreToolsFactory.getInstance(args[2], storeId, slotType, null, protectionParameter);
            boolean failure = false;
            for (int i = 4; i < args.length; i++) {
                try {
                    container.installCertificate(args[i]);
                } catch (Exception ex) {
                    failure = true;
                    log.error("File "+args[i]+" failed.", ex);
                }
            }
            if (failure) {
                throw new Exception("At least one certificate could not be installed. See the log for more info.");
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(INSTALL_TRUSTED_ROOT)) {
            if ( args.length < 5 ) {
                printCommandString( args, TOKEN_ID_PARAM, " <trusted root certificate in PEM format>");
                printTokenIdDescription();
                tooFewArguments(args);
            }
            final String storeId = trimStoreId(args[3]);
            final Pkcs11SlotLabelType slotType = getTokenLabelType(args[3]);
            KeyStoreToolsFactory.getInstance(args[2], storeId, slotType, null, protectionParameter).installTrustedRoot(args[4]);
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(ENCRYPT_SWITCH)) {
            String symmAlgOid = CMSEnvelopedGenerator.AES128_CBC;
            if ( args.length < 5 ) {
                System.err.println("There are two ways of doing the encryption:");
                printCommandString( args, TOKEN_ID_PARAM, " <input file> <output file> <key alias> [optional symm algorithm oid]");
                printCommandStringNoSharedLib( args, "<input file> <output file> <file with certificate with public key to use> [optional symm algorithm oid]");
                printTokenIdDescription();
                System.err.println("Optional symmetric encryption algorithm OID can be for example 2.16.840.1.101.3.4.1.42 (AES256_CBC) or 1.2.392.200011.61.1.1.1.4 (CAMELLIA256_CBC). Default is to use AES256_CBC.");
                tooFewArguments(args);
            }
            if ( args.length < 7 ) {
                Security.addProvider( new BouncyCastleProvider() );
                if (args.length > 5) {
                    // We have a symmAlg as last parameter
                    symmAlgOid = args[5];
                }
                System.out.println("Using symmetric encryption algorithm: "+symmAlgOid);
                try(
                        final InputStream certIS = new FileInputStream(args[4]);
                        final InputStream is=new FileInputStream(args[2]);
                        final OutputStream os = new FileOutputStream(args[3])
                        ) {
                    final X509Certificate cert = (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new BufferedInputStream(certIS));
                    CMS.encrypt(is, os, cert, symmAlgOid);
                }
            } else {
                if (args.length > 7) {
                    // We have a symmAlg as last parameter
                    symmAlgOid = args[7];
                }
                System.out.println("Using symmstric encryption algorithm: "+symmAlgOid);
                final String storeId = trimStoreId(args[3]);
                final Pkcs11SlotLabelType slotType = getTokenLabelType(args[3]);
                try(
                        final InputStream is = new FileInputStream(args[4]);
                        final OutputStream os = new FileOutputStream(args[5]);
                        ) {
                    final Certificate cert = KeyStoreToolsFactory.getInstance(args[2], storeId, slotType, null, protectionParameter).getKeyStore().getCertificate(args[6]);
                    CMS.encrypt(is, os, (X509Certificate)cert, symmAlgOid);
                }
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(DECRYPT_SWITCH)) {
            if ( args.length < 7 ) {
                printCommandString( args, TOKEN_ID_PARAM, " <input file> <output file> <key alias>");
                printTokenIdDescription();
                tooFewArguments(args);
            }
            final String storeId = trimStoreId(args[3]);
            final Pkcs11SlotLabelType slotType = getTokenLabelType(args[3]);
            try(
                    final InputStream is = new FileInputStream(args[4]);
                    final OutputStream os = new FileOutputStream(args[5])
                    ) {
                final KeyStoreTools keyStore = KeyStoreToolsFactory.getInstance(args[2], storeId, slotType, null, protectionParameter);
                CMS.decrypt(is, os, (PrivateKey)keyStore.getKeyStore().getKey(args[6], null), keyStore.getProviderName());
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(SIGN_SWITCH)) {
            if ( args.length < 7 ) {
                printCommandString( args, TOKEN_ID_PARAM, " <input file> <output file> <key alias>");
                printTokenIdDescription();
                tooFewArguments(args);
            }
            final String storeId = trimStoreId(args[3]);
            final Pkcs11SlotLabelType slotType = getTokenLabelType(args[3]);
            final KeyStoreTools keyStore = KeyStoreToolsFactory.getInstance(args[2], storeId, slotType, null, protectionParameter);
            final String alias = args[6];
            final PrivateKey key = (PrivateKey)keyStore.getKeyStore().getKey(alias, null);
            final X509Certificate cert = (X509Certificate)keyStore.getKeyStore().getCertificate(alias);
            try(
                    final InputStream is = new FileInputStream(args[4]);
                    final OutputStream os = new FileOutputStream(args[5]);
                    ) {
                CMS.sign(is, os, key, keyStore.getProviderName(), cert);
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(LINKCERT_SWITCH)) {
            if ( args.length < 8 ) {
                printCommandString( args, TOKEN_ID_PARAM, " <old ca-cert> <new ca-cert> <output link-cert> <key alias> [<sig alg override>]");
                printTokenIdDescription();
                System.err.println();
                System.err.println("Creates a link certificate that links the old and new certificate files.");
                System.err.println("You should use this command with the old HSM key. It does not need any");
                System.err.println("access to the new key.");
                System.err.println();
                tooFewArguments(args);
            }
            final String storeId = trimStoreId(args[3]);
            final Pkcs11SlotLabelType slotType = getTokenLabelType(args[3]);
            final KeyStoreTools ksc = KeyStoreToolsFactory.getInstance(args[2], storeId, slotType, null, protectionParameter);
            final String alias = args[7];
            final String oldCertPath = args[4];
            final String newCertPath = args[5];
            final String outputPath = args[6];
            final String signProviderName = ksc.getProviderName();
            final String sigAlgOverride = (args.length > 8 ? args[8] : "null");

            // Parse certificates
            final byte[] oldCertBytes;
            try( final InputStream is=new FileInputStream(oldCertPath) ) {
                oldCertBytes = IOUtils.toByteArray(is);
            }
            final byte[] newCertBytes;
            try( final InputStream is=new FileInputStream(newCertPath) ) {
                newCertBytes = IOUtils.toByteArray(is);
            }
            final Certificate oldCert = CertTools.getCertfromByteArray(oldCertBytes, BouncyCastleProvider.PROVIDER_NAME, Certificate.class);
            final Certificate newCert = CertTools.getCertfromByteArray(newCertBytes, BouncyCastleProvider.PROVIDER_NAME, Certificate.class);
            final boolean isCVCA = (oldCert instanceof CardVerifiableCertificate);
            if (isCVCA != (newCert instanceof CardVerifiableCertificate)) {
                log.error("Error: Old and new certificates are not of the same type (X509 / CVC)");
                return true; // = valid command-line syntax
            }
            System.out.println("Type of certificates: "+(isCVCA ? "CVC" : "X509"));

            // Detect name change
            final String oldDN = CertTools.getSubjectDN(oldCert);
            final String newDN = CertTools.getSubjectDN(newCert);
            System.out.println("Old DN: "+oldDN);
            System.out.println("New DN: "+newDN);
            final boolean nameChange;
            if (!oldDN.equals(newDN)) {
                if (isCVCA) {
                    System.out.println("Name change detected.");
                } else {
                    System.out.println("Name change detected. Will add Name Change extension.");
                }
                nameChange = true;
            } else {
                System.out.println("No name change detected.");
                nameChange = false;
            }

            final ByteArrayOutputStream baos = new ByteArrayOutputStream();

            // Get new and old key
            final PublicKey newPubKey = newCert.getPublicKey();
            if (newPubKey == null) {
                System.err.println("Error: Failed to extract public key from new certificate");
                return true;
            }
            final Key oldKey = ksc.getKeyStore().getKey(alias, null);
            if (oldKey == null) {
                System.err.println("Error: Could not find the key named "+alias);
                return true;
            }
            final PrivateKey oldPrivKey = (PrivateKey)oldKey;

            if (isCVCA) {
                final CVCertificate oldCertCVC = ((CardVerifiableCertificate)oldCert).getCVCertificate();
                final CVCertificate newCertCVC = ((CardVerifiableCertificate)newCert).getCVCertificate();

                final String linkSigAlg;
                if (sigAlgOverride.equalsIgnoreCase("null")) {
                    final OIDField oldKeyTypeOid = oldCertCVC.getCertificateBody().getPublicKey().getObjectIdentifier();
                    linkSigAlg = AlgorithmUtil.getAlgorithmName(oldKeyTypeOid);
                } else {
                    System.err.println("Error: Overriding the signature algorithm is not supported for CVC");
                    return true;
                }
                System.out.println("Using signature algorithm "+linkSigAlg);

                final HolderReferenceField caHolder = oldCertCVC.getCertificateBody().getHolderReference();
                final CAReferenceField caRef = new CAReferenceField(caHolder.getCountry(), caHolder.getMnemonic(), caHolder.getSequence());
                final HolderReferenceField certHolder = newCertCVC.getCertificateBody().getHolderReference();
                final AuthorizationRole authRole = newCertCVC.getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getAuthRole();                    
                final AccessRights rights = newCertCVC.getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getAccessRights();
                final Date validFrom = new Date(new Date().getTime() - 60L*15L*1000L); // back date by 15 minutes to allow for clock skew
                // End date is the same as the new CVCA certificate
                final Date validTo = newCertCVC.getCertificateBody().getValidTo();

                // In link certificates we can change algorithm and keys. The algorithm in CVC is encoded into the public key though, so if we
                // don't take special precaution here CertificateGenerator.createCertificate will sign with linkSigAlg but put the algorithm OID
                // from cvcNewPubKey, which will not be the algorithm used to sign the cert with, if the algorithm has changed (say from SHA256WithECDSA to SHA512withECDSA).
                // Therefore we "hack" the new key here to set the same oid as in the old public key, which is the one used for signing (well the private key, 
                // but with the algorithm as encoded in the public key)
                CVCPublicKey cvcOldPubKey = oldCertCVC.getCertificateBody().getPublicKey();
                CVCPublicKey cvcNewPubKey = newCertCVC.getCertificateBody().getPublicKey();
                cvcNewPubKey.setObjectIdentifier(cvcOldPubKey.getObjectIdentifier());
                
                final CVCertificate linkCert = CertificateGenerator.createCertificate(cvcNewPubKey, oldPrivKey, linkSigAlg, caRef, certHolder, authRole, rights, validFrom, validTo, signProviderName);
                try ( final DataOutputStream dos = new DataOutputStream(baos) ) {
                    linkCert.encode(dos);
                }
            } else {
                // X509 CA
                final X509Certificate oldCertX509 = (X509Certificate)oldCert;
                final X509Certificate newCertX509 = (X509Certificate)newCert;

                final String linkSigAlg;
                if (sigAlgOverride.equalsIgnoreCase("null")) {
                    // Actually, we should use signature algorithm of new cert if the old key allows that.
                    // Instead of doing that we allow the user to manually override the signature algorithm if needed.
                    linkSigAlg = oldCertX509.getSigAlgName();
                } else {
                    System.err.println("Warning: Signature algorithm manually overridden!");
                    linkSigAlg = sigAlgOverride;
                }
                System.out.println("Using signature algorithm "+linkSigAlg);

                final BigInteger serno = SernoGeneratorRandom.instance(12).getSerno();
                final SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance(newPubKey.getEncoded());
                final Date validFrom = new Date(new Date().getTime() - 60L*15L*1000L); // back date by 15 minutes to allow for clock skew
                final Date validTo = oldCertX509.getNotAfter();

                final X500Name oldDNName = X500Name.getInstance(oldCertX509.getSubjectX500Principal().getEncoded());
                final X500Name newDNName = X500Name.getInstance(newCertX509.getSubjectX500Principal().getEncoded());

                final X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(oldDNName, serno, validFrom, validTo, newDNName, pkinfo);

                // Copy all extensions except AKID
                final ExtensionsGenerator extgen = new ExtensionsGenerator();
                final Set<String> oids = new LinkedHashSet<>();
                final Set<String> criticalOids = newCertX509.getCriticalExtensionOIDs();
                oids.addAll(criticalOids);
                oids.addAll(newCertX509.getNonCriticalExtensionOIDs());
                for (final String extOidStr : oids) {
                    final ASN1ObjectIdentifier extoid = new ASN1ObjectIdentifier(extOidStr);
                    if (!extoid.equals(Extension.authorityKeyIdentifier)) {
                        final byte[] extbytes = newCertX509.getExtensionValue(extOidStr);
                        final ASN1OctetString str = (ASN1OctetString)ASN1Primitive.fromByteArray(extbytes);
                        extgen.addExtension(extoid, criticalOids.contains(extOidStr), ASN1Primitive.fromByteArray(str.getOctets()));
                    }
                }

                if (nameChange) {
                    // id-icao-mrtd-security-extensions-nameChange = 2.23.136.1.1.6.1
                    extgen.addExtension(ICAOObjectIdentifiers.id_icao_extensions_namechangekeyrollover, false, DERNull.INSTANCE);
                }

                // Some checks
                if (newCertX509.getExtensionValue(Extension.subjectKeyIdentifier.getId()) == null) {
                    System.err.println("Warning: Certificate of new CSCA is missing the Subject Key Identifier extension, which is mandatory.");
                }
                if (newCertX509.getExtensionValue(Extension.authorityKeyIdentifier.getId()) == null) {
                    System.err.println("Warning: Certificate of new CSCA is missing the Authority Key Identifier extension, which is mandatory.");
                }

                // If the new cert has an AKID, then add that extension but with the key id value of the old cert
                final byte[] oldSKIDBytes = oldCertX509.getExtensionValue(Extension.subjectKeyIdentifier.getId());
                if (oldSKIDBytes != null) {
                    final ASN1OctetString str = (ASN1OctetString)ASN1Primitive.fromByteArray(oldSKIDBytes);
                    final ASN1OctetString innerStr = (ASN1OctetString)ASN1Primitive.fromByteArray(str.getOctets());
                    final AuthorityKeyIdentifier akidExt = new AuthorityKeyIdentifier(innerStr.getOctets());
                    extgen.addExtension(Extension.authorityKeyIdentifier, false, akidExt);
                } else {
                    System.err.println("Warning: The old certificate doesn't have any SubjectKeyIdentifier. The link certificate will not have any AuthorityKeyIdentifier.");
                }

                // Add extensions to the certificate
                final Extensions exts = extgen.generate();
                for (final ASN1ObjectIdentifier extoid : exts.getExtensionOIDs()) {
                    final Extension ext = exts.getExtension(extoid);
                    certbuilder.addExtension(extoid, ext.isCritical(), ext.getParsedValue());
                }

                // Sign the certificate
                final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder(linkSigAlg).setProvider(signProviderName).build(oldPrivKey), 20480);
                final X509CertificateHolder certHolder = certbuilder.build(signer);
                baos.write(certHolder.getEncoded());
                
            }
            // Save to output file
            try( final FileOutputStream fos = new FileOutputStream(outputPath) ) {
                baos.writeTo(fos);
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(VERIFY_SWITCH)) {
            final CMS.VerifyResult verifyResult;
            if ( args.length < 5 ) {
                System.err.println("There are two ways of doing the encryption:");
                printCommandString( args, TOKEN_ID_PARAM, " <input file> <output file> <key alias>");
                printTokenIdDescription();
                printCommandStringNoSharedLib(args, "<input file> <output file> <file with certificate with public key to use>");
                tooFewArguments(args);
            }
            if ( args.length < 7 ) {
                Security.addProvider( new BouncyCastleProvider() );
                try (
                        final InputStream certIS = new FileInputStream(args[4]);
                        final InputStream is = new FileInputStream(args[2]);
                        final OutputStream os = new FileOutputStream(args[3]);
                        ) {
                    final X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new BufferedInputStream(certIS));
                    verifyResult = CMS.verify(is, os, cert);
                }
            } else {
                final String storeId = trimStoreId(args[3]);
                final Pkcs11SlotLabelType slotType = getTokenLabelType(args[3]);
                final KeyStoreTools keyStore = KeyStoreToolsFactory.getInstance(args[2], storeId, slotType, null, protectionParameter);
                final X509Certificate cert = (X509Certificate)keyStore.getKeyStore().getCertificate(args[6]);
                try (
                        final InputStream is = new FileInputStream(args[4]);
                        final OutputStream os = new FileOutputStream(args[5])
                        ) {
                    verifyResult = CMS.verify(is, os, cert);
                }
            }
            if ( verifyResult==null ) {
                System.err.println("Not possible to parse signed file.");
                System.exit(4); // Not verifying // NOPMD, it's not a JEE app
                return false;//will never be executes. just to avoid warning.
            }
            System.out.println("The signature of the input " +(verifyResult.isVerifying?"has been":"could not be")+" verified. The file was signed on '"+verifyResult.signDate+"'. The public part of the signing key is in a certificate with serial number "+verifyResult.signerId.getSerialNumber()+" issued by '"+verifyResult.signerId.getIssuer()+"'.");
            if ( !verifyResult.isVerifying ) {
                System.exit(4); // Not verifying // NOPMD, it's not a JEE app
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(TEST_SWITCH)) {
            if ( args.length < 4 ) {
                printCommandString( args, TOKEN_ID_PARAM, " [<'m:n' m # of threads, n # of tests>] [<alias for stress test>] [<type of stress test>]");
                printTokenIdDescription();
                System.err.println("    If a file named \"./testData\" exists then the data that is signed, is read from this file.");
                tooFewArguments(args);
            }
            final String storeId = trimStoreId(args[3]);
            final Pkcs11SlotLabelType slotType = getTokenLabelType(args[3]);
            final NrOfThreadsAndNrOfTests notanot = new NrOfThreadsAndNrOfTests(args.length>4 ? args[4] : null);
            KeyStoreContainerTest.test(
                    args[2], storeId, slotType,
                    notanot.getThreads(), notanot.getTests(),
                    args.length>5 ? args[5].trim() : null,
                    args.length>6 ? args[6].trim() : null,
                    protectionParameter);
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(RENAME)) {
            if ( args.length < 6 ) {
                printCommandString( args, TOKEN_ID_PARAM, " <old key alias> <new key alias>");
                printTokenIdDescription();
                tooFewArguments(args);
            }
            final String storeId = trimStoreId(args[3]);
            final Pkcs11SlotLabelType slotType = getTokenLabelType(args[3]);
            final KeyStoreTools keyStore = KeyStoreToolsFactory.getInstance(args[2], storeId, slotType, null, protectionParameter);

            keyStore.renameEntry(args[4], args[5]);
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(MOVE_SWITCH)) {
            if ( args.length < 5 ) {
                printCommandString( args, "<from PKCS#11 token identifier> <to PKCS#11 token identifier>");
                printTokenIdDescription();
                tooFewArguments(args);
            }
            final KeyStoreTools fromKS = KeyStoreToolsFactory.getInstance(
                    args[2],
                    trimStoreId(args[3]),
                    getTokenLabelType(args[3]),
                    null, protectionParameter );
            final KeyStoreTools toKS = KeyStoreToolsFactory.getInstance(
                    args[2],
                    trimStoreId(args[4]),
                    getTokenLabelType(args[4]),
                    null, protectionParameter );
            System.out.println("Moving entry with alias '"+args[3]+"' to alias '"+args[4]+'.');
            final Enumeration<String> e = fromKS.getKeyStore().aliases();
            while( e.hasMoreElements() ) {
                final String alias = e.nextElement();
                if (fromKS.getKeyStore().isKeyEntry(alias)) {
                    final Key key=fromKS.getKeyStore().getKey(alias, null);
                    final Certificate chain[] = fromKS.getKeyStore().getCertificateChain(alias);
                    toKS.setKeyEntry(alias, key, chain);
                }
                fromKS.getKeyStore().deleteEntry(alias);
            }
            fromKS.getKeyStore().store(null, null);
            toKS.getKeyStore().store(null, null);
            return true;
        }
        return false;
    }
    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.ClientToolBox#execute(java.lang.String[])
     */
    @Override
	protected void execute(String[] args) {
        try {
            if ( args.length>1 && doIt(args)) {
                return; // command was found.
            }
            final PrintWriter pw = new PrintWriter(System.err);
            pw.println("Use one of following commands: ");
//            pw.println("  "+args[0]+" "+CREATE_CA_SWITCH);
            pw.println("  "+args[0]+" "+GENERATE_SWITCH);
            pw.println("  "+args[0]+" "+GENERATE_BATCH_SWITCH);
            pw.println("  "+args[0]+" "+CERT_REQ);
            pw.println("  "+args[0]+" "+INSTALL_CERT);
            pw.println("  "+args[0]+" "+DELETE_SWITCH);
            pw.println("  "+args[0]+" "+TEST_SWITCH);
            pw.println("  "+args[0]+" "+RENAME);
            pw.println("  "+args[0]+" "+ENCRYPT_SWITCH);
            pw.println("  "+args[0]+" "+DECRYPT_SWITCH);
            pw.println("  "+args[0]+" "+SIGN_SWITCH);
            pw.println("  "+args[0]+" "+VERIFY_SWITCH);
            pw.println("  "+args[0]+" "+MOVE_SWITCH);
            pw.println("  "+args[0]+" "+LINKCERT_SWITCH);
            pw.println("  The optional -password <password> switch can be specified as a last argument for scripting any of these commands.");
            pw.flush();
            if (args.length > 1) {
                // Don't print this if it is only a general usage message
                System.err.println("Command '"+commandString(args)+"' not found.");
            }
            System.exit(1); // Command not found.  // NOPMD, it's not a JEE app
        } catch( SecurityException e ) {
            throw e; // in test of the tool System.exit() is throwing exception that should be thrown to the the app.
        } catch (Throwable e) {
            System.err.println("Command could not be executed. See log for stack trace.");
            log.error("Command '"+commandString(args)+"' could not be executed.", e);
            System.exit(2); // Command did not execute OK! // NOPMD, it's not a JEE app
        }
    }
    @Override
    protected String getName() {
        return "PKCS11HSMKeyTool";
    }

    private static final String trimStoreId(String storeId) {
        if(storeId.contains(":")) {
            return storeId.split(":", 2)[1];
        }
        return storeId;
    }

    private static final Pkcs11SlotLabelType getTokenLabelType(String storeId) {
        if(storeId.contains(":")) {
            String prefix = storeId.split(":", 2)[0].trim();
            if(prefix.equals("TOKEN_LABEL") || prefix.equals(Pkcs11SlotLabelType.SLOT_LABEL.getKey())) {
                return Pkcs11SlotLabelType.SLOT_LABEL;
            }
            if (prefix.equals("SLOT_ID") || prefix.equals(Pkcs11SlotLabelType.SLOT_NUMBER.getKey())) {
                return Pkcs11SlotLabelType.SLOT_NUMBER;
            }
            if (prefix.equals("SLOT_LIST_IX") || prefix.equals(Pkcs11SlotLabelType.SLOT_INDEX.getKey())) {
                return Pkcs11SlotLabelType.SLOT_INDEX;
            }
            throw new IllegalArgumentException("Type " + prefix + " was not valid");
        }
        if(Pkcs11SlotLabelType.SLOT_NUMBER.validate(storeId)) {
            return Pkcs11SlotLabelType.SLOT_NUMBER;
        }
        if(Pkcs11SlotLabelType.SLOT_INDEX.validate(storeId)) {
            return Pkcs11SlotLabelType.SLOT_INDEX;
        }
        return Pkcs11SlotLabelType.SLOT_LABEL;
    }
}
