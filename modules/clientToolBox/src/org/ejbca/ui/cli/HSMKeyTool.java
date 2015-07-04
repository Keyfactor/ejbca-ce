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
import org.bouncycastle.asn1.ASN1Sequence;
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
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.util.CertTools;
import org.ejbca.cvc.AccessRights;
import org.ejbca.cvc.AlgorithmUtil;
import org.ejbca.cvc.AuthorizationRole;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.OIDField;
import org.ejbca.util.CMS;
import org.ejbca.util.CliTools;
import org.ejbca.util.keystore.KeyStoreContainer;
import org.ejbca.util.keystore.KeyStoreContainerBase;
import org.ejbca.util.keystore.KeyStoreContainerFactory;



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
    private static final String GENERATE_MODULE_SWITCH = GENERATE_SWITCH+"module";
    private static final String GENERATE_BATCH_SWITCH = "batchgenerate";
    private static final String DELETE_SWITCH = "delete";
    private static final String TEST_SWITCH = "test";
    private static final String CREATE_KEYSTORE_SWITCH = "createkeystore";
    private static final String CREATE_KEYSTORE_MODULE_SWITCH = CREATE_KEYSTORE_SWITCH+"module";
    private static final String MOVE_SWITCH = "move";
    private static final String CERT_REQ = "certreq";
    private static final String INSTALL_CERT = "installcert";
    private static final String RENAME = "rename";
    private static final String INSTALL_TRUSTED_ROOT = "installtrusted";
    private static final String SIGN_SWITCH = "sign";
    private static final String LINKCERT_SWITCH = "linkcert";

    final static private Logger log = Logger.getLogger(HSMKeyTool.class);

    /**
     * To be overided if the HSM implementation knows the value of some parameters.
     * @return description of parameters common to all commands.
     */
    String getProviderParameterDescription() {
        return "<signature provider name> <crypto provider name (use null if same as signature)> <keystore provider name>";
    }
    /**
     * @return description of the keystore id.
     */
    String getKeyStoreDescription() {
        return "keystore ID";
    }
    /**
     * The HSM may overide to print an extra comment for the generate command.
     */
    void generateComment(){
        return;
    }
    /**
     * HSMs not capable to create a keystore should overide this method and return false.
     * @return true if the HSM is capable to create a keystore.
     */
    boolean doCreateKeyStore() {
        return true;
    }
    /**
     * HSMs capable of module protection should overide this method and return true.
     * @return true if the HSDM is capable of module protection.
     */
    boolean doModuleProtection() {
        return false;
    }
    /**
     * HSMs capable of module protection should overide this method.
     */
    void setModuleProtection() {
        return;
    }
    private static String commandString(String[] sa) {
        String s = "";
        for ( int i=0; i<sa.length; i++) {
            s += sa[i];
            if (i+1<sa.length) {
                s += " ";
            }
        }
        return s;
    }
    private static void tooFewArguments(String[] args) {
        System.err.println("Too few arguments in command: '"+commandString(args)+'\'');
        System.exit(3); // NOPMD, it's not a JEE app
    }
    private static void generateBatch( final String batchFile, final KeyStoreContainer keyStoreContainer ) throws Exception {
        final Properties p = new Properties();
        {
            final InputStream is = new FileInputStream(batchFile);
            try {
                p.load(is);
            } finally {
                is.close();
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
                keyStoreContainer.generate(keySpec, alias);
                log.info("Key with specification '"+keySpec+"' generated for alias '"+alias+"'.");
            } catch( Exception e ) {
                log.error("Failed to generate key for alias '"+alias+"' with key specification '"+keySpec+"'.", e);
            }
        }
    }
    final static String KEY_SPEC_DESC = "all decimal digits RSA key with specified length, otherwise name of ECC curve or DSA key using syntax DSAnnnn";
    private boolean doIt(String[] args) throws Exception {
        final String commandStringNoSharedLib = args[0]+" "+args[1]+" ";
        final String commandString = commandStringNoSharedLib+getProviderParameterDescription()+" ";
        // Get and remove optional switches
        final List<String> argsList = CliTools.getAsModifyableList(args);
        KeyStore.ProtectionParameter protectionParameter = null;
        final String password = CliTools.getAndRemoveParameter("-password", argsList);
        if (password != null) {
            protectionParameter = new KeyStore.PasswordProtection(password.toCharArray());
        }
        args = CliTools.getAsArgs(argsList);
        if ( args[1].toLowerCase().trim().contains(GENERATE_BATCH_SWITCH) ) {
            if ( args.length < 6 ) {
                System.err.println(commandString + "<name of batch file> " + '['+'<'+getKeyStoreDescription()+'>'+']');
                generateComment();
                System.err.println("The batch file is a file which specifies alias and key specification for each key to be generated.");
                System.err.println("Each row is starting with a key alias then the key specification is following.");
                System.err.println("The specification of the key is done like this: "+KEY_SPEC_DESC);
                tooFewArguments(args);
                return true;
            }
            if ( args[1].toLowerCase().trim().contains(GENERATE_MODULE_SWITCH) ) {
                setModuleProtection();
            }
            String storeId = null;
            Pkcs11SlotLabelType slotType = null;
            if(args.length > 6) {
                storeId = trimStoreId(args[6]);
                slotType = divineSlotLabelType(args[6]);
            } else {
                slotType = Pkcs11SlotLabelType.SUN_FILE;
            }
            final KeyStoreContainer store = KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], storeId, slotType, null, protectionParameter, "batch-"+new Date().getTime());
            generateBatch(args[5], store);
            return true;
        }
        if ( args[1].toLowerCase().trim().contains(GENERATE_SWITCH) ) {
            if ( args.length < 6 ) {
                System.err.println(commandString + '<' + KEY_SPEC_DESC + "> <key entry name> [<"+getKeyStoreDescription()+">]");
                generateComment();
                tooFewArguments(args);
            } else {
                if ( args[1].toLowerCase().trim().contains(GENERATE_MODULE_SWITCH) ) {
                    setModuleProtection();
                }
                final String keyEntryName = args.length>6 ? args[6] :"myKey";
                String storeId = null;
                Pkcs11SlotLabelType slotType = null;
                if(args.length > 7) {
                    storeId = trimStoreId(args[7]);
                    slotType = divineSlotLabelType(args[7]);
                } else {
                    slotType = Pkcs11SlotLabelType.SUN_FILE;
                }
                System.err.println("Using Slot Reference Type: "+slotType+'.');
                final KeyStoreContainer store = KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], storeId, slotType, null, protectionParameter, "priv-"+keyEntryName);
                store.generate(args[5], keyEntryName);
                System.err.println("Created certificate with entry "+keyEntryName+'.');
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(DELETE_SWITCH)) {
            if ( args.length < 6 ) {
                System.err.println(commandString + '<'+getKeyStoreDescription()+'>' + " [<key entry name>]");
                tooFewArguments(args);
            } else {
                String alias = args.length>6 ? args[6] : null;
                System.err.println("Deleting certificate with alias "+alias+'.');
                String storeId = null;
                Pkcs11SlotLabelType slotType = null;
              
                storeId = trimStoreId(args[5]);
                slotType = divineSlotLabelType(args[5]);

                KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], storeId, slotType, null, protectionParameter).delete(alias);
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(CERT_REQ)) {
        	// First we check if we have a switch for "-explicitecc" for explicit ecc parameters used in ICAO epassports.
    		List<String> argsListLocal = CliTools.getAsModifyableList(args);
    		boolean explicitEccParameters = argsListLocal.remove("-explicitecc");
                final boolean forAllKeys = argsListLocal.remove("-all");
    		args = argsListLocal.toArray(new String[argsListLocal.size()]);
            if ( args.length < 6 || (args.length < 7 && !forAllKeys) ) {
                System.err.println(commandString + '<'+getKeyStoreDescription()+'>' + " <key entry name> [<CN>] [-explicitecc]");
                System.err.println(commandString + '<'+getKeyStoreDescription()+'>' + " [-all] [-explicitecc]");
                tooFewArguments(args);
            } else {
                String storeId = trimStoreId(args[5]);
                Pkcs11SlotLabelType slotType = divineSlotLabelType(args[5]);
                final KeyStoreContainer container = KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], storeId, slotType, null, protectionParameter);
                final List<String> entries;
                if (forAllKeys) {
                    entries = new LinkedList<String>();
                    final KeyStore ks = container.getKeyStore();
                    final Enumeration<String> aliases = ks.aliases();
                    while (aliases.hasMoreElements()) {
                        final String alias = aliases.nextElement();
                        if (ks.isKeyEntry(alias)) {
                            entries.add(alias);
                        }
                    }
                } else {
                    entries = Collections.singletonList(args[6]);
                }
                
                for (String entry : entries) {
                    container.generateCertReq(entry, args.length>7 ? args[7] : null, explicitEccParameters);
                }
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(INSTALL_CERT)) {
            if ( args.length < 7 ) {
                System.err.println(commandString + '<'+getKeyStoreDescription()+'>' + " <certificate chain files in PEM format (one chain per file)>");
                tooFewArguments(args);
            } else {
                String storeId = null;
                Pkcs11SlotLabelType slotType = null;
                storeId = trimStoreId(args[5]);
                slotType = divineSlotLabelType(args[5]);
                final KeyStoreContainer container = KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], storeId, slotType, null, protectionParameter);
                boolean failure = false;
                for (int i = 6; i < args.length; i++) {
                    try {
                        container.installCertificate(args[i]);
                    } catch (Exception ex) {
                        failure = true;
                        log.error("Failed: " + ex.getMessage());
                    }
                }
                if (failure) {
                    throw new Exception("At least one certificate could not be installed");
                }
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(INSTALL_TRUSTED_ROOT)) {
            if ( args.length < 7 ) {
                System.err.println(commandString + '<'+getKeyStoreDescription()+'>' + " <trusted root certificate in PEM format>");
                tooFewArguments(args);
            } else {
                String storeId = null;
                Pkcs11SlotLabelType slotType = null;
                storeId = trimStoreId(args[5]);
                slotType = divineSlotLabelType(args[5]);
                KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], storeId, slotType, null, protectionParameter).installTrustedRoot(args[6]);
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(ENCRYPT_SWITCH)) {
            String symmAlgOid = CMSEnvelopedGenerator.AES128_CBC;
            if ( args.length < 7 ) {
                System.err.println("There are two ways of doing the encryption:");
                System.err.println(commandString + '<'+getKeyStoreDescription()+'>' + " <input file> <output file> <key alias> [optional symm algorithm oid]");
                System.err.println(commandStringNoSharedLib + "<input file> <output file> <file with certificate with public key to use> [optional symm algorithm oid]");
                System.err.println("Optional symmetric encryption algorithm OID can be for example 2.16.840.1.101.3.4.1.42 (AES256_CBC) or 1.2.392.200011.61.1.1.1.4 (CAMELLIA256_CBC). Default is to use AES256_CBC.");
                tooFewArguments(args);
            } else if ( args.length < 9 ) {
                Security.addProvider( new BouncyCastleProvider() );
                if (args.length > 7) {
                    // We have a symmAlg as last parameter
                    symmAlgOid = args[7];
                }
                System.err.println("Using symmetric encryption algorithm: "+symmAlgOid);
                final X509Certificate cert = (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new BufferedInputStream(new FileInputStream(args[6])));
                CMS.encrypt(new FileInputStream(args[2]), new FileOutputStream(args[5]), cert, symmAlgOid);
            } else {
                if (args.length > 9) {
                    // We have a symmAlg as last parameter
                    symmAlgOid = args[9];
                }
                System.err.println("Using symmstric encryption algorithm: "+symmAlgOid);
                String storeId = null;
                Pkcs11SlotLabelType slotType = null;
                storeId = trimStoreId(args[5]);
                slotType = divineSlotLabelType(args[5]);
                KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], storeId, slotType, null, protectionParameter).encrypt(new FileInputStream(args[6]), new FileOutputStream(args[7]), args[8], symmAlgOid);
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(DECRYPT_SWITCH)) {
            if ( args.length < 9 ) {
                System.err.println(commandString + '<'+getKeyStoreDescription()+'>' + " <input file> <output file> <key alias>");
                tooFewArguments(args);
            } else {
                String storeId = null;
                Pkcs11SlotLabelType slotType = null;
                storeId = trimStoreId(args[5]);
                slotType = divineSlotLabelType(args[5]);
                KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], storeId, slotType, null, protectionParameter).decrypt(new FileInputStream(args[6]), new FileOutputStream(args[7]), args[8]);
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(SIGN_SWITCH)) {
            if ( args.length < 9 ) {
                System.err.println(commandString + '<'+getKeyStoreDescription()+'>' + " <input file> <output file> <key alias>");
                tooFewArguments(args);
            } else {
                String storeId = null;
                Pkcs11SlotLabelType slotType = null;
                storeId = trimStoreId(args[5]);
                slotType = divineSlotLabelType(args[5]);
                KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], storeId, slotType, null, protectionParameter).sign(new FileInputStream(args[6]), new FileOutputStream(args[7]), args[8]);
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(LINKCERT_SWITCH)) {
            if ( args.length < 10 ) {
                System.err.println(commandString + '<'+getKeyStoreDescription()+'>' + " <old ca-cert> <new ca-cert> <output link-cert> <key alias> [<sig alg override>]");
                System.err.println();
                System.err.println("Creates a link certificate that links the old and new certificate files.");
                System.err.println("You should use this command with the old HSM key. It does not need any");
                System.err.println("access to the new key.");
                System.err.println();
                tooFewArguments(args);
            } else {
                String storeId = null;
                Pkcs11SlotLabelType slotType = null;
                storeId = trimStoreId(args[5]);
                slotType = divineSlotLabelType(args[5]);
                final KeyStoreContainer ksc = KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], storeId, slotType, null, protectionParameter);
                final String alias = args[9];
                final String oldCertPath = args[6];
                final String newCertPath = args[7];
                final String outputPath = args[8];
                final String signProviderName = ksc.getProviderName();
                final String sigAlgOverride = (args.length >= 11 ? args[10] : "null");
                
                // Parse certificates
                final byte[] oldCertBytes = IOUtils.toByteArray(new FileInputStream(oldCertPath));
                final byte[] newCertBytes = IOUtils.toByteArray(new FileInputStream(newCertPath));
                final Certificate oldCert = CertTools.getCertfromByteArray(oldCertBytes, BouncyCastleProvider.PROVIDER_NAME);
                final Certificate newCert = CertTools.getCertfromByteArray(newCertBytes, BouncyCastleProvider.PROVIDER_NAME);
                final boolean isCVCA = (oldCert instanceof CardVerifiableCertificate);
                if (isCVCA != (newCert instanceof CardVerifiableCertificate)) {
                    log.error("Error: Old and new certificates are not of the same type (X509 / CVC)");
                    return true; // = valid command-line syntax
                }
                System.err.println("Type of certificates: "+(isCVCA ? "CVC" : "X509"));
                
                // Detect name change
                final String oldDN = CertTools.getSubjectDN(oldCert);
                final String newDN = CertTools.getSubjectDN(newCert);
                System.err.println("Old DN: "+oldDN);
                System.err.println("New DN: "+newDN);
                final boolean nameChange;
                if (!oldDN.equals(newDN)) {
                    if (isCVCA) {
                        System.err.println("Name change detected.");
                    } else {
                        System.err.println("Name change detected. Will add Name Change extension.");
                    }
                    nameChange = true;
                } else {
                    System.err.println("No name change detected.");
                    nameChange = false;
                }
                
                final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                
                // Get new and old key
                PublicKey newPubKey = newCert.getPublicKey();
                if (newPubKey == null) {
                    System.err.println("Error: Failed to extract public key from new certificate");
                    return true;
                }
                final Key oldKey = ksc.getKey(alias);
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
                    System.err.println("Using signature algorithm "+linkSigAlg);
                    
                    final HolderReferenceField caHolder = oldCertCVC.getCertificateBody().getHolderReference();
                    final CAReferenceField caRef = new CAReferenceField(caHolder.getCountry(), caHolder.getMnemonic(), caHolder.getSequence());
                    final HolderReferenceField certHolder = newCertCVC.getCertificateBody().getHolderReference();
                    final AuthorizationRole authRole = newCertCVC.getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getAuthRole();                    
                    final AccessRights rights = newCertCVC.getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getAccessRights();
                    final Date validFrom = new Date(new Date().getTime() - 60L*15L*1000L); // back date by 15 minutes to allow for clock skew
                    final Date validTo = oldCertCVC.getCertificateBody().getValidTo();
                    
                    final CVCertificate linkCert = CertificateGenerator.createCertificate(newPubKey, oldPrivKey, linkSigAlg, caRef, certHolder, authRole, rights, validFrom, validTo, signProviderName);
                    final DataOutputStream dos = new DataOutputStream(baos);
                    linkCert.encode(dos);
                    dos.close();
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
                    System.err.println("Using signature algorithm "+linkSigAlg);
                    
                    final BigInteger serno = SernoGeneratorRandom.instance().getSerno();
                    final SubjectPublicKeyInfo pkinfo = new SubjectPublicKeyInfo((ASN1Sequence)ASN1Primitive.fromByteArray(newPubKey.getEncoded()));
                    final Date validFrom = new Date(new Date().getTime() - 60L*15L*1000L); // back date by 15 minutes to allow for clock skew
                    final Date validTo = oldCertX509.getNotAfter();
                    
                    final X500Name oldDNName = X500Name.getInstance(oldCertX509.getSubjectX500Principal().getEncoded());
                    final X500Name newDNName = X500Name.getInstance(newCertX509.getSubjectX500Principal().getEncoded());
                    
                    final X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(oldDNName, serno, validFrom, validTo, newDNName, pkinfo);
                    
                    // Copy all extensions except AKID
                    final ExtensionsGenerator extgen = new ExtensionsGenerator();
                    final Set<String> oids = new LinkedHashSet<String>();
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
                final FileOutputStream fos = new FileOutputStream(outputPath);
                baos.writeTo(fos);
                fos.close();
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(VERIFY_SWITCH)) {
            final CMS.VerifyResult verifyResult;
            if ( args.length < 7 ) {
                System.err.println("There are two ways of doing the encryption:");
                System.err.println(commandString + '<'+getKeyStoreDescription()+'>' + " <input file> <output file> <key alias>");
                System.err.println(commandStringNoSharedLib + "<input file> <output file> <file with certificate with public key to use>");
                tooFewArguments(args);
                return true;
            } else if ( args.length < 9 ) {
                Security.addProvider( new BouncyCastleProvider() );
                final X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new BufferedInputStream(new FileInputStream(args[6])));
                verifyResult = CMS.verify(new FileInputStream(args[2]), new FileOutputStream(args[5]), cert);
            } else {
                String storeId = null;
                Pkcs11SlotLabelType slotType = null;
                storeId = trimStoreId(args[5]);
                slotType = divineSlotLabelType(args[5]);
                verifyResult = KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], storeId, slotType, null, protectionParameter).verify(new FileInputStream(args[6]), new FileOutputStream(args[7]), args[8]);
            }
            if ( verifyResult==null ) {
                System.out.println("Not possible to parse signed file.");
                System.exit(4); // Not verifying // NOPMD, it's not a JEE app
            }
            System.out.println("The signature of the input " +(verifyResult.isVerifying?"has been":"could not be")+" verified. The file was signed on '"+verifyResult.signDate+"'. The public part of the signing key is in a certificate with serial number "+verifyResult.signerId.getSerialNumber()+" issued by '"+verifyResult.signerId.getIssuer()+"'.");
            if ( !verifyResult.isVerifying ) {
                System.exit(4); // Not verifying // NOPMD, it's not a JEE app
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(TEST_SWITCH)) {
            if ( args.length < 6 ) {
                System.err.println(commandString + '<'+getKeyStoreDescription()+'>' + " [<# of tests or threads>] [<alias for stress test>] [<type of stress test>]");
                System.err.println("    If a file named \"./testData\" exists then the data that is signed, is read from this file.");
                tooFewArguments(args);
            } else {
                String storeId = null;
                Pkcs11SlotLabelType slotType = null;
                storeId = trimStoreId(args[5]);
                slotType = divineSlotLabelType(args[5]);
                KeyStoreContainerTest.test(args[2], args[3], args[4], storeId, slotType,
                                           args.length>6 ? Integer.parseInt(args[6].trim()) : 1,
                                           args.length>7 ? args[7].trim() : null, args.length>8 ? args[8].trim() : null,
                                           protectionParameter);
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(RENAME)) {
            if ( args.length < 8 ) {
                System.err.println(commandString + '<'+getKeyStoreDescription()+'>' + " <old key alias> <new key alias>");
                tooFewArguments(args);
            } else {
                String storeId = null;
                Pkcs11SlotLabelType slotType = null;
                storeId = trimStoreId(args[5]);
                slotType = divineSlotLabelType(args[5]);
                KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], storeId, slotType, null, protectionParameter).renameAlias(args[6], args[7]);
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(MOVE_SWITCH)) {
            if ( args.length < 7 ) {
                System.err.println(commandString + "<from "+getKeyStoreDescription()+"> <to "+getKeyStoreDescription()+'>');
                tooFewArguments(args);
            } else {
                String fromId = args[5];                    
                String toId = args[6];
                Pkcs11SlotLabelType slotType = null;
                slotType = divineSlotLabelType(args[5]);
                System.err.println("Moving entry with alias '"+fromId+"' to alias '"+toId+'.');
                KeyStoreContainerBase.move(args[2], args[3], args[4], fromId, toId, slotType, protectionParameter);
            }
            return true;
        }
        if ( doCreateKeyStore() && args[1].toLowerCase().trim().contains(CREATE_KEYSTORE_SWITCH)) {
            if( args[1].toLowerCase().trim().contains(CREATE_KEYSTORE_MODULE_SWITCH)) {
                setModuleProtection();
            }
            KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], null, Pkcs11SlotLabelType.SUN_FILE, null, protectionParameter).storeKeyStore();
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
            PrintWriter pw = new PrintWriter(System.err);
            pw.println("Use one of following commands: ");
//            pw.println("  "+args[0]+" "+CREATE_CA_SWITCH);
            pw.println("  "+args[0]+" "+GENERATE_SWITCH);
            pw.println("  "+args[0]+" "+GENERATE_BATCH_SWITCH);
            if ( doModuleProtection() ) {
                pw.println("  "+args[0]+" "+GENERATE_MODULE_SWITCH);
            }
            pw.println("  "+args[0]+" "+CERT_REQ);
            pw.println("  "+args[0]+" "+INSTALL_CERT);
            pw.println("  "+args[0]+" "+DELETE_SWITCH);
            pw.println("  "+args[0]+" "+TEST_SWITCH);
            pw.println("  "+args[0]+" "+RENAME);
            if ( doCreateKeyStore() ){
                pw.println("  "+args[0]+" "+CREATE_KEYSTORE_SWITCH);
                if ( doModuleProtection() ) {
                    pw.println("  "+args[0]+" "+CREATE_KEYSTORE_MODULE_SWITCH);
                }
            }
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
                log.error("Command '"+commandString(args)+"' not found.");
            }
            System.exit(1); // Command not found.  // NOPMD, it's not a JEE app
        } catch (Throwable e) {
            System.err.println("Command could not be executed. See log for stack trace.");
            log.error("Command '"+commandString(args)+"' could not be executed.", e);
            System.exit(2); // Command did not execute OK! // NOPMD, it's not a JEE app
        }
    }
    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.ClientToolBox#getName()
     */
    @Override
    protected String getName() {
        return "HSMKeyTool";
    }
    
    private static final String trimStoreId(String storeId) {
        if(storeId.contains(":")) {
            return storeId.split(":", 2)[1];
        } else {
            return storeId;
        }
    }
    
    private static final Pkcs11SlotLabelType divineSlotLabelType(String storeId) {
        if(storeId.contains(":")) {
            String prefix = storeId.split(":", 2)[0].trim();
            if(prefix.equals("TOKEN_LABEL") || prefix.equals(Pkcs11SlotLabelType.SLOT_LABEL.getKey())) {
                return Pkcs11SlotLabelType.SLOT_LABEL;
            } else if (prefix.equals("SLOT_ID") || prefix.equals(Pkcs11SlotLabelType.SLOT_NUMBER.getKey())) {
                return Pkcs11SlotLabelType.SLOT_NUMBER;
            } else if (prefix.equals("SLOT_LIST_IX") || prefix.equals(Pkcs11SlotLabelType.SLOT_INDEX.getKey())) {
                return Pkcs11SlotLabelType.SLOT_INDEX;
            } else {
                throw new IllegalArgumentException("Type " + prefix + " was not valid");
            }
                
        } else {
            if(Pkcs11SlotLabelType.SLOT_NUMBER.validate(storeId)) {
                return Pkcs11SlotLabelType.SLOT_NUMBER;
            } else if(Pkcs11SlotLabelType.SLOT_INDEX.validate(storeId)) {
                return Pkcs11SlotLabelType.SLOT_INDEX;
            } else {
                return Pkcs11SlotLabelType.SLOT_LABEL;
            }
        }
    }
}
