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

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSEnvelopedGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ejbca.util.CMS;
import org.ejbca.util.CliTools;
import org.ejbca.util.keystore.KeyStoreContainer;
import org.ejbca.util.keystore.KeyStoreContainerBase;
import org.ejbca.util.keystore.KeyStoreContainerFactory;



/**
 * Manages a key store on a HSM. This class may be extended by a class specific for a typical HSM.
 * 
 * @author primelars
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
    private static final String DELETE_SWITCH = "delete";
    private static final String TEST_SWITCH = "test";
    private static final String CREATE_KEYSTORE_SWITCH = "createkeystore";
    private static final String CREATE_KEYSTORE_MODULE_SWITCH = CREATE_KEYSTORE_SWITCH+"module";
    private static final String MOVE_SWITCH = "move";
    private static final String CERT_REQ = "certreq";
    private static final String INSTALL_CERT = "installcert";
    private static final String RENAME = "rename";
    private static final String INSTALL_TRUSTED_ROOT = "installtrusted";
    private static final Object SIGN_SWITCH = "sign";

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
    private String commandString(String[] sa) {
        String s = "";
        for ( int i=0; i<sa.length; i++) {
            s += sa[i];
            if (i+1<sa.length) {
                s += " ";
            }
        }
        return s;
    }
    private void tooFewArguments(String[] args) {
        log.error("Too few arguments in command: '"+commandString(args)+'\'');
        System.exit(3); // NOPMD, it's not a JEE app
    }
    private boolean doIt(String[] args) throws Exception {
        final String commandStringNoSharedLib = args[0]+" "+args[1]+" ";
        final String commandString = commandStringNoSharedLib+getProviderParameterDescription()+" ";
        /*if ( args[1].toLowerCase().trim().equals(CREATE_CA_SWITCH)) {
            try {
                new HwCaInitCommand(args).execute();
            } catch (Exception e) {
                System.out.println(e.getMessage());            
                //e.printStackTrace();
                System.exit(-1);
            }
            return true;
        } else */
        if ( args[1].toLowerCase().trim().contains(GENERATE_SWITCH) ) {
            if ( args.length < 6 ) {
                System.err.println(commandString + "<all decimal digits RSA key with specified length, otherwise name of ECC curve or DSA key using syntax DSAnnnn> <key entry name> " + '['+'<'+getKeyStoreDescription()+'>'+']');
                generateComment();
                tooFewArguments(args);
            } else {
                if ( args[1].toLowerCase().trim().contains(GENERATE_MODULE_SWITCH) ) {
                    setModuleProtection();
                }
                KeyStoreContainer store = KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], args.length>7 ? args[7] : null, null, null);
                String keyEntryName = args.length>6 ? args[6] :"myKey";
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
                KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], args[5], null, null).delete(alias);
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(CERT_REQ)) {
        	// First we check if we have a switch for "-explicitecc" for explicit ecc parameters used in ICAO epassports.
    		List<String> argsList = CliTools.getAsModifyableList(args);
    		boolean explicitEccParameters = argsList.remove("-explicitecc");
    		args = argsList.toArray(new String[0]);
            if ( args.length < 7 ) {
                System.err.println(commandString + '<'+getKeyStoreDescription()+'>' + " <key entry name> [<CN>] -explicitecc");
                tooFewArguments(args);
            } else {
                KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], args[5], null, null).generateCertReq(args[6], args.length>7 ? args[7] : null, explicitEccParameters);
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(INSTALL_CERT)) {
            if ( args.length < 7 ) {
                System.err.println(commandString + '<'+getKeyStoreDescription()+'>' + " <certificate chain in PEM format>");
                tooFewArguments(args);
            } else {
                KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], args[5], null, null).installCertificate(args[6]);
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(INSTALL_TRUSTED_ROOT)) {
            if ( args.length < 7 ) {
                System.err.println(commandString + '<'+getKeyStoreDescription()+'>' + " <trusted root certificate in PEM format>");
                tooFewArguments(args);
            } else {
                KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], args[5], null, null).installTrustedRoot(args[6]);
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
                System.err.println("Using symmstric encryption algorithm: "+symmAlgOid);
                final X509Certificate cert = (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new BufferedInputStream(new FileInputStream(args[6])));
                CMS.encrypt(new FileInputStream(args[2]), new FileOutputStream(args[5]), cert, symmAlgOid);
            } else {
                if (args.length > 9) {
                    // We have a symmAlg as last parameter
                    symmAlgOid = args[9];
                }
                System.err.println("Using symmstric encryption algorithm: "+symmAlgOid);
                KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], args[5], null, null).encrypt(new FileInputStream(args[6]), new FileOutputStream(args[7]), args[8], symmAlgOid);
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(DECRYPT_SWITCH)) {
            if ( args.length < 9 ) {
                System.err.println(commandString + '<'+getKeyStoreDescription()+'>' + " <input file> <output file> <key alias>");
                tooFewArguments(args);
            } else {
                KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], args[5], null, null).decrypt(new FileInputStream(args[6]), new FileOutputStream(args[7]), args[8]);
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(SIGN_SWITCH)) {
            if ( args.length < 9 ) {
                System.err.println(commandString + '<'+getKeyStoreDescription()+'>' + " <input file> <output file> <key alias>");
                tooFewArguments(args);
            } else {
                KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], args[5], null, null).sign(new FileInputStream(args[6]), new FileOutputStream(args[7]), args[8]);
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
                verifyResult = KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], args[5], null, null).verify(new FileInputStream(args[6]), new FileOutputStream(args[7]), args[8]);
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
                tooFewArguments(args);
            } else {
                KeyStoreContainerTest.test(args[2], args[3], args[4], args[5],
                                           args.length>6 ? Integer.parseInt(args[6].trim()) : 1, args.length>7 ? args[7].trim() : null, args.length>8 ? args[8].trim() : null);
            }
            return true;
        }
        if ( args[1].toLowerCase().trim().equals(RENAME)) {
            if ( args.length < 8 ) {
                System.err.println(commandString + '<'+getKeyStoreDescription()+'>' + " <old key alias> <new key alias>");
                tooFewArguments(args);
            } else {
                KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], args[5], null, null).renameAlias(args[6], args[7]);
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
                System.err.println("Moving entry with alias '"+fromId+"' to alias '"+toId+'.');
                KeyStoreContainerBase.move(args[2], args[3], args[4], fromId, toId, null);
            }
            return true;
        }
        if ( doCreateKeyStore() && args[1].toLowerCase().trim().contains(CREATE_KEYSTORE_SWITCH)) {
            if( args[1].toLowerCase().trim().contains(CREATE_KEYSTORE_MODULE_SWITCH)) {
                setModuleProtection();
            }
            KeyStoreContainerFactory.getInstance(args[4], args[2], args[3], null, null, null).storeKeyStore();
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
}
