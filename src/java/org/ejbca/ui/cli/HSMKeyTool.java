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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.PrintWriter;



/**
 * @author lars
 * @version $Id: HSMKeyTool.java,v 1.25 2008-02-06 14:25:24 primelars Exp $
 *
 */
public class HSMKeyTool {
//    private static String CREATE_CA_SWITCH = "createca";
    private static String ENCRYPT_SWITCH = "encrypt";
    private static String DECRYPT_SWITCH = "decrypt";
    private static String GENERATE_SWITCH = "generate";
    private static String DELETE_SWITCH = "delete";
    private static String TEST_SWITCH = "test";
    private static String CREATE_KEYSTORE_SWITCH = "createkeystore";
    private static String CREATE_KEYSTORE_MODULE_SWITCH = "createkeystoremodule";
    private static String MOVE_SWITCH = "move";
    /**
     * @param args
     */
    public static void main(String[] args) {
        try {
            final boolean isP11 = args.length>4 && KeyStoreContainer.isP11(args[4]);
            final String sKeyStore =  isP11 ? "<slot number. start with \'i\' to indicate index in list>" : "<keystore ID>";
            final String commandString = args[0] + " " + args[1] + (isP11 ? " <shared library name> " : " ");
            /*if ( args.length > 1 && args[1].toLowerCase().trim().equals(CREATE_CA_SWITCH)) {
                try {
                    new HwCaInitCommand(args).execute();
                } catch (Exception e) {
                    System.out.println(e.getMessage());            
                    //e.printStackTrace();
                    System.exit(-1);
                }
                return;
            } else */
            if ( args.length > 1 && args[1].toLowerCase().trim().equals(GENERATE_SWITCH)) {
                if ( args.length < 6 ) {
                    System.err.println(commandString + "<key size> <key entry name> " + '['+sKeyStore+']');
                    if ( isP11 )
                        System.err.println("If <slot number> is omitted then <the shared library name> will specify the sun config file.");
                } else
                    KeyStoreContainer.getIt(args[4], args[2], args[3], args.length>7 ? args[7] : null).generate(Integer.parseInt(args[5].trim()), args.length>6 ? args[6] :"myKey");
                return;
            } else if ( args.length > 1 && args[1].toLowerCase().trim().equals(DELETE_SWITCH)) {
                if ( args.length < 6 )
                    System.err.println(commandString + sKeyStore + " [<key entry name>]");
                else
                    KeyStoreContainer.getIt(args[4], args[2], args[3], args[5]).delete(args.length>6 ? args[6] : null);
                return;
            } else if ( args.length > 1 && args[1].toLowerCase().trim().equals(ENCRYPT_SWITCH)) {
                if ( args.length < 9 )
                    System.err.println(commandString + sKeyStore + " <input file> <output file> <key alias>");
                else
                    KeyStoreContainer.getIt(args[4], args[2], args[3], args[5]).encrypt(new FileInputStream(args[6]), new FileOutputStream(args[7]), args[8]);
                return;
            } else if ( args.length > 1 && args[1].toLowerCase().trim().equals(DECRYPT_SWITCH)) {
                if ( args.length < 9 )
                    System.err.println(commandString + sKeyStore + " <input file> <output file> <key alias>");
                else
                    KeyStoreContainer.getIt(args[4], args[2], args[3], args[5]).decrypt(new FileInputStream(args[6]), new FileOutputStream(args[7]), args[8]);
                return;
            } else if( args.length > 1 && args[1].toLowerCase().trim().equals(TEST_SWITCH)) {
                if ( args.length < 6 )
                    System.err.println(commandString + sKeyStore + " [<# of tests>]");
                else
                    KeyStoreContainerTest.test(args[2], args[3], args[4], args[5], args.length>6 ? Integer.parseInt(args[6].trim()) : 1);
                return;
            } else if( args.length > 1 && args[1].toLowerCase().trim().equals(MOVE_SWITCH)) {
                if ( args.length < 7 )
                    System.err.println(commandString +
                                       (isP11 ? "<from slot number> <to slot number>" : "<from keystore ID> <to keystore ID>"));
                else
                    KeyStoreContainer.move(args[2], args[3], args[4], args[5], args[6]);
                return;
            } else if ( !isP11 ){
                if( args.length > 1 && args[1].toLowerCase().trim().equals(CREATE_KEYSTORE_SWITCH)) {
                    KeyStoreContainer.getIt(args[4], args[2], args[3], null).storeKeyStore();
                    return;
                } else if( args.length > 1 && args[1].toLowerCase().trim().equals(CREATE_KEYSTORE_MODULE_SWITCH)) {
                    System.setProperty("protect", "module");
                    KeyStoreContainer.getIt(args[4], args[2], args[3], null).storeKeyStore();
                    return;
                }
            }
            PrintWriter pw = new PrintWriter(System.err);
            pw.println("Use one of following commands: ");
//            pw.println("  "+args[0]+" "+CREATE_CA_SWITCH);
            pw.println("  "+args[0]+" "+GENERATE_SWITCH);
            pw.println("  "+args[0]+" "+DELETE_SWITCH);
            pw.println("  "+args[0]+" "+TEST_SWITCH);
            if ( !isP11 ){
                pw.println("  "+args[0]+" "+CREATE_KEYSTORE_SWITCH);
                pw.println("  "+args[0]+" "+CREATE_KEYSTORE_MODULE_SWITCH);
            }
            pw.println("  "+args[0]+" "+ENCRYPT_SWITCH);
            pw.println("  "+args[0]+" "+DECRYPT_SWITCH);
            pw.println("  "+args[0]+" "+MOVE_SWITCH);
            pw.flush();
        } catch (Throwable e) {
            e.printStackTrace(System.err);
        }
    }
}
