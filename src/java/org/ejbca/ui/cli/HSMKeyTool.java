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



/**
 * @author lars
 * @version $Id: HSMKeyTool.java,v 1.14 2007-02-10 21:31:13 primelars Exp $
 *
 */
public class HSMKeyTool {
    private static String CREATE_CA_SWITCH = "createca";
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
            if ( args.length > 1 && args[1].toLowerCase().trim().equals(CREATE_CA_SWITCH)) {
                try {
                    new HwCaInitCommand(args).execute();
                } catch (Exception e) {
                    System.out.println(e.getMessage());            
                    //e.printStackTrace();
                    System.exit(-1);
                }
            } else if ( args.length > 1 && args[1].toLowerCase().trim().equals(GENERATE_SWITCH)) {
                if ( args.length < 5 )
                    System.err.println(args[0] + " " + args[1] + " <key size> [<key entry name>] [<keystore ID>]");
                else
                    new KeyStoreContainer(args[3],args[2], args.length>6 ? args[6] : null).generate(Integer.parseInt(args[4].trim()), args.length>5 ? args[5] :"myKey");
            } else if ( args.length > 1 && args[1].toLowerCase().trim().equals(DELETE_SWITCH)) {
                if ( args.length < 5 )
                    System.err.println(args[0] + " " + args[1] + " <keystore ID> [<key entry name>]");
                else
                    new KeyStoreContainer(args[3], args[2], args[4]).delete(args.length>5 ? args[5] : null);
            } else if( args.length > 1 && args[1].toLowerCase().trim().equals(TEST_SWITCH)) {
                if ( args.length < 5 )
                    System.err.println(args[0] + " " + args[1] + " <keystore ID> [<# of tests>]");
                else
                    KeyStoreContainerTest.test(args[2], args[3], args[4], args.length>5 ? Integer.parseInt(args[5].trim()) : 1);
            } else if( args.length > 1 && args[1].toLowerCase().trim().equals(CREATE_KEYSTORE_SWITCH)) {
                new KeyStoreContainer(args[3], args[2], (byte[])null).storeKeyStore();
            } else if( args.length > 1 && args[1].toLowerCase().trim().equals(CREATE_KEYSTORE_MODULE_SWITCH)) {
                System.setProperty("protect", "module");
                new KeyStoreContainer(args[3], args[2], (byte[])null).storeKeyStore();
            } else if( args.length > 1 && args[1].toLowerCase().trim().equals(MOVE_SWITCH)) {
                if ( args.length < 6 )
                    System.err.println(args[0] + " " + args[1] + " <from keystore ID> <to keystore ID>");
                else
                    KeyStoreContainer.move(args[2], args[3], args[4], args[5]);
            } else
                System.err.println("Use \"" + args[0]+" "+CREATE_CA_SWITCH+"\" or \"" +
                                   args[0]+" "+GENERATE_SWITCH+"\" or \"" +
                                   args[0]+" "+DELETE_SWITCH+"\" or \"" +
                                   args[0]+" "+TEST_SWITCH+"\" or \"" +
                                   args[0]+" "+CREATE_KEYSTORE_SWITCH+"\" or \"" +
                                   args[0]+" "+CREATE_KEYSTORE_MODULE_SWITCH+"\" or \"" +
                                   args[0]+" "+MOVE_SWITCH+"\".");
        } catch (Throwable e) {
            e.printStackTrace(System.err);
        }
    }
}
