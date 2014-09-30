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

import java.util.ArrayList;
import java.util.List;

import org.ejbca.util.keystore.KeyStoreContainer;

/**
 * Used for p11 HSMs.
 * 
 * @author primelars
 * @version $Id$
 *
 */
public class PKCS11HSMKeyTool extends HSMKeyTool {

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.HSMKeyTool#execute(java.lang.String[])
     */
    @Override
	protected void execute(String[] args) {
        if (args.length<3) {
            super.execute(args);
            return;
        }
        final List<String> lArgs = new ArrayList<String>();
        lArgs.add(args[0]);// toolname
        lArgs.add(args[1]);// keytool command
        lArgs.add(args[2]);// signature provider contains the p11 shared lib.
        lArgs.add("null");// decryption provider not uses
        lArgs.add(KeyStoreContainer.KEYSTORE_TYPE_PKCS11);
        for ( int i=3; i<args.length; i++) { // rest of the arguments
            lArgs.add(args[i]);
        }
        super.execute(lArgs.toArray(new String[]{}));
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.HSMKeyTool#getName()
     */
    @Override
    protected String getName() {
        return "PKCS11HSMKeyTool";
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.HSMKeyTool#getProviderParameterDescription()
     */
    @Override
    String getProviderParameterDescription() {
        return "<shared library name>";
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.HSMKeyTool#getKeyStoreDescription()
     */
    @Override
    String getKeyStoreDescription() {
        return "slot number. Index with \'i\' to indicate index in slot list. To get the slot from the label of the token in the slot give the label indexed by \'SLOT_LABEL:\'.";
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.HSMKeyTool#generateComment()
     */
    @Override
    void generateComment() {
        System.err.println("If <slot number> is omitted then <the shared library name> will specify the sun config file.");
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.HSMKeyTool#doCreateKeyStore()
     */
    @Override
    boolean doCreateKeyStore() {
        return false;
    }

}
