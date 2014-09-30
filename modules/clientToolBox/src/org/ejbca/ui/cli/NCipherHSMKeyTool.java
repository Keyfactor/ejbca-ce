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

/**
 * To be used for a nCipher HSM with JCA keys.
 * @author primelars
 * @version $Id$
 *
 */
public class NCipherHSMKeyTool extends HSMKeyTool {

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.HSMKeyTool#execute(java.lang.String[])
     */
    @Override
	protected void execute(String[] args) {
        if (args.length<2) {
            super.execute(args);
            return;
        }
        final List<String> lArgs = new ArrayList<String>();
        lArgs.add(args[0]);// toolname
        lArgs.add(args[1]);// keytool command
        lArgs.add("com.ncipher.provider.km.nCipherKM"); // signature provider
        lArgs.add("com.ncipher.fixup.provider.nCipherRSAPrivateEncrypt");// decryption provider
        lArgs.add("nCipher.sworld");// keystore implementation name
        for ( int i=2; i<args.length; i++)  { // rest of the arguments
            lArgs.add(args[i]);
        }
        super.execute(lArgs.toArray(new String[]{}));
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.HSMKeyTool#getName()
     */
    @Override
    protected String getName() {
        return "NCipherHSMKeyTool";
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.HSMKeyTool#getProviderParameterDescription()
     */
    @Override
    String getProviderParameterDescription() {
        return "";
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.HSMKeyTool#doModuleProtection()
     */
    @Override
    boolean doModuleProtection() {
        return true;
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.HSMKeyTool#setModuleProtection()
     */
    @Override
    void setModuleProtection() {
        System.setProperty("protect", "module");
    }

}
