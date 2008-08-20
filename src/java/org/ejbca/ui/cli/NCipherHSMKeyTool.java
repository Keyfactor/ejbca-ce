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

import java.util.ArrayList;
import java.util.List;

/**
 * @author lars
 * @version $Id$
 *
 */
public class NCipherHSMKeyTool extends HSMKeyTool {

    @Override
    public void execute(String[] args) {
        if (args.length<2) {
            super.execute(args);
            return;
        }
        final List<String> lArgs = new ArrayList<String>();
        lArgs.add(args[0]);
        lArgs.add(args[1]);
        lArgs.add("com.ncipher.provider.km.nCipherKM");
        lArgs.add("com.ncipher.fixup.provider.nCipherRSAPrivateEncrypt");
        lArgs.add("nCipher.sworld");
        for ( int i=2; i<args.length; i++)
            lArgs.add(args[i]);
        super.execute(lArgs.toArray(new String[]{}));
    }

    @Override
    String getName() {
        return "NCipherHSMKeyTool";
    }

    @Override
    String getProviderParameterDescription() {
        return "";
    }

    @Override
    boolean doModuleProtection() {
        return true;
    }

    @Override
    void setModuleProtection() {
        System.setProperty("protect", "module");
    }

}
