/**
 * 
 */
package org.ejbca.ui.cli;

import java.util.ArrayList;
import java.util.List;

import org.ejbca.util.keystore.KeyStoreContainer;

/**
 * @author lars
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
