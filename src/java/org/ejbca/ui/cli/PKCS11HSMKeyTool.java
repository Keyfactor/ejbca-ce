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
public class PKCS11HSMKeyTool extends HSMKeyTool {

    @Override
    public void execute(String[] args) {
        if (args.length<3) {
            super.execute(args);
            return;
        }
        final List<String> lArgs = new ArrayList<String>();
        lArgs.add(args[0]);
        lArgs.add(args[1]);
        lArgs.add(args[2]); // library name
        lArgs.add("null");
        lArgs.add(KeyStoreContainer.KEYSTORE_TYPE_PKCS11);
        for ( int i=3; i<args.length; i++)
            lArgs.add(args[i]);
        super.execute(lArgs.toArray(new String[]{}));
    }

    @Override
    String getName() {
        return "PKCS11HSMKeyTool";
    }

    @Override
    String getProviderParameterDescription() {
        return "<shared library name>";
    }

    @Override
    String getKeyStoreDescription() {
        return "slot number. start with \'i\' to indicate index in list";
    }

    @Override
    void generateComment() {
        System.err.println("If <slot number> is omitted then <the shared library name> will specify the sun config file.");
    }

    @Override
    boolean doCreateKeyStore() {
        return false;
    }

}
