package org.ejbca.ui.p11ngcli.helper;

import java.io.File;

import org.apache.log4j.Logger;
import org.ejbca.ui.p11ngcli.command.P11NgCliListSlotsCommand;
import org.pkcs11.jacknji11.CEi;
import org.pkcs11.jacknji11.Ci;
import org.pkcs11.jacknji11.jna.JNAi;
import org.pkcs11.jacknji11.jna.JNAiNative;

import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;

public final class P11NgCliHelper {
    
    private static final Logger log = Logger.getLogger(P11NgCliListSlotsCommand.class);
    
    public static CEi provideCe(final String lib) {
        final File library = new File(lib);
        final String libDir = library.getParent();
        final String libName = library.getName();
        log.debug("Adding search path: " + libDir);
        NativeLibrary.addSearchPath(libName, libDir);
        JNAiNative jnaiNative = (JNAiNative) Native.loadLibrary(libName, JNAiNative.class);
        return new CEi(new Ci(new JNAi(jnaiNative)));
    }

}
