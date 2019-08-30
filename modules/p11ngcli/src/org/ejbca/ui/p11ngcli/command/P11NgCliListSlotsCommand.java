package org.ejbca.ui.p11ngcli.command;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.apache.log4j.Logger;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.pkcs11.jacknji11.CEi;
import org.pkcs11.jacknji11.CK_TOKEN_INFO;
import org.pkcs11.jacknji11.Ci;
import org.pkcs11.jacknji11.jna.JNAi;
import org.pkcs11.jacknji11.jna.JNAiNative;

import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;

public class P11NgCliListSlotsCommand extends P11NgCliCommandBase {
    
    private static final Logger log = Logger.getLogger(P11NgCliListSlotsCommand.class);
    
    private static final String LIBFILE = "-libfile";
    private static CEi ce;
    
    //Register all parameters
    {
        registerParameter(
                new Parameter(LIBFILE, "lib file", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "Shared library path"));
    }

    @Override
    public String getMainCommand() {
        return "listslots";
    }

    @Override
    public String getCommandDescription() {
        return "Lists slots available on the HSM";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        log.trace(">executeCommand");
        final String lib = parameters.get(LIBFILE);
        try {
            final File library = new File(lib);
            final String libDir = library.getParent();
            final String libName = library.getName();
            log.debug("Adding search path: " + libDir);
            NativeLibrary.addSearchPath(libName, libDir);
            JNAiNative jnaiNative = (JNAiNative) Native.loadLibrary(libName, JNAiNative.class);
            ce = new CEi(new Ci(new JNAi(jnaiNative)));
            
            ce.Initialize();
            long[] allSlots = ce.GetSlotList(false);
            System.out.println("All slots:        " + Arrays.toString(allSlots));
            long[] slots = ce.GetSlotList(true);
            System.out.println("Slots with token: " + Arrays.toString(slots));
            
            for (long slot : allSlots) {
                CK_TOKEN_INFO info = ce.GetTokenInfo(slot);
                System.out.println("ID: " + slot + ", Label: " + new String(info.label, StandardCharsets.UTF_8));
            }
        } finally {
            ce.Finalize();
        }
        return CommandResult.SUCCESS;
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
}
