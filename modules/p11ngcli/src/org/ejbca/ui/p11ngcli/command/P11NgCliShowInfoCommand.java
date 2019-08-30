package org.ejbca.ui.p11ngcli.command;

import java.io.File;

import org.apache.log4j.Logger;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.pkcs11.jacknji11.CEi;
import org.pkcs11.jacknji11.CK_INFO;
import org.pkcs11.jacknji11.Ci;
import org.pkcs11.jacknji11.jna.JNAi;
import org.pkcs11.jacknji11.jna.JNAiNative;

import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;

public class P11NgCliShowInfoCommand extends P11NgCliCommandBase {
    
    private static final Logger log = Logger.getLogger(P11NgCliShowInfoCommand.class);
    
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
        return "showinfo";
    }

    @Override
    public String getCommandDescription() {
        return "Shows information about HSM.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
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
            CK_INFO info = ce.GetInfo();
            System.out.println("info: " + info);
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
