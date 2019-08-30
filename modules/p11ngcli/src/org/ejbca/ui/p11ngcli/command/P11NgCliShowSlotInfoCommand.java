package org.ejbca.ui.p11ngcli.command;

import org.apache.log4j.Logger;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.ejbca.ui.p11ngcli.helper.P11NgCliHelper;
import org.pkcs11.jacknji11.CEi;
import org.pkcs11.jacknji11.CK_SLOT_INFO;

public class P11NgCliShowSlotInfoCommand extends P11NgCliCommandBase {

    private static final Logger log = Logger.getLogger(P11NgCliShowSlotInfoCommand.class);

    private static final String LIBFILE = "-libfile";
    private static final String SLOT = "-slot";

    private static CEi ce;

    //Register all parameters
    {
        registerParameter(
                new Parameter(LIBFILE, "lib file", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, "Shared library path"));
        registerParameter(new Parameter(SLOT, "HSM slot", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Slot on the HSM which will be used."));
    }

    @Override
    public String getMainCommand() {
        return "showslotinfo";
    }

    @Override
    public String getCommandDescription() {
        return "Prints information about the slot.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        final String lib = parameters.get(LIBFILE);
        try {
            ce = P11NgCliHelper.provideCe(lib);
            final long slotId = Long.parseLong(parameters.get(SLOT));
            ce.Initialize();
            CK_SLOT_INFO info = ce.GetSlotInfo(slotId);
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
