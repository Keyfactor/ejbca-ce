package org.ejbca.ui.cli;

import org.ejbca.core.model.log.Admin;

public abstract class BaseLogAdminCommand extends BaseAdminCommand {

    /**
     * Creates a new instance of BaseCaAdminCommand
     *
     * @param args command line arguments
     */
    public BaseLogAdminCommand(String[] args) {
        super(args, Admin.TYPE_CACOMMANDLINE_USER, "cli");
    }
}
