package org.ejbca.ui.cli;

public class LogAdminCommandFactory {

    private LogAdminCommandFactory() {
    }

    public static IAdminCommand getCommand(String[] args) {
        if (args.length < 1) {
            return null;
        }
        if (args[0].equals("verifyprotected")) {
            return new LogVerifyProtectedLogCommand(args);
        } else if (args[0].equals("accept")) {
            return new LogAcceptProtectedLogCommand(args);
        } else if (args[0].equals("resetexports")) {
            return new LogResetExportProtectedLogCommand(args);
        } else if (args[0].equals("resetprotected")) {
            return new LogResetProtectedLogCommand(args);
        } else {
            return null;
        }
    } // getCommand

}
