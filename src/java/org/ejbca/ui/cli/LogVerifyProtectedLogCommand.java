package org.ejbca.ui.cli;

import java.rmi.RemoteException;

import org.ejbca.core.model.log.ProtectedLogActions;
import org.ejbca.core.model.log.ProtectedLogEventIdentifier;

public class LogVerifyProtectedLogCommand extends BaseLogAdminCommand  {

	public static final String COMMAND_NAME = "verifyprotected";

	public LogVerifyProtectedLogCommand(String[] args) {
        super(args);
	}

	public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
		if (args.length < 2) {
			String msg = "Usage: LOG " + COMMAND_NAME + " <freezeThreshold>\n" +
			"Verify protected log. freezeThreshold is the oldest allowed log event for any node in seconds.\n";
			throw new IllegalAdminCommandException(msg);
		}
		long freezeThreshold = Long.parseLong(args[1]) * 1000;
		getOutputStream().print("Starting verification..\n");
        ProtectedLogActions protectedLogActions = new ProtectedLogActions(null);
        try {
			ProtectedLogEventIdentifier protectedLogEventIdentifier = getProtectedLogSession().verifyEntireLog(protectedLogActions, freezeThreshold);
			if (protectedLogEventIdentifier == null) {
				getOutputStream().print("Log verification OK!\n");
		        return;
			}
			getOutputStream().print("Failed to verify nodeGUID=" + protectedLogEventIdentifier.getNodeGUID() + " counter=" + protectedLogEventIdentifier.getCounter() + "\n");
		} catch (RemoteException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		getOutputStream().print("Log verification FAILED!\n");
	}
}
