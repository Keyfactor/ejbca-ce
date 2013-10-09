package org.ejbca.ui.cli;

/**
 * 
 * @version $Id$
 *
 */

public class CliCommand implements Comparable<CliCommand> {

	private final String mainCommand;
	private final String subCommand;
	private final String description;
	private final Class<CliCommandPlugin> commandClass;
	private final String[] commandAliases;
	private final String[] subcommandAliases;
	
    public CliCommand(String mainCommand, String[] commandAliases, String subCommand, final String[] subcommandAliases, String description, Class<CliCommandPlugin> commandClass) {
        this.mainCommand = mainCommand;
        this.subCommand = subCommand;
        this.description = description;
        this.commandClass = commandClass;
        this.commandAliases = commandAliases;
        this.subcommandAliases = subcommandAliases;
    }
	
	public String getMainCommand() { return this.mainCommand; }
	public String[] getCommandAliases() { return this.commandAliases; }
	public String getSubCommand() { return this.subCommand; }
	public String[] getSubCommandAliases() { return this.subcommandAliases; }
	public String getDescription() { return this.description; }
	public Class<CliCommandPlugin> getCommandClass() { return this.commandClass; }

	public int compareTo(CliCommand cliCommand) {
		if (getMainCommand()==null) {
			return getSubCommand().compareTo(cliCommand.getSubCommand());
		}
		final int ret = getMainCommand().compareTo(cliCommand.getMainCommand());
		if (ret==0) {
			return getSubCommand().compareTo(cliCommand.getSubCommand());
		}
		return ret;
	}
}
