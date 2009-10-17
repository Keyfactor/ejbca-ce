package org.ejbca.ui.cli;

public class CliCommand implements Comparable {

	private final String mainCommand;
	private final String subCommand;
	private final String description;
	private final Class<?> commandClass;
	
	public CliCommand(String mainCommand, String subCommand, String description, Class<?> commandClass) {
		this.mainCommand = mainCommand;
		this.subCommand = subCommand;
		this.description = description;
		this.commandClass = commandClass;
	}
	
	public String getMainCommand() { return mainCommand; }
	public String getSubCommand() { return subCommand; }
	public String getDescription() { return description; }
	public Class<?> getCommandClass() { return commandClass; }

	public int compareTo(Object arg0) {
		if (!(arg0 instanceof CliCommand)) {
			return 0;
		}
		CliCommand cliCommand = (CliCommand) arg0;
		if (getMainCommand()==null) {
			return getSubCommand().compareTo(cliCommand.getSubCommand());
		} else {
			int ret = getMainCommand().compareTo(cliCommand.getMainCommand());
			if (ret==0) {
				ret = getSubCommand().compareTo(cliCommand.getSubCommand());
			}
			return ret;
		}
	}
}
