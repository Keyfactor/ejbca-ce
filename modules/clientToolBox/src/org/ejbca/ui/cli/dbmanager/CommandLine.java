/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.cli.dbmanager;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.util.Iterator;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A command line to be executed.
 * @author Lars Silven PrimeKey Solution AB
 * @version $Id$
 *
 */
class CommandLine {
	private static final String INPUT_GZIP_SUFFIX="_input_gzip";
	private static final String OUTPUT_GZIP_SUFFIX="_output_gzip";
	private static final String PASSWORD_PROMPT_SUFFIX = "_password";
	private static final String RESOURCE_INPUT_SUFFIX = "_resource_input_name";
	private static final String COMMAND_SUFFIX = "_command";
	private static final String NEXT_COMMAND_SUFFIX = "_nextCommand";

	final private DataBaseConfig dataBaseConfig;
	final private String commandLine;
	final private String nextCommandLine;
	final private String command;
	final private String gzipInput;
	final private String gzipOutput;
	final private String resourceInputName;
	final private String ejbcaHome;
	/**
	 * The text to be showed to the user when he should give a password.
	 */
	final String passwordPrompt;
	
	/**
	 * Read information from the properties file of the used DB.
	 * @param ejbcaHome the root directory of EJBCA
	 * @param _command the command label
	 * @throws IOException should not be thrown
	 */
	CommandLine(String _ejbcaHome, String _command) throws IOException {
		this.ejbcaHome = _ejbcaHome;
		this.command = _command;
		final String vaPrefix = "va-";
		this.dataBaseConfig = new DataBaseConfig(this.ejbcaHome, this.command!=null && this.command.substring(0, vaPrefix.length()).equals(vaPrefix));
		final Properties properties = new Properties();
		properties.load(getResourceInputStream("config.properties"));
		if ( this.command==null ) {
			System.err.println("No command given.");
			listAvailableCommands(properties);
			System.exit(-1); // NOPMD, this is not a JEE app
		}
		this.commandLine=properties.getProperty(this.command+COMMAND_SUFFIX);
		this.nextCommandLine=properties.getProperty(this.command+NEXT_COMMAND_SUFFIX);
		if ( this.commandLine==null ) {
			System.err.println("Command '"+this.command+"' not available.");
			listAvailableCommands(properties);
			System.exit(-1); // NOPMD, this is not a JEE app
		}
		this.gzipInput = (String)properties.get(this.command+INPUT_GZIP_SUFFIX);
		this.gzipOutput = (String)properties.get(this.command+OUTPUT_GZIP_SUFFIX);
		this.passwordPrompt = (String)properties.get(this.command+PASSWORD_PROMPT_SUFFIX);

		this.resourceInputName = (String)properties.get(this.command+RESOURCE_INPUT_SUFFIX);
		if ( this.resourceInputName!=null && this.gzipInput!=null ) {
			throw new Error("Wrong configuration in the file bundled in the jar. It can not be both a '"+RESOURCE_INPUT_SUFFIX+"' and a '"+INPUT_GZIP_SUFFIX+"' for the same command." );
		}
	}
	private InputStream getResourceInputStream(String name) {
		final String resourcePropertiesName = "/DBCommands/"+this.dataBaseConfig.dbName+"/"+name;
		return DBManager.class.getResourceAsStream(resourcePropertiesName);
	}
	InputStream getInputStream() throws IOException {
		if ( this.resourceInputName==null ) {
			return null;
		}
		final InputStreamReader isr = new InputStreamReader( getResourceInputStream(this.resourceInputName) );
		final BufferedReader bf = new BufferedReader(isr);
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		final PrintStream ps = new PrintStream(baos);
		while ( true ) {
			final String nextLine = bf.readLine();
			if ( nextLine==null ) {
				break;
			}
			ps.println(this.dataBaseConfig.parseCommandline(nextLine, null));
		}
		ps.close();
		return new ByteArrayInputStream(baos.toByteArray());
	}
	private void listAvailableCommands(Properties properties) {
		final Set<Object> keySet = properties.keySet();
		final Iterator<Object> i=keySet.iterator();
		System.err.println("Available commands are:");
		while( i.hasNext() ) {
			final String key=(String)i.next();
			if ( !key.matches(".*"+Pattern.quote(COMMAND_SUFFIX)+"$") ) {
				continue;
			}
			System.err.println( key.substring(0,key.length()-COMMAND_SUFFIX.length()) );
		}
	}
	/**
	 * @return true if the user should give the name of a gzip file to be used for input.
	 */
	boolean hasInput() {
		return this.gzipInput!=null;
	}
	/**
	 * @return true if the user should give the name of a gzip file to be used for output.
	 */
	boolean hasOutput() {
		return this.gzipOutput!=null;
	}
	/**
	 * @return A string that shows the syntax of the command line.
	 */
	String showCommand() {
		return " "+this.command+(this.gzipInput!=null ? " <"+this.gzipInput+">" : "")+(this.gzipOutput!=null ? " <"+this.gzipOutput+">" : "");
	}
	/**
	 * @return A string that shows the syntax of the command line.
	 */
	String getIt(String password) {
		return this.dataBaseConfig.parseCommandline(this.commandLine, password);
	}
	/**
	 * @return
	 * @throws IOException
	 */
	CommandLine getNext() throws IOException {
		if ( this.nextCommandLine==null ) {
			return null;
		}
		return new CommandLine(this.ejbcaHome, this.nextCommandLine);
	}
}
