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

import java.io.File;
import java.io.IOException;

/**
 * Holds arguments given by the user.
 * @author Lars Silven PrimeKey Solution AB
 * @version $Id$
 *
 */
class Arguments {
	/**
	 * The command to be executed.
	 */
	final CommandLine commandLine;
	/**
	 * Input file.
	 */
	final File inputFile;
	/**
	 * Output file.
	 */
	final File outputFile;
	/**
	 * Password.
	 */
	final String password;
	/**
	 * Evaluates arguments given by the user.
	 * @param args
	 * @throws IOException
	 */
	Arguments(final String[] args) throws IOException {
		this.commandLine = new CommandLine(args[1], args.length>2 ? args[2]:null);
		if ( this.commandLine.hasInput() && this.commandLine.hasOutput() ) {
			if ( args.length<5 ) {
				System.err.println("You got to give both input and output file for the command:"+this.commandLine.showCommand());
				System.exit(-1); // NOPMD, it's not a JEE app
			}
			this.inputFile = new File(args[3]).getCanonicalFile();
			this.outputFile = new File(args[4]).getCanonicalFile();
		} else if ( this.commandLine.hasInput() ) {
			if ( args.length<4 ) {
				System.err.println("You got to give input file for the command:"+this.commandLine.showCommand());
				System.exit(-1); // NOPMD, it's not a JEE app
			}
			this.inputFile = new File(args[3]).getCanonicalFile();
			this.outputFile = null;
		} else if ( this.commandLine.hasOutput() ) {
			if ( args.length<4 ) {
				System.err.println("You got to give output file for the command:"+this.commandLine.showCommand());
				System.exit(-1); // NOPMD, it's not a JEE app
			}
			this.inputFile = null;
			this.outputFile = new File(args[3]).getCanonicalFile();
		} else {
			this.inputFile = null;
			this.outputFile = null;
		}
		if ( this.inputFile!=null && !this.inputFile.isFile() ) {
			System.err.println("Input file '"+this.inputFile.getPath()+"' does not exist.");
			System.exit(-1); // NOPMD, it's not a JEE app
		}
		if ( this.inputFile!=null && !this.inputFile.canRead() ) {
			System.err.println("Input file '"+this.inputFile.getPath()+"' is not readable.");
			System.exit(-1); // NOPMD, it's not a JEE app
		}
		if ( this.outputFile!=null && this.outputFile.exists() ) {
			System.err.println("Output file '"+this.outputFile.getPath()+"' does already exist.");
			System.exit(-1); // NOPMD, it's not a JEE app
		}
		final File outputDir = this.outputFile!=null ? this.outputFile.getParentFile() : null;
		if ( this.outputFile!=null && !outputDir.isDirectory()  ) {
			System.err.println("Output directory '"+outputDir.getPath()+"' is not existing.");
			System.exit(-1); // NOPMD, it's not a JEE app
		}
		if ( this.outputFile!=null && !outputDir.canWrite() ) {
			System.err.println("Output directory '"+outputDir.getPath()+"' is not writable.");
			System.exit(-1); // NOPMD, it's not a JEE app
		}
		if ( this.commandLine.passwordPrompt!=null ) {
			System.err.print(this.commandLine.passwordPrompt);
			this.password = String.valueOf(System.console().readPassword());            	
			System.err.println();
		} else {
			this.password = null;
		}
	}
}
