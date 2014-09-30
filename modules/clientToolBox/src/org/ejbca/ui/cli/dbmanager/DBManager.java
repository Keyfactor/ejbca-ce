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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import org.ejbca.ui.cli.ClientToolBox;


/**
 * Provides commands for management of the DB.
 * @author Lars Silven PrimeKey Solution AB
 * @version $Id$
 * 
 */
public class DBManager extends ClientToolBox {

	/* (non-Javadoc)
	 * @see org.ejbca.ui.cli.ClientToolBox#execute(java.lang.String[])
	 */
	@Override
	protected void execute(final String[] args) {
		if (args.length<2) {
			System.out.println(args[0]+" <EJBCA home> <command>");
			System.out.println("Give just the <EJBCA home> to get available commands for this database");
			return;
		}
		try {
			final Arguments arguments = new Arguments(args);
			doIt(arguments.commandLine.getIt(arguments.password), arguments.inputFile,
			     arguments.outputFile, arguments.commandLine.getInputStream(), arguments.commandLine.getNext());
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(-1); // NOPMD, this is not a JEE component
		}
	}
	private void doIt(String commandLine, File inputFile, File outputFile, InputStream is,
	                  CommandLine nextCommandLine) throws IOException {
		System.err.println("Executing: "+commandLine);
		final Process process = Runtime.getRuntime().exec(commandLine);
		if ( inputFile!=null ) {
			System.err.println("Input file: "+inputFile);
			unzipIt(process.getOutputStream(), inputFile);
		} else if ( is!=null ) {
			in2out(is,process.getOutputStream());
		}
		if ( nextCommandLine!=null ) {
			doIt(nextCommandLine.getIt(null), null, outputFile, process.getInputStream(), null);
		} else if ( outputFile!=null ) {
			System.err.println("Output file: "+outputFile);
			zipIt(process.getInputStream(), outputFile);
		} else {
			printToStdOut(process.getInputStream());
		}
		printToStdErr(process.getErrorStream());
	}
	private void unzipIt(final OutputStream os, final File file) throws IOException {
		final InputStream fileInputStream = new FileInputStream(file);
		final InputStream is = new GZIPInputStream(fileInputStream);
		in2out(is, os);
	}
	private void zipIt(final InputStream is, final File file) throws IOException {
		final OutputStream fileOs = new FileOutputStream(file);
		final OutputStream zippedOs = new GZIPOutputStream(fileOs);
		in2out(is,zippedOs);
		zippedOs.close();
		fileOs.close();
	}
	private void printToStdOut(final InputStream is) throws IOException {
		in2out(is, System.out);
	}
	private void printToStdErr(final InputStream is) throws IOException {
		in2out(is, System.err);
	}
	private void in2out(final InputStream is, final OutputStream os) throws IOException {
		while ( true ) {
			final int available = is.available();
			if ( available>0 ) {
				final byte bv[] = new byte[available];
				is.read(bv);
				os.write(bv);
			} else {
				final int next = is.read();
				if ( next<0 ) {
					os.close();
					return;
				}
				os.write(next);
			}
		}
	}
	/* (non-Javadoc)
	 * @see org.ejbca.ui.cli.ClientToolBox#getName()
	 */
	@Override
	protected String getName() {
		return "DBManager";
	}
}
