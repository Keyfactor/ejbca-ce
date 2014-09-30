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

package org.ejbca.ui.cli.hardtoken.importer;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.Properties;

import org.ejbca.core.model.hardtoken.HardTokenInformation;

/**
 * A abstract base class that should be used by all
 * File based hard token data importers 
 * 
 * It have a protected field fileReader that can be used by
 * the implementation of readHardTokenData()
 *
 * @version $Id$
 */

public abstract class FileReadHardTokenImporter implements IHardTokenImporter {

	protected BufferedReader bufferedReader = null;

	/**
	 * Open up a text file and expecting the property "file" to point to
	 * the location of the input file.
	 * @see org.ejbca.ui.cli.hardtoken.importer.IHardTokenImporter#startImport(java.util.Properties)
	 * @throws IOException if file doesn't exist of the property FILE isn't set.
	 */
	public void startImport(Properties props) throws IOException {
		if(props.getProperty("file") == null){
			throw new IOException("Error: the property file pointing to the file to import isn't set.");
		}
 
		 bufferedReader = new BufferedReader(new FileReader(props.getProperty("file")));
	}


	/**
	 * @see org.ejbca.ui.cli.hardtoken.importer.IHardTokenImporter#readHardTokenData()
	 */
	public abstract HardTokenInformation readHardTokenData() throws IOException ;


	/**
	 * Closes the file after completion.
	 * 
	 * @see org.ejbca.ui.cli.hardtoken.importer.IHardTokenImporter#endImport()
	 */
	public void endImport() throws IOException {
       if(bufferedReader != null){
    	   bufferedReader.close();
       }
	}
	
}
