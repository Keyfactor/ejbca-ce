/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.cli.batch;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

import org.apache.log4j.Logger;

/**
 * Class used to manage the batch tool property file.
 * 
 * @author Philip Vendil 2006 sep 19
 *
 * @version $Id: BatchToolProperties.java,v 1.1 2006-09-19 15:54:57 herrvendil Exp $
 */
public class BatchToolProperties {
	
	private static final String PROPERTY_KEYSIZE           = "keys.size";
	private static final String PROPERTY_PRINTING_USE      = "printing.use";
	private static final String PROPERTY_PRINTING_NAME     = "printing.printername";
	private static final String PROPERTY_PRINTING_COPIES   = "printing.copies";
	private static final String PROPERTY_PRINTING_TEMPLATE = "printing.template";
	

	Properties batchToolProperties = new Properties();
	private static final Logger log = Logger.getLogger(BatchToolProperties.class);
	
	BatchToolProperties(){
		load();
	}
	
	/**
	 * Returns the configured keysize
	 * Default is 1024
	 */
	public int getKeySize(){
		return Integer.parseInt(batchToolProperties.getProperty(PROPERTY_KEYSIZE,"1024"));
	}
	
	/**
	 * Returns true of the printing of keystore envelopes should be used.
	 * Default false.
	 */
	public boolean usePrinting(){
		return batchToolProperties.getProperty(PROPERTY_PRINTING_USE,"false").equalsIgnoreCase("TRUE");
	}

	/**
	 * Returns the name of the printer that should be used.
	 * Never returns null, returns "" if no printer is configured.
	 */
	public String getPrinterName(){
		return batchToolProperties.getProperty(PROPERTY_PRINTING_NAME,"").trim();
	}
	
	/**
	 * Returns the path of the filename to be used as template
	 * Never returns null, returns "" if no printer is configured.
	 */
	public String getSVGTemplatePath(){
		return batchToolProperties.getProperty(PROPERTY_PRINTING_TEMPLATE,"").trim();
	}
	
	/**
	 * Returns the number of copies that should be printed
	 * Default is 1.
	 */
	public int getPrintedCopies(){
		return Integer.parseInt(batchToolProperties.getProperty(PROPERTY_PRINTING_COPIES,"1"));
	}
	
	
	
	/**
	 * Method that tries to read the property file 'batchtool.properties'
	 * in the home directory then in the current directory and finally 
	 * in the bin\batchtool.properties 
	 *
	 */
	private void load(){
        File file = new File( System.getProperty("user.home"),
                "batchtool.properties");
        try {
        	try{
			FileInputStream fis = new FileInputStream(file);
			batchToolProperties.load(fis);
		    } catch (FileNotFoundException e) {
		    	try{
		    		FileInputStream fis = new FileInputStream("batchtool.properties");
		    		batchToolProperties.load(fis);
		    	}catch (FileNotFoundException e1) {
		    		try{
		    			FileInputStream fis = new FileInputStream("bin/batchtool.properties");
		    			batchToolProperties.load(fis);
		    		}catch (FileNotFoundException e2) {
		    			log.info("Couldn't find ant batchtool property file, default values will be used.");
		    			log.debug(e);
		    		}
		    	}
		    }
		} catch (IOException e) {
			log.error("Error reading batchtool property file ");
			log.debug(e);
		}
	}
	
	
	
}
