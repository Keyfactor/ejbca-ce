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
 
package org.ejbca.ui.cli;

import java.io.FileInputStream;
import java.util.Date;
import java.util.Properties;

import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.ejbca.util.PrinterManager;

/**
 * @author philip
 *
 * Class used as a help tool when creating hard token visual layout templates
 * @version $Id$
 */
public class SVGTemplatePrinter extends BaseCommand {

	private static final String USERDATAFILENAME = "src/cli/svgtemplateprinttester.properties";

	public String getMainCommand() { return null; }
	public String getSubCommand() { return "template"; }
	public String getDescription() { return "Tool for creating hard token visual layout templates"; }

	public void execute(String[] args) throws ErrorAdminCommandException {
		boolean noargmatch = true;
		if(args.length == 2 && args[1].equalsIgnoreCase("listprinters")){
			String[] printerNames = PrinterManager.listPrinters();
			getLogger().info("Found " + printerNames.length + " printers:");
			for(int i=0;i<printerNames.length;i++){
				getLogger().info("  " + printerNames[i]);	
			}						
			noargmatch = false;
		}
		if(args.length == 4 && args[1].equalsIgnoreCase("print")){
			try {
				String templatefilename = args[2];
				String printername = args[3];
				Properties data = new Properties();
				data.load(new FileInputStream(USERDATAFILENAME));
				EndEntityInformation userdata = new EndEntityInformation("", data.getProperty("DN"),0,"", data.getProperty("EMAIL"), 
						                                           0,new EndEntityType(EndEntityTypes.INVALID),0,0, (Date) null, (Date) null,0,0 ,null);
				String[] pins = new String[2];
				String[] puks = new String[2];
				pins[0] = data.getProperty("PIN1");
				pins[1] = data.getProperty("PIN2");
				puks[0] = data.getProperty("PUK1");
				puks[1] = data.getProperty("PUK2");
				String copyofhardtokensn = data.getProperty("COPYOFHARDTOKENSN");
				String hardtokensn = data.getProperty("HARDTOKENSN");
				int validity = Integer.parseInt(data.getProperty("VALIDITY"));		
				String hardtokensnprefix = data.getProperty("HARDTOKENSNPREFIX");
				FileInputStream fis = new FileInputStream(templatefilename);
				byte[] byteData = new byte[fis.available()];
			    fis.read(byteData);
			    String sVGData = new String(byteData,"UTF8");
			    PrinterManager.print(printername, templatefilename, sVGData, 1, validity, userdata, pins, puks, hardtokensnprefix, hardtokensn, copyofhardtokensn);	
			} catch(Exception e) {
				getLogger().error(e.getMessage());
				e.printStackTrace();
			}
			noargmatch = false;
		}
		if(noargmatch){
			getLogger().info("Usage 1: " + getCommand() + " listprinters");
			getLogger().info("Usage 2: " + getCommand() + " print <templatefilename> <printername>");
			getLogger().info("User data is configured in  " + USERDATAFILENAME);
			System.exit(-1); // NOPMD
		}
	}
}
