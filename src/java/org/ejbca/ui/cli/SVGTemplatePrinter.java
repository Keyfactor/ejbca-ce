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
 
/*
 * Created on 2004-jan-26
 *
 * Class used as a help tool when creating hard token visual layout templates
 */
package org.ejbca.ui.cli;

import java.awt.print.PageFormat;
import java.awt.print.Paper;
import java.awt.print.PrinterJob;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.util.Date;
import java.util.Properties;

import javax.print.DocFlavor;
import javax.print.PrintService;
import javax.print.PrintServiceLookup;
import javax.print.attribute.HashPrintRequestAttributeSet;
import javax.print.attribute.PrintRequestAttributeSet;

import org.ejbca.core.model.hardtoken.profiles.SVGImageManipulator;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.PrinterManager;






/**
 * @author philip
 *
 * Class used as a help tool when creating hard token visual layout templates
 */
public class SVGTemplatePrinter {

	
	private static final String USERDATAFILENAME = "src/cli/svgtemplateprinttester.properties";
	
	final private UserDataVO userdata;
	final private String[] pins = new String[2];
	final private String[] puks = new String[2];
	final private String hardtokensn;
	final private String copyofhardtokensn;
	final private int validity;
	final private String hardtokensnprefix;
	final private String templatefilename;
	final private String printername;
	
	public SVGTemplatePrinter(String templatefilename, String printername) throws FileNotFoundException, IOException{
		this.templatefilename = templatefilename;
		this.printername = printername;
		
		Properties data = new Properties();
		data.load(new FileInputStream(USERDATAFILENAME));
  						
		userdata = new UserDataVO("", data.getProperty("DN"),0,"", data.getProperty("EMAIL"), 
				                                           0,0,0,0, (Date) null, (Date) null,0,0 ,null);
		
		pins[0] = data.getProperty("PIN1");
		pins[1] = data.getProperty("PIN2");
		
		
		puks[0] = data.getProperty("PUK1");
		puks[1] = data.getProperty("PUK2");
		
		copyofhardtokensn = data.getProperty("COPYOFHARDTOKENSN");
		hardtokensn = data.getProperty("HARDTOKENSN");
		
		validity = Integer.parseInt(data.getProperty("VALIDITY"));		
		hardtokensnprefix = data.getProperty("HARDTOKENSNPREFIX");
				
	
    }
	public void print() throws Exception{
		
		FileInputStream fis = new FileInputStream(templatefilename);
		byte[] data = new byte[fis.available()];
	    fis.read(data);
	    String sVGData = new String(data,"UTF8");
	   
	    PrinterManager.print(printername, templatefilename, sVGData, 1, validity, userdata, pins, puks, hardtokensnprefix, hardtokensn, copyofhardtokensn);	
		
			   	   
	}
	

	
					
	public static void main(String[] args) throws Exception {
		boolean noargmatch = true;
				
		if(args.length == 1 && args[0].equalsIgnoreCase("listprinters")){
			String[] printerNames = PrinterManager.listPrinters();
			
			System.out.println("\n Found " + printerNames.length + " printers:");
			for(int i=0;i<printerNames.length;i++){
			   System.out.println("  " + printerNames[i]);	
			}						
			
			noargmatch = false;
		}
		
		if(args.length > 0 && args[0].equalsIgnoreCase("print")){
			if(args.length != 3 ){
				System.out.println("Usage: svgprinttest print <templatefilename> <printername> ");
				System.out.println("User data is configured in  " + USERDATAFILENAME);
				System.exit(-1);
			}
			
			try{
			  SVGTemplatePrinter printtester = new SVGTemplatePrinter(args[1], args[2]);
			  printtester.print();
			}catch(Exception e){
				
				System.out.println("Error:" + e.getMessage());
				e.printStackTrace();
			}
			
			noargmatch = false;
		}
	
		
		if(noargmatch){
			System.out.println("Usage: svgprinttest print | listprinters ");
			System.out.println("User data is configured in  " + USERDATAFILENAME);
			System.exit(-1);
		}
						
	}
	
	
}
