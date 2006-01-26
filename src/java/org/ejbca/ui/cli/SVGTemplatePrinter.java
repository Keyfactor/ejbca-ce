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
import java.io.InputStreamReader;
import java.util.Date;
import java.util.Properties;

import javax.print.DocFlavor;
import javax.print.PrintService;
import javax.print.PrintServiceLookup;
import javax.print.attribute.HashPrintRequestAttributeSet;
import javax.print.attribute.PrintRequestAttributeSet;

import org.ejbca.core.model.hardtoken.profiles.SVGImageManipulator;
import org.ejbca.core.model.ra.UserDataVO;






/**
 * @author philip
 *
 * Class used as a help tool when creating hard token visual layout templates
 */
public class SVGTemplatePrinter {

	
	private static final String USERDATAFILENAME = "src/cli/svgtemplateprinttester.properties";
	
	private SVGImageManipulator imagemanipulator = null;
	private PrintService printservice = null;
	
	private UserDataVO userdata = null;
	private String[] pins = new String[2];
	private String[] puks = new String[2];
	private String hardtokensn = "";
	private String copyofhardtokensn = "";
	
	public SVGTemplatePrinter(String templatefilename, String printer) throws Exception{
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
		
		int validity = Integer.parseInt(data.getProperty("VALIDITY"));		
		String hardtokensnprefix = data.getProperty("HARDTOKENSNPREFIX");
				
		// Read the tempate file.
		 imagemanipulator = new SVGImageManipulator( new InputStreamReader(new FileInputStream(templatefilename), "UTF-8"), validity, hardtokensnprefix);
		
		// Setup the printer.
		 PrintRequestAttributeSet pras = new HashPrintRequestAttributeSet();
		 DocFlavor flavor = DocFlavor.BYTE_ARRAY.AUTOSENSE;
		 PrintService printService[] =  PrintServiceLookup.lookupPrintServices(flavor, pras);		 
		 for(int i=0;i<printService.length;i++){		 
		 	if(printer.trim().equalsIgnoreCase(printService[i].getName())){
		 		printservice = printService[i];	
		 	}		 	
		 }		 		
	}			
	
	public void print() throws Exception{
	   if(printservice != null){
	   	  PrinterJob job = PrinterJob.getPrinterJob();

	   	  job.setPrintService(printservice);
	   	  PageFormat pf = job.defaultPage();	   	  
	   	  Paper paper = new Paper();
	   	  paper.setSize(pf.getWidth(), pf.getHeight());
	   	  paper.setImageableArea(0.0,0.0,pf.getWidth(), pf.getHeight());
	   	  
	   	  pf.setPaper(paper);	   	  
	   	  job.setPrintable(imagemanipulator.print(userdata,pins,puks,hardtokensn, copyofhardtokensn),pf);	   	  
	   	  
	   	  job.print();	   	  	   	  	   	  	   	 
	   	  		   	  
	   	  
	   	  Thread.sleep(10000);	   	
	   }else{
	      System.out.println("Error: Couldn't find printer.");		  	   	
	   }			   	   
	}
	

	
					
	public static void main(String[] args) throws Exception {
		boolean noargmatch = true;
				
		if(args.length == 1 && args[0].equalsIgnoreCase("listprinters")){		   
			PrintRequestAttributeSet pras = new HashPrintRequestAttributeSet();
			DocFlavor flavor = DocFlavor.BYTE_ARRAY.AUTOSENSE;
			PrintService printService[] =  PrintServiceLookup.lookupPrintServices(flavor, pras);
			System.out.println("\n Found " + printService.length + " printers:");
			for(int i=0;i<printService.length;i++){
			   System.out.println("  " + printService[i].getName());	
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
