/*
 * Created on 2004-jan-26
 *
 * Class used as a help tool when creating hard token visual layout templates
 */
package se.anatom.ejbca.admin;

import java.awt.PrintJob;
import java.awt.print.PrinterJob;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.util.Date;
import java.util.Properties;

import javax.print.Doc;
import javax.print.DocFlavor;
import javax.print.DocPrintJob;
import javax.print.PrintService;
import javax.print.PrintServiceLookup;
import javax.print.SimpleDoc;
import javax.print.attribute.DocAttributeSet;
import javax.print.attribute.HashDocAttributeSet;
import javax.print.attribute.HashPrintRequestAttributeSet;
import javax.print.attribute.PrintRequestAttributeSet;

import se.anatom.ejbca.hardtoken.hardtokenprofiles.SVGImageManipulator;
import se.anatom.ejbca.ra.UserAdminData;



/**
 * @author philip
 *
 * Class used as a help tool when creating hard token visual layout templates
 */
public class SVGTemplatePrinter {

	private static final String USERDATAFILENAME = "svgtemplateprinttester.properties";
	
	private SVGImageManipulator imagemanipulator = null;
	private PrintService printservice = null;
	
	private UserAdminData userdata = null;
	private String[] pins = new String[2];
	private String[] puks = new String[2];
	private String hardtokensn = "";
	private String copyofhardtokensn = "";
	
	public SVGTemplatePrinter(String templatefilename, String printer) throws Exception{
		Properties data = new Properties();
		data.load(new FileInputStream(USERDATAFILENAME));
  						
		userdata = new UserAdminData("", data.getProperty("DN"),0,"", data.getProperty("EMAIL"), 
				                                           0,0,0,0, (Date) null, (Date) null,0,0 );
		
		pins[0] = data.getProperty("PIN1");
		pins[1] = data.getProperty("PIN2");
		
		
		puks[0] = data.getProperty("PUK1");
		puks[1] = data.getProperty("PUK2");
		
		copyofhardtokensn = data.getProperty("COPYOFHARDTOKENSN");
		hardtokensn = data.getProperty("HARDTOKENSN");
		
		int validity = Integer.parseInt(data.getProperty("VALIDITY"));		
		String hardtokensnprefix = data.getProperty("HARDTOKENSNPREFIX");
				
		// Read the tempate file.
		 imagemanipulator = new SVGImageManipulator( new FileReader(templatefilename), validity, hardtokensnprefix);
		
		// Setup the printer.
		 PrintRequestAttributeSet pras = new HashPrintRequestAttributeSet();
		 DocFlavor flavor = DocFlavor.INPUT_STREAM.POSTSCRIPT;
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
	   	  job.setPrintable(imagemanipulator.print(userdata,pins,puks,hardtokensn, copyofhardtokensn));
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
