package se.anatom.ejbca.util;



import java.io.*;
import java.util.Date;

import javax.print.*;
import javax.print.attribute.DocAttributeSet;
import javax.print.attribute.HashDocAttributeSet;
import javax.print.attribute.HashPrintRequestAttributeSet;
import javax.print.attribute.PrintRequestAttributeSet;



import se.anatom.ejbca.hardtoken.hardtokenprofiles.SVGImageManipulator;
import se.anatom.ejbca.ra.UserAdminData;

/**
  * A class used to test printing templates of hardtoken envelopes and
  * labels etc, used in hard token profiles.
  * 
  * @version $Id: TestPrintTemplate.java,v 1.1 2003-12-05 14:50:26 herrvendil Exp $
  */
public class TestPrintTemplate {
	
    public TestPrintTemplate(){}

	/**
	 * The main method.
	 */
	public static void main(String[] args){
		TestPrintTemplate tpt = new TestPrintTemplate();	
		try{
			if( args.length == 1 && args[0].toUpperCase().equals("LISTPRINTERS")){
				tpt.listPrinters();
			}
			else			
			  if( args.length == 3 && args[0].toUpperCase().equals("PRINTTEMPLATE")){
			    tpt.testPrintTemplate(args);
			  }else{
			    tpt.usage();	
			  }		
		}catch (Exception e){
			e.printStackTrace();
		}
	}


    public void listPrinters(){
      
      PrintService[] printservices = PrintServiceLookup.lookupPrintServices(null,null);
      
      System.out.println("Found the following printers:");
      for(int i=0;i< printservices.length;i++){
      	System.out.println(printservices[i].getName());
      }      
      	
    }

    public void testPrintTemplate(String args[]) throws Exception{
      String template = args[1];	
	  String printer = args[2];
	  	  
	  
	  PrintRequestAttributeSet pras = new HashPrintRequestAttributeSet();
	  
	  PrintService[] printservices = PrintServiceLookup.lookupPrintServices(null,pras);
	  PrintService printservice = null;
	  for(int i=0;i< printservices.length;i++){
		if(printservices[i].getName().equalsIgnoreCase(printer))
	      printservice = printservices[i];
	  }
	  
	  if(printservice == null){
	  	System.out.println("Given printername not found in system.");
	  }else{
	  	// Read and Parse Image
	  	java.io.Reader svgdata = new FileReader(template); 
	  	
		SVGImageManipulator imagemanipulator = new SVGImageManipulator(svgdata,                                        
		                                             10, // Validity 
		                                             "12345"); // hardtokenprefix)	
	  	
	  	String[] pins = {"1234","2345","3456"};
	  	String[] puks = {"123456","234567","345678"}; // puks
	  		  	
	  	byte[] bytearray = imagemanipulator.print( new UserAdminData(
	  	                                             "TISHOROUSER", // Username
	  	                                             "CN=Tishoro Mifune, OU=Yellow Group, O=SAMURAI. inc, L=Tokyo, T=Samurai, C=JP", // DN
	  												 0, // caid
                                                     "", // subjectaltname
                                                     "", // email
                                                     0, // status
                                                     0, // type
								                     0, // endentityprofileid
                                                     0, // certificateprofileid
		                                             new Date(), // createtime
	  												 new Date(), // modifiedtime
	  												 0, // tokentype
	  												 0), // hardtokenissuerid 
		                                             pins,
		                                             puks,
		                                            "123456789", // tokensn
		                                            "12345567"); // copyoftokensn
		                        
					  	
	  	
	  	DocPrintJob job = printservice.createPrintJob();
		DocAttributeSet das = new HashDocAttributeSet();
		ByteArrayInputStream bais = new ByteArrayInputStream(bytearray); 
        Doc doc = new SimpleDoc(bais, DocFlavor.INPUT_STREAM.AUTOSENSE, das);
        System.out.print("Printing...");
        job.print(doc,pras);          
		Thread.sleep(10000);	  	
	  }
	  
	  
	  	
    }

	/**
	 * This will print out a message telling how to use this example.
	 */
	public void usage()
	{
		System.out.println( "Wrong number of arguments:" );
		System.out.println( "usage: testprinttemplate printtemplate <template.svg> <printername>" );
		System.out.println( "or     testprinttemplate listprinters" );
	}
  		
  }



