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

import java.awt.print.PageFormat;
import java.awt.print.Paper;
import java.awt.print.PrinterException;
import java.awt.print.PrinterJob;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;

import javax.print.DocFlavor;
import javax.print.PrintService;
import javax.print.PrintServiceLookup;
import javax.print.attribute.HashPrintRequestAttributeSet;
import javax.print.attribute.PrintRequestAttributeSet;

import org.apache.log4j.Logger;
import org.ejbca.core.model.hardtoken.profiles.SVGImageManipulator;
import org.ejbca.core.model.ra.UserDataVO;

/**
 * Class managing the printing functionality from the batchtool.
 * it takes care of all the printing functionality configured
 * in the properties
 * 
 * @author Philip Vendil 2006 sep 19
 *
 * @version $Id: BatchSVGPrinter.java,v 1.1 2006-09-19 15:54:56 herrvendil Exp $
 */
public class BatchSVGPrinter {
	private static final Logger log = Logger.getLogger(BatchSVGPrinter.class);
	
	BatchToolProperties props = null;
	private SVGImageManipulator imagemanipulator;
	private PrintService printservice;	
	
	public BatchSVGPrinter(BatchToolProperties props){
		this.props = props;

		if(props.usePrinting()){

			String templatefilename = props.getSVGTemplatePath();
			if(templatefilename.equals("")){
				log.error("Missconfigured batchtool.properties file. 'printing.template' must be set properly");
			}else{
				try{
				// Read the tempate file.
				imagemanipulator = new SVGImageManipulator( new InputStreamReader(new FileInputStream(templatefilename), "UTF-8"), 0, "");

				// Setup the printer.
				PrintRequestAttributeSet pras = new HashPrintRequestAttributeSet();
				DocFlavor flavor = DocFlavor.BYTE_ARRAY.AUTOSENSE;
				PrintService printService[] =  PrintServiceLookup.lookupPrintServices(flavor, pras);
				int i = 0;
				while ( i<printService.length && !props.getPrinterName().equalsIgnoreCase(printService[i].getName()) )
					i++;
				printservice = i<printService.length ? printService[i] : null;
				}catch(IOException e){
					log.error("Missconfigured batchtool.properties file. couldn't read svg template properly.");
				}
			}
		}
	}
	
	public void print(UserDataVO userdata){
		if(props.usePrinting()){			
			if(printservice != null){
				try {
					PrinterJob job = PrinterJob.getPrinterJob();

					job.setPrintService(printservice);

					PageFormat pf = job.defaultPage();	   	  
					Paper paper = new Paper();
					paper.setSize(pf.getWidth(), pf.getHeight());
					paper.setImageableArea(0.0,0.0,pf.getWidth(), pf.getHeight());			

					String[] pins = new String[1];
					pins[0] = userdata.getPassword();

					String[] puks = new String[1];
					puks[0] = "";

					pf.setPaper(paper);	   	  
					job.setPrintable(imagemanipulator.print(userdata,pins,puks,"", ""),pf);	   	  
					job.setCopies(props.getPrintedCopies());
					job.print();	
				} catch (PrinterException e) {
					log.error("Problem with printer : " + e.getMessage() );
					log.debug(e);
				} catch (IOException e) {
					log.error("Problem with creating SVG image : " + e.getMessage() );
					log.debug(e);				
				}
			}else{
				log.error("Error: Couldn't find printer.");		  	   	
			}	
		}
	}
	
	
	
}
