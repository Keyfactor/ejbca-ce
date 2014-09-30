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
 
package org.ejbca.core.model.hardtoken.profiles;


import java.awt.print.Printable;
import java.awt.print.PrinterException;
import java.io.IOException;
import java.io.StringReader;

import org.cesecore.certificates.endentity.EndEntityInformation;





/**
 * HardTokenProfileWithReceipt is a basic class that should be inherited by all types
 * of hardtokenprofiles that should have receipt functionality.
 * 
 * @version $Id$
 */
public abstract class HardTokenProfileWithReceipt extends HardTokenProfileWithVisualLayout implements IReceiptSettings{
		
	
	private static final long serialVersionUID = 2963055087857426772L;
    // Protected Constants
	protected static final String RECEIPTTYPE                = "receipttype";
	protected static final String RECEIPTFILENAME            = "receiptfilename";
	protected static final String RECEIPTDATA                = "receiptdata";
	protected static final String RECEIPTCOPIES              = "receiptcopies";
	

	private SVGImageManipulator receiptsvgimagemanipulator = null;
			
    // Default Values
    public HardTokenProfileWithReceipt() {
      super();
      
      setReceiptType(IReceiptSettings.RECEIPTTYPE_GENERAL);
      setReceiptTemplateFilename("");
	  setNumberOfReceiptCopies(1);
         
      
    }

    // Public Methods
    
    @Override
    public void upgrade(){
      // Perform upgrade functionality
    	
      if(data.get(RECEIPTTYPE) == null){
      	setReceiptType(IReceiptSettings.RECEIPTTYPE_GENERAL);
      } 	
      if(data.get(RECEIPTFILENAME) == null){
      	setReceiptTemplateFilename("");
      }      	
      if(data.get(RECEIPTCOPIES) == null){
      	setNumberOfReceiptCopies(1);	
      }
    	
      super.upgrade(); 
    }
    

    
    @Override
	public int getNumberOfReceiptCopies() {
		return ((Integer) data.get(RECEIPTCOPIES)).intValue();
	}
    @Override
	public String getReceiptData() {
		return (String) data.get(RECEIPTDATA);
	}
    @Override
	public String getReceiptTemplateFilename() {
		return (String) data.get(RECEIPTFILENAME);
	}
    @Override
	public int getReceiptType() {
		return ((Integer) data.get(RECEIPTTYPE)).intValue();
	}
    @Override
	public Printable printReceipt(EndEntityInformation userdata, String[] pincodes,
			String[] pukcodes, String hardtokensn, String copyoftokensn) throws IOException, PrinterException {
		Printable returnval = null;

		if(getReceiptData() != null){
			if(receiptsvgimagemanipulator == null) {
				receiptsvgimagemanipulator = new SVGImageManipulator(new StringReader(getReceiptData()), getVisualValidity(), getHardTokenSNPrefix()); 
			}	
			returnval = receiptsvgimagemanipulator.print(userdata, pincodes, pukcodes, hardtokensn, copyoftokensn); 														
		}		  

		return returnval;	
	}
	
    @Override
	public void setNumberOfReceiptCopies(int copies) {
		  data.put(RECEIPTCOPIES, Integer.valueOf(copies));	
	}
    @Override
	public void setReceiptData(String templatedata) {
		data.put(RECEIPTDATA, templatedata);	
	}
    @Override
	public void setReceiptTemplateFilename(String filename) {
		  data.put(RECEIPTFILENAME, filename);		
	}
    @Override
	public void setReceiptType(int type) {
		data.put(RECEIPTTYPE, Integer.valueOf(type));
	}
}
