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
 
package se.anatom.ejbca.hardtoken.hardtokenprofiles;


import java.awt.print.Printable;
import java.awt.print.PrinterException;
import java.io.IOException;
import java.io.StringReader;

import se.anatom.ejbca.common.UserDataVO;


/**
 * HardTokenProfileWithReceipt is a basic class that should be inherited by all types
 * of hardtokenprofiles that should have receipt functionality.
 * 
 * @version $Id: HardTokenProfileWithReceipt.java,v 1.2 2005-04-21 15:19:10 herrvendil Exp $
 */
public abstract class HardTokenProfileWithReceipt extends HardTokenProfileWithVisualLayout implements IReceiptSettings{
		
	
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

    // Public Methods mostly used by PrimeCard
    
    
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
    

    
	/* (non-Javadoc)
	 * @see se.anatom.ejbca.hardtoken.hardtokenprofiles.IReceiptSettings#getNumberOfReceiptCopies()
	 */
	public int getNumberOfReceiptCopies() {
		return ((Integer) data.get(RECEIPTCOPIES)).intValue();
	}
	/* (non-Javadoc)
	 * @see se.anatom.ejbca.hardtoken.hardtokenprofiles.IReceiptSettings#getReceiptData()
	 */
	public String getReceiptData() {
		return (String) data.get(RECEIPTDATA);
	}
	/* (non-Javadoc)
	 * @see se.anatom.ejbca.hardtoken.hardtokenprofiles.IReceiptSettings#getReceiptTemplateFilename()
	 */
	public String getReceiptTemplateFilename() {
		return (String) data.get(RECEIPTFILENAME);
	}
	/* (non-Javadoc)
	 * @see se.anatom.ejbca.hardtoken.hardtokenprofiles.IReceiptSettings#getReceipttype()
	 */
	public int getReceiptType() {
		return ((Integer) data.get(RECEIPTTYPE)).intValue();
	}
	/* (non-Javadoc)
	 * @see se.anatom.ejbca.hardtoken.hardtokenprofiles.IReceiptSettings#printReceipt(se.anatom.ejbca.ra.UserDataVO, java.lang.String[], java.lang.String[], java.lang.String, java.lang.String)
	 */
	public Printable printReceipt(UserDataVO userdata, String[] pincodes,
			String[] pukcodes, String hardtokensn, String copyoftokensn)
			throws IOException, PrinterException {
		Printable returnval = null;
		  
			if(getReceiptData() != null){
				if(receiptsvgimagemanipulator == null)
					receiptsvgimagemanipulator = new SVGImageManipulator(new StringReader(getReceiptData()),
															  getVisualValidity(),
															  getHardTokenSNPrefix()); 
															
			  returnval = receiptsvgimagemanipulator.print(userdata, pincodes, pukcodes, hardtokensn, copyoftokensn); 														
			}
		  
		  
			return returnval;	
	}
	/* (non-Javadoc)
	 * @see se.anatom.ejbca.hardtoken.hardtokenprofiles.IReceiptSettings#setNumberOfReceiptCopies(int)
	 */
	public void setNumberOfReceiptCopies(int copies) {
		  data.put(RECEIPTCOPIES, new Integer(copies));	
	}
	/* (non-Javadoc)
	 * @see se.anatom.ejbca.hardtoken.hardtokenprofiles.IReceiptSettings#setReceiptData(java.lang.String)
	 */
	public void setReceiptData(String templatedata) {
		data.put(RECEIPTDATA, templatedata);	
	}
	/* (non-Javadoc)
	 * @see se.anatom.ejbca.hardtoken.hardtokenprofiles.IReceiptSettings#setReceiptTemplateFilename(java.lang.String)
	 */
	public void setReceiptTemplateFilename(String filename) {
		  data.put(RECEIPTFILENAME, filename);		
	}
	/* (non-Javadoc)
	 * @see se.anatom.ejbca.hardtoken.hardtokenprofiles.IReceiptSettings#setReceipttype(int)
	 */
	public void setReceiptType(int type) {
		data.put(RECEIPTTYPE, new Integer(type));
	}
}
