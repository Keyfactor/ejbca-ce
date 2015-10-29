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

import org.cesecore.certificates.endentity.EndEntityInformation;


/**
 * Interface containing methods that need to be implemented in order 
 * to have a hard token profile contain a reciept that may contain policy and 
 * the users hand signature.
 * 
 * @version $Id$
 */

public interface IReceiptSettings {


	/**
	 * Constant indicating that no recepit should be printed.
	 */    
	public static int RECEIPTTYPE_NONE               = 0;
    /**
     * Constants indicating what type of receipt that should be
     * should be printed.
     */ 
    public static int RECEIPTTYPE_GENERAL       = 1;


    /**      
     * @return the type of receipt to print.
     */
    public abstract int getReceiptType();    

	/**      
	 * sets the receipt type.
	 */
	public abstract void setReceiptType(int type);    
    
    /**
     * @return the filename of the current visual layout template.
     */
    public abstract String getReceiptTemplateFilename();

	/**
	 * Sets the filename of the current visual layout template.
	 */    
	public abstract void setReceiptTemplateFilename(String filename);
    
	/**
	 * Returns the image data of the receipt, should be a SVG image.
	 */
	public abstract String getReceiptData();		
	 

	/**
	 * Sets the imagedata of the receipt.
	 */
	public abstract void setReceiptData(String templatedata);
	
    /**
     * @return the number of copies of this receipt that should be printed.
     */
    public abstract int getNumberOfReceiptCopies();

	/**
	 * Sets the number of copies of this receipt that should be printed.
	 */
	public abstract void setNumberOfReceiptCopies(int copies);
	

   /**
    * Method that parses the template, replaces the userdata
    * and returning a printable byte array 
    */	
	public abstract Printable printReceipt(EndEntityInformation userdata, 
	                                        String[] pincodes, String[] pukcodes,
	                                        String hardtokensn, String copyoftokensn)
	                                          throws IOException, PrinterException;
}

