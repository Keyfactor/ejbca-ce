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
 
package org.ejbca.core.model.hardtoken.profiles;


import java.awt.print.Printable;
import java.awt.print.PrinterException;
import java.io.IOException;
import java.io.StringReader;

import org.cesecore.certificates.endentity.EndEntityInformation;





/**
 * HardTokenProfileWithAdressLabel is a basic class that should be inherited by all types
 * of hardtokenprofiles that should have adress label functionality.
 * 
 * @version $Id$
 */
public abstract class HardTokenProfileWithAdressLabel extends HardTokenProfileWithReceipt implements IAdressLabelSettings{
		
	
	private static final long serialVersionUID = 6349060371407093333L;
    // Protected Constants
	protected static final String ADRESSLABELTYPE                = "adresslabeltype";
	protected static final String ADRESSLABELFILENAME            = "adresslabelfilename";
	protected static final String ADRESSLABELDATA                = "adresslabeldata";
	protected static final String ADRESSLABELCOPIES              = "adresslabelcopies";
	

	private SVGImageManipulator adresslabelsvgimagemanipulator = null;
			
    // Default Values
    public HardTokenProfileWithAdressLabel() {
      super();
      
      setAdressLabelType(IAdressLabelSettings.ADRESSLABELTYPE_GENERAL);
      setAdressLabelTemplateFilename("");
	  setNumberOfAdressLabelCopies(1);
         
      
    }

    // Public Methods mostly used by PrimeCard
    
    
    public void upgrade(){
      // Perform upgrade functionality
    	
      if(data.get(ADRESSLABELTYPE) == null){
      	setAdressLabelType(IAdressLabelSettings.ADRESSLABELTYPE_GENERAL);
      } 	
      if(data.get(ADRESSLABELFILENAME) == null){
      	setAdressLabelTemplateFilename("");
      }      	
      if(data.get(ADRESSLABELCOPIES) == null){
      	setNumberOfAdressLabelCopies(1);	
      }
    	
      super.upgrade(); 
    }
    

    
	/* (non-Javadoc)
	 * @see org.ejbca.core.model.hardtoken.hardtokenprofiles.IAdressLabelSettings#getNumberOfAdressLabelCopies()
	 */
	public int getNumberOfAdressLabelCopies() {
		return ((Integer) data.get(ADRESSLABELCOPIES)).intValue();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.model.hardtoken.hardtokenprofiles.IAdressLabelSettings#getAdressLabelData()
	 */
	public String getAdressLabelData() {
		return (String) data.get(ADRESSLABELDATA);
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.model.hardtoken.hardtokenprofiles.IAdressLabelSettings#getAdressLabelTemplateFilename()
	 */
	public String getAdressLabelTemplateFilename() {
		return (String) data.get(ADRESSLABELFILENAME);
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.model.hardtoken.hardtokenprofiles.IAdressLabelSettings#getAdressLabeltype()
	 */
	public int getAdressLabelType() {
		return ((Integer) data.get(ADRESSLABELTYPE)).intValue();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.model.hardtoken.hardtokenprofiles.IAdressLabelSettings#printAdressLabel(org.ejbca.core.model.ra.UserDataVO, java.lang.String[], java.lang.String[], java.lang.String, java.lang.String)
	 */
	public Printable printAdressLabel(EndEntityInformation userdata, String[] pincodes,
			String[] pukcodes, String hardtokensn, String copyoftokensn) throws IOException, PrinterException {
		Printable returnval = null;

		if(getAdressLabelData() != null){
			if(adresslabelsvgimagemanipulator == null) {
				adresslabelsvgimagemanipulator = new SVGImageManipulator(new StringReader(getAdressLabelData()),
						getVisualValidity(),
						getHardTokenSNPrefix()); 
			}
			returnval = adresslabelsvgimagemanipulator.print(userdata, pincodes, pukcodes, hardtokensn, copyoftokensn); 														
		}

		return returnval;	
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.model.hardtoken.hardtokenprofiles.IAdressLabelSettings#setNumberOfAdressLabelCopies(int)
	 */
	public void setNumberOfAdressLabelCopies(int copies) {
		  data.put(ADRESSLABELCOPIES, Integer.valueOf(copies));	
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.model.hardtoken.hardtokenprofiles.IAdressLabelSettings#setAdressLabelData(java.lang.String)
	 */
	public void setAdressLabelData(String templatedata) {
		data.put(ADRESSLABELDATA, templatedata);	
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.model.hardtoken.hardtokenprofiles.IAdressLabelSettings#setAdressLabelTemplateFilename(java.lang.String)
	 */
	public void setAdressLabelTemplateFilename(String filename) {
		  data.put(ADRESSLABELFILENAME, filename);		
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.model.hardtoken.hardtokenprofiles.IAdressLabelSettings#setAdressLabeltype(int)
	 */
	public void setAdressLabelType(int type) {
		data.put(ADRESSLABELTYPE, Integer.valueOf(type));
	}
}
