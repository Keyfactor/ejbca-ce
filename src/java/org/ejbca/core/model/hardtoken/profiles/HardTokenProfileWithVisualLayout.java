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
 * HardTokenProfileWithVisualLayout is a basic class that should be inherited by all types
 * of hardtokenprofiles in the system that need PIN envelope and visual layout printing functionality.
 * 
 * It used to customize the information generated on hard tokens when they are 
 * processed. This information could be PIN-type number of certificates, 
 * certificate profiles and so on. 
 *
 * @version $Id$
 */
public abstract class HardTokenProfileWithVisualLayout extends HardTokenProfileWithPINEnvelope implements IVisualLayoutSettings{
		
	// Protected Constants

	private static final long serialVersionUID = -4609931101290447428L;
    protected static final String VISUALLAYOUTTYPE               = "visuallayouttype";
	protected static final String VISUALLAYOUTFILENAME           = "visuallayoutfilename";
	protected static final String VISUALLAYOUTDATA               = "visuallayoutdata";


    private SVGImageManipulator visualsvgimagemanipulator = null;
			
    // Default Values
    public HardTokenProfileWithVisualLayout() {
      super();
      
      setVisualLayoutType(IVisualLayoutSettings.VISUALLAYOUTTYPE_GENERALLABEL);
      setVisualLayoutTemplateFilename("");      
    }

    // Public Methods 

    @Override
	public int getVisualLayoutType() {	
	  return ((Integer) data.get(VISUALLAYOUTTYPE)).intValue();
	}

    @Override
	public void setVisualLayoutType(int type) {		
	  data.put(VISUALLAYOUTTYPE, Integer.valueOf(type));	
	}

    @Override
	public String getVisualLayoutTemplateFilename() {		
		return (String) data.get(VISUALLAYOUTFILENAME);
	}

    @Override
	public void setVisualLayoutTemplateFilename(String filename) {
      data.put(VISUALLAYOUTFILENAME, filename);
	}

    @Override
	public String getVisualLayoutData() {		
	  return (String) data.get(VISUALLAYOUTDATA);
	}

    @Override
	public void setVisualLayoutData(String templatedata) {		
	  data.put(VISUALLAYOUTDATA, templatedata);	
	}

	@Override
	public Printable printVisualValidity(EndEntityInformation userdata, String[] pincodes, String[] pukcodes, String hardtokensn, String copyoftokensn) throws IOException, PrinterException{
		Printable returnval = null;

		if(getVisualLayoutData() != null){
			if(visualsvgimagemanipulator == null) {
				visualsvgimagemanipulator = new SVGImageManipulator(new StringReader(getVisualLayoutData()), getVisualValidity(), getHardTokenSNPrefix()); 
			}		
			returnval = visualsvgimagemanipulator.print(userdata, pincodes, pukcodes, hardtokensn, copyoftokensn); 														
		}	  

		return returnval;
	}
    

}
