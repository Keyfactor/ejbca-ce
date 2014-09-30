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
 * HardTokenProfileWithPINEnvelope is a basic class that should be inherited by all types
 * of hardtokenprofiles that should have PIN envelope functionality.
 * 
 * @version $Id$
 */
public abstract class HardTokenProfileWithPINEnvelope extends HardTokenProfile implements IPINEnvelopeSettings{
		
	
	private static final long serialVersionUID = -3611906956402573441L;
    // Protected Constants
	protected static final String PINENVELOPETYPE                = "pinenvelopetype";
	protected static final String PINENVELOPEFILENAME            = "pinenvelopefilename";
	protected static final String PINENVELOPEDATA                = "pinenvelopetdata";
	protected static final String PINENVELOPECOPIES              = "pinenvelopetcopies";
	protected static final String VISUALVALIDITY                 = "visualvalidity";

	private SVGImageManipulator envelopesvgimagemanipulator = null;
			
    // Default Values
    public HardTokenProfileWithPINEnvelope() {
      super();
      
      setPINEnvelopeType(IPINEnvelopeSettings.PINENVELOPETYPE_GENERALENVELOBE);
      setPINEnvelopeTemplateFilename("");
	  setNumberOfPINEnvelopeCopies(1);
      setVisualValidity(356);            
      
    }

    // Public Methods
    
    @Override
	public int getPINEnvelopeType() {
		return ((Integer) data.get(PINENVELOPETYPE)).intValue();
	}

    @Override
	public void setPINEnvelopeType(int type) {
	  data.put(PINENVELOPETYPE, Integer.valueOf(type));		
	}

    @Override
	public String getPINEnvelopeTemplateFilename() {		
		return (String) data.get(PINENVELOPEFILENAME);
	}

    @Override
	public void setPINEnvelopeTemplateFilename(String filename) {
	  data.put(PINENVELOPEFILENAME, filename);		
	}

    @Override
	public String getPINEnvelopeData() {		
		return (String) data.get(PINENVELOPEDATA);
	}

    @Override
	public void setPINEnvelopeData(String templatedata) {
	  data.put(PINENVELOPEDATA, templatedata);	
	}

    @Override
	public int getNumberOfPINEnvelopeCopies() {		
		return ((Integer) data.get(PINENVELOPECOPIES)).intValue();
	}

    @Override
	public void setNumberOfPINEnvelopeCopies(int copies) {		
	  data.put(PINENVELOPECOPIES, Integer.valueOf(copies));	
	}

    @Override
	public int getVisualValidity(){
	  return ((Integer) data.get(VISUALVALIDITY)).intValue();	
	}

    @Override
	public void setVisualValidity(int validity){
	  data.put(VISUALVALIDITY, Integer.valueOf(validity));	
	}


    @Override
	public Printable printPINEnvelope(EndEntityInformation userdata, String[] pincodes, String[] pukcodes, String hardtokensn, String copyoftokensn) throws IOException, PrinterException{
		Printable returnval = null;

		if(getPINEnvelopeData() != null){
			if(envelopesvgimagemanipulator == null) {
				envelopesvgimagemanipulator = new SVGImageManipulator(new StringReader(getPINEnvelopeData()), getVisualValidity(), getHardTokenSNPrefix()); 
			}	
			returnval = envelopesvgimagemanipulator.print(userdata, pincodes, pukcodes, hardtokensn, copyoftokensn); 														
		}

		return returnval;	
	}

    

}
