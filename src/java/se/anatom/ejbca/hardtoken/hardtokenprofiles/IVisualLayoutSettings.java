package se.anatom.ejbca.hardtoken.hardtokenprofiles;

import java.awt.print.Printable;
import java.awt.print.PrinterException;
import java.io.IOException;

import se.anatom.ejbca.ra.UserAdminData;



/**
 * Interface contating methods that need to be implementet in order 
 * to have a hard token profile contain Visual Layout, either as a label
 * or used with cardprinter.
 * 
 * @version $Id: IVisualLayoutSettings.java,v 1.2 2004-01-27 10:10:47 herrvendil Exp $
 */

public interface IVisualLayoutSettings {


	/**
	 * Constant indicating that no visual layout should be printed.
	 */    
	public static int VISUALLAYOUTTYPE_NONE               = 0;
    /**
     * Constants indicating what type of visual layout that should be
     * should be printed.
     */ 
    public static int VISUALLAYOUTTYPE_GENERALLABEL       = 1;
	public static int VISUALLAYOUTTYPE_GENERALCARDPRINTER = 2;

    /**      
     * @return the type of visual layout to print.
     */
    public abstract int getVisualLayoutType();    

	/**      
	 * sets the visual layout type.
	 */
	public abstract void setVisualLayoutType(int type);    
    
    /**
     * @return the filename of the current visual layout template.
     */
    public abstract String getVisualLayoutTemplateFilename();

	/**
	 * Sets the filename of the current visual layout template.
	 */    
	public abstract void setVisualLayoutTemplateFilename(String filename);
    
	/**
	 * Returns the image data of the visual layout, should be a SVG image.
	 */
	public abstract String getVisualLayoutData();		
	 

	/**
	 * Sets the imagedata of the visual layout.
	 */
	public abstract void setVisualLayoutData(String templatedata);
	

   /**
    * Method that parses the template, replaces the userdata
    * and returning a printable byte array 
    */	
	public abstract Printable printVisualValidity(UserAdminData userdata, 
	                                        String[] pincodes, String[] pukcodes,
	                                        String hardtokensn, String copyoftokensn)
	                                          throws IOException, PrinterException;
}

