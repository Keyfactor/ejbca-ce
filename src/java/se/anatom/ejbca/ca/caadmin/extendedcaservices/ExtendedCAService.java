package se.anatom.ejbca.ca.caadmin.extendedcaservices;

import se.anatom.ejbca.ca.caadmin.CA;
import se.anatom.ejbca.util.UpgradeableDataHashMap;

/** 
 * ExtendedCAService base class.
 * 
 * @version $Id: ExtendedCAService.java,v 1.1 2003-11-02 15:51:37 herrvendil Exp $
 */
public abstract class ExtendedCAService extends UpgradeableDataHashMap implements java.io.Serializable{
    
    public static final String EXTENDEDCASERVICETYPE = "extendedcaservicetype";

	public static final int TYPE_OCSPEXTENDEDSERVICE   = 1; 	
		
	public static final String STATUS = "status";
	
	protected void setStatus(int status){ this.data.put(STATUS, new Integer(status)); }
	
	protected int getStatus(){ return ((Integer) data.get(STATUS)).intValue(); }
	
	/**
	 * Initializes the ExtendedCAService
	 * 
	 * @param info contains information used to activate the service.    
	 */
	public abstract void init(ExtendedCAServiceInfo info, CA ca) throws Exception;
	
	
	/**
	 * Activates the ExtendedCAService
	 * 
	 * @param info contains information used to activate the service.    
	 */
	public abstract void activate();
	
	/**
	 * Deactivates the ExtendedCAService
	 * 
	 * @param info contains information used to activate the service.    
	 */
	public abstract void deactivate();
	

	/** 
	 * Method used to retrieve information about the service.
	 */

    public abstract ExtendedCAServiceInfo getExtendedCAServiceInfo();

    /** 
     * Method used to perform the service.
     */
    public abstract ExtendedCAServiceResponse extendedService(ExtendedCAServiceRequest request) 
      throws IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException;

    
}
