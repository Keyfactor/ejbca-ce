package se.anatom.ejbca.ca.caadmin.extendedcaservices;

import se.anatom.ejbca.ca.caadmin.CA;
import se.anatom.ejbca.util.UpgradeableDataHashMap;

/** 
 * ExtendedCAService base class.
 * 
 * @version $Id: ExtendedCAService.java,v 1.2 2003-11-14 14:59:57 herrvendil Exp $
 */
public abstract class ExtendedCAService extends UpgradeableDataHashMap implements java.io.Serializable{
    
    public static final String EXTENDEDCASERVICETYPE = "extendedcaservicetype";

	public final String SERVICENAME = "";  	
		
	public static final String STATUS = "status";
	
	protected void setStatus(int status){ this.data.put(STATUS, new Integer(status)); }
	
	protected int getStatus(){ return ((Integer) data.get(STATUS)).intValue(); }
	
	/**
	 * Initializes the ExtendedCAService
	 * 
	 * @param info contains information used to activate the service.    
	 */
	public abstract void init(CA ca) throws Exception;
	
	
	/**
	 * Update the ExtendedCAService data
	 * 
	 * @param info contains information used to activate the service.    
	 */
	public abstract void update(ExtendedCAServiceInfo info, CA ca) throws Exception;
			

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
