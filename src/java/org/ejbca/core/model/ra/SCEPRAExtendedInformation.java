package org.ejbca.core.model.ra;


/**
 * Class used to store RA specific information about the user, such as public key.
 * 
 * Should be used standalone and not extend any other type of ExtendedInformation.
 * 
 * @author Philip Vendil
 * $id$
 */
public class SCEPRAExtendedInformation extends ExtendedInformation {
		
    public static final float LATEST_VERSION = 0;
    
    private static final String SCEPREQUEST = "sceprequest";
    private static final String USER        = "user";

    /**
     * Constructor that only should be used for serialization/deserialization.
     *
     */
    public SCEPRAExtendedInformation(){
    	super();
    	setType(TYPE_SCEPRA);
    }
    
	/**
	 * Default Construtor
	 */
	public SCEPRAExtendedInformation(String sceprequest, String user) {
		super();
	    setType(TYPE_SCEPRA);
		data.put(SCEPREQUEST, sceprequest);
		data.put(USER,user);
	}
	
	/**
	 * @return Returns the request.
	 */
	public String getSCEPRequest() {
		return (String) data.get(SCEPREQUEST);
	}
	
	/**
	 * @return Returns the user.
	 */
	public String getUser() {
		return (String) data.get(USER);
	}
	
	/**
	 * @see se.anatom.ejbca.ra.ExtendedInformation#getLatestVersion()
	 */
	public float getLatestVersion() {		
		return LATEST_VERSION;
	}
	/* *
	 * @see se.anatom.ejbca.ra.ExtendedInformation#upgrade()
	 */
	public void upgrade() {
		if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
			
			data.put(VERSION, new Float(LATEST_VERSION));
		}
	}
	
}
