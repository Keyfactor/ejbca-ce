package se.anatom.ejbca.ca.caadmin;

/**
 * @author herrvendil
 *
 * Value class containing information about an available hard catoken registered to the HardCATokenManager.
 * 
 * 
 */
public class AvailableHardCAToken {
	
	private String classpath;
	private String name;
	private boolean translateable;
	private boolean use;
	
	public AvailableHardCAToken(String classpath, String name, boolean translateable, boolean use){
		this.classpath = classpath;
		this.name = name;
		this.translateable = translateable;
		this.use = use;
	}
	
	
	/**
	 *  Method returning the classpath used to create the plugin. Must implement the HardCAToken interface.
	 * 
	 */
	public String getClassPath(){
		return this.classpath;
	}
	
	/**
	 *  Method returning the general name of the plug-in used in the adminweb-gui. If translateable flag is 
	 *  set then must the resource be in the language files.
	 * 
	 */	
	
	public String getName(){
		return this.name;		
	}

	/**
	 *  Indicates if the name should be translated in the adminweb-gui. 
	 * 
	 */	
	public boolean isTranslateable(){
		return this.translateable;
	}

	/**
	 *  Indicates if the plug should be used in the system or if it's a dummy or test class.
	 * 
	 */		
	public boolean isUsed(){
		return this.use;
	}

}
