package se.anatom.ejbca.util;

import java.util.HashMap;

/**
 *  UpgradeableDataHashMap is an class implementing the IUpgradeableData intended to be extended by classes
 *  saving it's data to a database in BLOB form. 
 *  
 * @see se.anatom.ejbca.util.IUpgradeableData
 * @version $Id: UpgradeableDataHashMap.java,v 1.4 2003-02-06 15:35:49 herrvendil Exp $
 */
public abstract class UpgradeableDataHashMap implements IUpgradeableData, java.io.Serializable {
        
    public UpgradeableDataHashMap(){
      data = new HashMap();  
      data.put(VERSION,new Float(getLatestVersion()));   
    }
    
    /** Should return a constant containing the latest available version of the class. */
    public abstract float getLatestVersion();
    
    /** Function returning the current version of the class data. */
    public float getVersion(){
      return ((Float) data.get(VERSION)).floatValue();   
    }
    
    /** Function sending the data to be saved to the database. */
    public Object saveData(){
      return (Object) data;
    }
    
    /** 
     * Function loading saved data into to data structure.
     */
    public  void loadData(Object data){
      this.data = (HashMap) data;    
      if(getLatestVersion() >  getVersion())
         upgrade();
    }
    
    /**
     * Function that should handle the update if of the data in the class so it's up to date with the latest version.
     * An update is only done when needed.
     */
    public abstract void upgrade();
    
    protected HashMap data;
    protected static final String VERSION = "version";
    
}
    
 