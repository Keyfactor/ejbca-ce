/*
 * HardTokenIssuer.java
 *
 * Created on den 19 januari 2003, 12:53
 */
package se.anatom.ejbca.hardtoken;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import se.anatom.ejbca.util.UpgradeableDataHashMap;
/**
 * HardTokenIssuer is a class representing the data saved for each HardTokenIssuer.
 *
 * @author  TomSelleck
 * @version $Id: HardTokenIssuer.java,v 1.2 2003-02-09 14:56:16 anatom Exp $
 */
public  class HardTokenIssuer extends UpgradeableDataHashMap implements Serializable, Cloneable {

    // Default Values
    public static final float LATEST_VERSION = 0;

    // Protexted Constants, must be overloaded by all deriving classes.   
    protected static final String AVAILABLEHARDTOKENS     = "availablehardtokens"; 
    
    // Public Constructors.
    
    public HardTokenIssuer(){
      data.put(AVAILABLEHARDTOKENS,new ArrayList());         
    }
    
    // Public Methods
    
    // Availablehardtokens defines which hard tokens the issuer is able to issue. 
    public ArrayList getAvailableHardTokens(){
      return  (ArrayList) data.get(AVAILABLEHARDTOKENS); 
    }
    
    public void setAvailableHardTokens(ArrayList availablehardtokens){
      data.put(AVAILABLEHARDTOKENS,availablehardtokens); 
    }    
    
    public void setField(String field, Object value){ 
       data.put(field,value);   
    }
    
    /** Implemtation of UpgradableDataHashMap function getLatestVersion */
    public float getLatestVersion(){
       return LATEST_VERSION;
    }

    /** Implemtation of UpgradableDataHashMap function upgrade. */

    public void upgrade(){
    }
    
    public Object clone() throws CloneNotSupportedException {
      HardTokenIssuer clone = new HardTokenIssuer();
      HashMap clonedata = (HashMap) clone.saveData();
      
      Iterator i = (data.keySet()).iterator();
      while(i.hasNext()){
        Object key = i.next();  
        clonedata.put(key,data.get(key)); 
      }
      
      clone.loadData(clonedata);
      return clone;
    }    

}
