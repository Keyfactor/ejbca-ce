package se.anatom.ejbca.ra;

import java.util.HashMap;
import java.util.Iterator;

import se.anatom.ejbca.util.UpgradeableDataHashMap;

/**
 * The model representation of Exended Information about a user. It's used for non-searchable data about a user, 
 * like a image, in an effort to minimize the need for database alterations
 *
 * @author  Philip Vendil
 * @version $Id: ExtendedInformation.java,v 1.1 2003-09-04 08:50:45 herrvendil Exp $
 */
public class ExtendedInformation extends UpgradeableDataHashMap implements java.io.Serializable, Cloneable {

    public static final float LATEST_VERSION = 0;

    // Public constants

    // Wait for fields to use with this class. 
    
    // Public methods.
    /** Creates a new instance of EndEntity Profile */
    public ExtendedInformation() {
      super();
    }

    
    public Object clone() throws CloneNotSupportedException {
      ExtendedInformation clone = new ExtendedInformation();
      HashMap clonedata = (HashMap) clone.saveData();

      Iterator i = (data.keySet()).iterator();
      while(i.hasNext()){
        Object key = i.next();
        clonedata.put(key, data.get(key));
      }

      clone.loadData(clonedata);
      return clone;
    }

    /** Implemtation of UpgradableDataHashMap function getLatestVersion */
    public float getLatestVersion(){
       return LATEST_VERSION;
    }

    /** Implemtation of UpgradableDataHashMap function upgrade. */

    public void upgrade(){
      if(LATEST_VERSION != getVersion()){
        // New version of the class, upgrade
        data.put(VERSION, new Float(LATEST_VERSION));
      }
    }

}
