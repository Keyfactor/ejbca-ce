/*
 * UserViewFilterConnector.java
 *
 * Created on den 18 april 2002, 16:51
 */

package se.anatom.ejbca.webdist.rainterface;

/**
 *  
 * A class representin the logical connections between two UserViewFilters, i.e. logical operators.
 *
 * @author  Philip Vendil
 */
public class UserViewFilterConnector {
    
    // Public constants.
    public static final String AND = "AND";
    public static final String OR  = "OR";
    
    /** Creates a new instance of UserViewFilterConnector */
    public UserViewFilterConnector(String connector) {
      this.connector=connector;
    }
    
    public String getConnector(){
      return this.connector;   
    }
    
    public void setConnector(String connector){
      this.connector=connector;   
    }
    
    // Private fields.
    private String connector;
}
