/*
 * AvailableHardToken.java
 *
 * Created on den 19 januari 2003, 13:04
 */

package se.anatom.ejbca.hardtoken;

/**
 *  Class representing a to the system available hard token, defined in ejb-jar.xml
 *
 * @author  TomSelleck
 */
public class AvailableHardToken implements java.io.Serializable {
    
    // Public Constructors
    public AvailableHardToken(String id, String name, String classpath){
      this.id=id;
      this.name=name;
      this.classpath=classpath;
    }
    
    // Public Methods    
    
    public String getId(){
      return this.id;         
    }
    public String getName(){
      return this.name;         
    }
    public String getClassPath(){
      return this.classpath;         
    }    
                  
    // Private fields
    private    String          id;
    private    String          name;   
    private    String          classpath;
}
