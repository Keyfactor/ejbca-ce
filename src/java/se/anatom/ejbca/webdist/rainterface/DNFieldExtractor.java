/*
 * DNFieldExtractor.java
 *
 * Created on den 1 maj 2002, 07:09
 */

package se.anatom.ejbca.webdist.rainterface;

/**
 * A class used to retrieve different fields from a Distiguished Name string.
 *
 * @author  Philip Vendil
 */
public class DNFieldExtractor {
    
    // Public constants
    public static final String COMMONNAME       = "CN=";
    public static final String ORGANIZATIONUNIT = "OU=";
    public static final String ORGANIZATION     = "O=";
    public static final String LOCALE           = "L=";
    public static final String STATE            = "ST=";
    public static final String COUNTRY          = "C=";
                   
        
    /** Creates a new instance of DNFieldExtractor */
    public DNFieldExtractor(String dn) {
      this.dn=dn;  
    }
    
    public void setDN() {
      this.dn=dn;  
    }
    
    public String getDN() {
      return dn;  
    }
    
    public String getField(String field) {
      int startindex, endindex =0;  
      String returnvalue="";

      startindex= dn.indexOf(field);
      if(startindex >= 0){
        startindex += field.length();  
        endindex=dn.indexOf(',',startindex);
        if(endindex > 0)
          returnvalue = dn.substring(startindex,endindex).trim();      
        else
          returnvalue = dn.substring(startindex).trim();                    
        }
      else{
        returnvalue = "";
      }        
      
      return returnvalue;
    }
   
    private String dn;    
}
