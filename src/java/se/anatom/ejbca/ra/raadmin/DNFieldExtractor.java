/*
 * DNFieldExtractor.java
 *
 * Created on den 1 maj 2002, 07:09
 */

package se.anatom.ejbca.ra.raadmin;

import org.ietf.ldap.LDAPDN;
import java.util.HashMap;
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
      setDN(dn);
    }
    
    public void setDN(String dn) {
      this.dn=dn;  
      dnfields = new HashMap();
      String[] dnexploded = LDAPDN.explodeDN(dn,false);
      for(int i = 0; i < dnexploded.length; i++){ 
        for(int j = 0; j < DNFIELDS.length; j++){
          if(dnexploded[i].toUpperCase().startsWith(DNFIELDS[j])){
           String rdn = LDAPDN.unescapeRDN(dnexploded[i]);             
           dnfields.put(DNFIELDS[j],rdn);   
          }
        }   
      }
    }
    
    public String getDN() {
      return dn;  
    }
    
    public String getField(String field) {
      String returnval;  
      returnval= (String) dnfields.get(field); 
      if(returnval == null)
        returnval = "";
      return returnval;
    }
   
    private static final String[] DNFIELDS = {COMMONNAME, ORGANIZATIONUNIT, ORGANIZATION, LOCALE, STATE, COUNTRY };  
    private HashMap dnfields;    
    private String  dn;
}
