/*
 * DNFieldExtractor.java
 *
 * Created on den 1 maj 2002, 07:09
 */

package se.anatom.ejbca.ra.raadmin;

import org.ietf.ldap.LDAPDN;
import java.util.HashMap;
import java.util.ArrayList;
/**
 * A class used to retrieve different fields from a Distiguished Name or Subject Alternate Name strings.
 *
 * @author  Philip Vendil
 */
public class DNFieldExtractor {
    
    // Public constants
    public static final int TYPE_SUBJECTDN            = 0;    
    public static final int TYPE_SUBJECTALTNAME       = 1;    
    // Subject DN Fields.
    public static final int EMAILADDRESS              = 0;    
    public static final int COMMONNAME                = 1;
    public static final int SERIALNUMBER              = 2;  
    public static final int TITLE                     = 3;      
    public static final int ORGANIZATIONUNIT          = 4;
    public static final int ORGANIZATION              = 5;
    public static final int LOCALE                    = 6;
    public static final int STATE                     = 7;
    public static final int DOMAINCOMPONENT           = 8;      
    public static final int COUNTRY                   = 9;

    // Subject Alternative Names.
    public static final int OTHERNAME                 = 10;
    public static final int RFC822NAME                = 11;  
    public static final int DNSNAME                   = 12;      
    public static final int IPADDRESS                 = 13;
    public static final int X400ADDRESS               = 14;
    public static final int DIRECTORYNAME             = 15;
    public static final int EDIPARTNAME               = 16;
    public static final int UNIFORMRESOURCEIDENTIFIER = 17;      
    public static final int REGISTEREDID              = 18;    
    
    public static final int SUBJECTALTERNATIVENAMEBOUNDRARY = 10;
    
    public static final String[] SUBJECTDNFIELDS = {"EMAILADDRESS=", "CN=", "SN=", "T=", "OU=", "O=", "L=", "ST=", "DC=", "C="};
    
    public static final String[] SUBJECTALTNAME =  {"OTHERNAME=","RFC822NAME=",  "DNSNAME=", "IPADDRESS=", "X400ADDRESS=", "DIRECTORYNAME=", "EDIPARTNAME=", "UNIFORMRESOURCEIDENTIFIER=",
                                                     "REGISTEREDID="};      
    
    // Constants used with field ordering
    public static final int FIELDTYPE = 0;
    public static final int NUMBER    = 1;    
  
    /** Creates a new instance of DNFieldExtractor */
    public DNFieldExtractor(String dn, int type) {
        
      setDN(dn,type);
    }
    
    public void setDN(String dn, int type) {
      String[]  fields;
      
      if(type == TYPE_SUBJECTDN){  
        fieldnumbers = new int[SUBJECTDNFIELDS.length];
        fields = SUBJECTDNFIELDS;        
      }  
      else{
        fieldnumbers = new int[SUBJECTALTNAME.length];  
        fields = SUBJECTALTNAME;        
      }        
      
      if(dn != null){
        this.dn=dn;  
        dnfields = new HashMap();
        String[] dnexploded = LDAPDN.explodeDN(dn,false);
        for(int i = 0; i < dnexploded.length; i++){ 
          boolean exists = false;  
          for(int j = 0; j < fields.length; j++){
            if(dnexploded[i].toUpperCase().startsWith("E=") && type == TYPE_SUBJECTDN){ // Special Case
                exists = true;  
                String rdn = LDAPDN.unescapeRDN(dnexploded[i]);   
                dnfields.put(new Integer((EMAILADDRESS * BOUNDRARY) + fieldnumbers[EMAILADDRESS]) ,rdn);             
            }
            else{
              if(dnexploded[i].toUpperCase().startsWith(fields[j])){
                exists = true;  
                String rdn = LDAPDN.unescapeRDN(dnexploded[i]);   
                if(type == TYPE_SUBJECTDN) 
                  dnfields.put(new Integer((j * BOUNDRARY) + fieldnumbers[j]) ,rdn);  
                else  
                  dnfields.put(new Integer(((j+ SUBJECTALTERNATIVENAMEBOUNDRARY) * BOUNDRARY) + fieldnumbers[j]) ,rdn);                 
                fieldnumbers[j]++;
              }
            }
          }  
          if(!exists)
            existsother=true;  
        }
      }
      else
        this.dn = null;
    }  
    
    public String getDN() {
      return dn;  
    }
    
    public String getField(int field, int number) {
      String returnval;       
      returnval= (String) dnfields.get(new Integer(field*BOUNDRARY + number)); 
      if(returnval == null)
        returnval = "";
      return returnval;
    }
    
    /** Function that returns true if non standard DN field exists id dn string. */
    public boolean existsOther(){
      return existsother;   
    }
    
   /**
    *  Returns the number of one kind of dn field. 
    */
    public int getNumberOfFields(int field){
      return fieldnumbers[field];  
    } 
    
    /** 
     * Returns the total number of fields in dn or subject alternative name.
     * Primary use is when checking user data with it's end entity profile.
     *
     */
    public int getFieldOrderLength(){
      return fieldorder.size();  
    }
    
    /**
     * Function that returns the field with given index in original dn field.
     * Primary use is when checking user data with it's end entity profile.
     *
     * @return An array of integers with the size of two, the first (0) indicating the type of field, the second (1)
     *         the current number of the field.
     */
    public int[] getFieldsInOrder(int index){
      int[] returnval = new int[2];
      returnval[FIELDTYPE] = ((Integer) fieldorder.get(index)).intValue() / BOUNDRARY;
      returnval[NUMBER] = ((Integer) fieldorder.get(index)).intValue() % BOUNDRARY;
      
      return returnval;
    }
    
    public int[] getNumberOfFields(){
      return fieldnumbers;   
    }
                                                 
    private static final int BOUNDRARY = 100;                                          
    private int[] fieldnumbers;                                            
    private HashMap dnfields;  
    private ArrayList fieldorder;
    private String  dn;
    private boolean existsother = false;
}
