/*
 * Profile.java
 *
 * Created on den 12 april 2002, 11:27
 */

package se.anatom.ejbca.ra.raadmin;

/**
 * The model representation of a profile, used in in the ra module of ejbca web interface.
 *
 * @author  Philip Vendil
 */
public class Profile implements java.io.Serializable, Cloneable {
    
    // Public constants
    public static final int VALUE      = 0;    
    public static final int ISREQUIRED = 1;
    public static final int CHANGEABLE = 2;
    
    public static final int USERNAME          = 0;
    public static final int PASSWORD          = 1;
    public static final int CLEARTEXTPASSWORD = 2; 
    public static final int COMMONNAME        = 3;
    public static final int ORGANIZATIONUNIT  = 4;
    public static final int ORGANIZATION      = 5;
    public static final int LOCALE            = 6;
    public static final int STATE             = 7;
    public static final int COUNTRY           = 8;
    public static final int EMAIL             = 9;
    public static final int TYPE_ENDUSER     = 10;
    public static final int TYPE_CA          = 11;
    public static final int TYPE_RA          = 12;
    public static final int TYPE_ROOTCA      = 13;
    public static final int TYPE_CAADMIN     = 14;
    public static final int TYPE_RAADMIN     = 15;
    
    public static final String TRUE  = "true";
    public static final String FALSE = "false";
    
    public static final int NUMBEROFPARAMETERS = 16;

    // Public methods.
    /** Creates a new instance of Profile */
    public Profile() {
      // initialize profile data  
      this. profiledata = new String[NUMBEROFPARAMETERS][3];
      
      for(int i=0; i < NUMBEROFPARAMETERS; i++){
        profiledata[i][VALUE]= "";          
        profiledata[i][ISREQUIRED]= FALSE;  
        profiledata[i][CHANGEABLE]= TRUE;
      }
      // Set default required fields.
      profiledata[USERNAME][ISREQUIRED]=TRUE;
      profiledata[PASSWORD][ISREQUIRED]=TRUE;
      profiledata[COMMONNAME][ISREQUIRED]=TRUE;    
      profiledata[TYPE_ENDUSER][VALUE]=TRUE;
      profiledata[TYPE_ENDUSER][ISREQUIRED]=TRUE;     
    }
    
    public Profile(String[][] values){
      this();
      
      setAllValues(values);
    }
    
    /* A method to set all values in profiles data by sending an array */
    public void setAllValues(String[][] values){
      for(int i=0; i < values.length ; i++){
        profiledata[i][VALUE] = values[i][VALUE];
        profiledata[i][ISREQUIRED] = values[i][ISREQUIRED];
        profiledata[i][CHANGEABLE] = values[i][CHANGEABLE];
      }
    }
    
    /* method that returns all profile data in strign array format */
    public String[][] getAllValues(){
      String[][] returndata = new String[NUMBEROFPARAMETERS][3];
      for(int i = 0; i < profiledata.length; i++){
         returndata[i][VALUE] = new String(profiledata[i][VALUE]); 
         returndata[i][ISREQUIRED] = new String(profiledata[i][ISREQUIRED]);  
         returndata[i][CHANGEABLE] = new String(profiledata[i][CHANGEABLE]);  
      }
      return returndata;   
    }
    
    public void setValue(int parameter, String value) {
       if(value !=null){
          value=value.trim(); 
          this.profiledata[parameter][VALUE]=value; 
       }else{
          this.profiledata[parameter][VALUE]=""; 
       }         
    }
    
    public void setRequired(int parameter, String isrequired) {
      if(isrequired != null){
         if(isrequired.equals(TRUE)){
           this.profiledata[parameter][ISREQUIRED]=Profile.TRUE;                  
         }
         else{
           this.profiledata[parameter][ISREQUIRED]=Profile.FALSE; 
         }
      }else{
         this.profiledata[parameter][ISREQUIRED]=Profile.FALSE; 
      }
    }
    
    public void setChangeable(int parameter, String changeable) {
      if(changeable != null){
         if(changeable.equals(TRUE)){
           this.profiledata[parameter][CHANGEABLE]=Profile.TRUE;                  
         }
         else{
           this.profiledata[parameter][CHANGEABLE]=Profile.FALSE; 
         }
      }else{
         this.profiledata[parameter][CHANGEABLE]=Profile.FALSE; 
      }
    }    
    
    public void setUsedInEnrollment(boolean used) {
      this.usedinenrollment=used;  
    }
    
    public String getValue(int parameter) {
      return this.profiledata[parameter][VALUE];
    }
    
    public boolean isRequried(int parameter) {
      return this.profiledata[parameter][ISREQUIRED].equals(TRUE); 
    } 
    
    public boolean isChangeable(int parameter){
      return this.profiledata[parameter][CHANGEABLE].equals(TRUE);       
    }
    
    public boolean isUsedInEnrollment() {
      return this.usedinenrollment;
    }

    public Object clone() throws CloneNotSupportedException {
      return super.clone();   
    }
    // Private Methods
    
    // Private Constants.

    // Private fields.
    private String[][] profiledata;
    private boolean usedinenrollment=false;
    
}
