/*
 * Profile.java
 *
 * Created on den 12 april 2002, 11:27
 */

package se.anatom.ejbca.ra.raadmin;
import RegularExpression.RE;

import se.anatom.ejbca.ra.raadmin.DNFieldExtractor;
import se.anatom.ejbca.SecConst;
/**
 * The model representation of a profile, used in in the ra module of ejbca web interface.
 *
 * @author  Philip Vendil
 * @version $Id: Profile.java,v 1.4 2002-08-27 12:41:07 herrvendil Exp $
 */
public class Profile implements java.io.Serializable, Cloneable {

    // Public constants
    public static final int VALUE      = 0;
    public static final int USE        = 1;
    public static final int ISREQUIRED = 2;
    public static final int CHANGEABLE = 3;

    public static final int USERNAME           = 0;
    public static final int PASSWORD           = 1;
    public static final int CLEARTEXTPASSWORD  = 2;
    public static final int COMMONNAME         = 3;
    public static final int ORGANIZATIONUNIT   = 4;
    public static final int ORGANIZATION       = 5;
    public static final int LOCALE             = 6;
    public static final int STATE              = 7;
    public static final int COUNTRY            = 8;
    public static final int EMAIL              = 9;
    public static final int TYPE_ENDUSER       = 10;
    public static final int TYPE_CA            = 11;
    public static final int TYPE_RA            = 12;
    public static final int TYPE_ROOTCA        = 13;
    public static final int TYPE_CAADMIN       = 14;
    public static final int TYPE_RAADMIN       = 15;
    public static final int DEFAULTCERTTYPE    = 16;
    public static final int AVAILABLECERTTYPES = 17;

    public static final String TRUE  = "true";
    public static final String FALSE = "false";

    public static final int NUMBEROFPARAMETERS = 18;
    
    public static final String SPLITCHAR = ";";

    // Public methods.
    /** Creates a new instance of Profile */
    public Profile() {
      // initialize profile data
      this. profiledata = new String[NUMBEROFPARAMETERS][4];

      for(int i=0; i < NUMBEROFPARAMETERS; i++){
        profiledata[i][VALUE]= "";
        profiledata[i][ISREQUIRED]= FALSE;
        profiledata[i][USE] = TRUE;
        profiledata[i][CHANGEABLE]= TRUE;
      }
      // Set default required fields.
      profiledata[USERNAME][ISREQUIRED]=TRUE;
      profiledata[PASSWORD][ISREQUIRED]=TRUE;
      profiledata[COMMONNAME][ISREQUIRED]=TRUE;
      profiledata[TYPE_ENDUSER][VALUE]=TRUE;
      profiledata[TYPE_ENDUSER][ISREQUIRED]=TRUE;
      profiledata[DEFAULTCERTTYPE][ISREQUIRED]=TRUE;
      profiledata[AVAILABLECERTTYPES][ISREQUIRED]=TRUE;  

      profiledata[DEFAULTCERTTYPE][VALUE] = "1";
      profiledata[AVAILABLECERTTYPES][VALUE] = "1;2;3";
    }

    public Profile(String[][] values){
      this();

      setAllValues(values);
    }

    /* A method to set all values in profiles data by sending an array */
    public void setAllValues(String[][] values){
      for(int i=0; i < values.length ; i++){
        profiledata[i][VALUE] = values[i][VALUE];
        profiledata[i][USE] = values[i][USE];
        profiledata[i][ISREQUIRED] = values[i][ISREQUIRED];
        profiledata[i][CHANGEABLE] = values[i][CHANGEABLE];
      }
    }

    /* method that returns all profile data in strign array format */
    public String[][] getAllValues(){
      String[][] returndata = new String[NUMBEROFPARAMETERS][4];
      for(int i = 0; i < profiledata.length; i++){
         returndata[i][VALUE] = new String(profiledata[i][VALUE]);
         returndata[i][USE] = new String(profiledata[i][USE]);         
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
    
    public void setUse(int parameter, String use){
      if(use != null){
         if(use.equals(TRUE)){
           this.profiledata[parameter][USE]=Profile.TRUE;
         }
         else{
           this.profiledata[parameter][USE]=Profile.FALSE;
         }
      }else{
         this.profiledata[parameter][USE]=Profile.FALSE;
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

    public String getValue(int parameter) {
      return this.profiledata[parameter][VALUE];
    }

    public boolean getUse(int parameter){
      return this.profiledata[parameter][USE].equals(TRUE);        
    }
    
    public boolean isRequired(int parameter) {
      return this.profiledata[parameter][ISREQUIRED].equals(TRUE);
    }

    public boolean isChangeable(int parameter){
      return this.profiledata[parameter][CHANGEABLE].equals(TRUE);
    }
    public boolean doesUserFulfillProfile(String username, String password, String dn, String email, int type,  int certificatetypeid, boolean clearpwd){
 /*      System.out.println("PASSWORD");
       System.out.println(" Use :" + (this.profiledata[PASSWORD][USE].equals(TRUE)));     
       System.out.println(" Required :" + (this.profiledata[PASSWORD][ISREQUIRED].equals(TRUE)));  
       System.out.println(" Changeable :" + (this.profiledata[PASSWORD][CHANGEABLE].equals(TRUE)));       
       System.out.println(" Profile Value : '" + this.profiledata[PASSWORD][VALUE] + "' User value '" + password +"'");  */       
       
      if(!this.profiledata[PASSWORD][CHANGEABLE].equals(TRUE)){
        if(!password.equals(this.profiledata[PASSWORD][VALUE])) 
          return false;        
      }
      else
        if(this.profiledata[PASSWORD][ISREQUIRED].equals(TRUE)){
          if(password == null || password.trim().equals(""))
          return false;           
        }
  /*     System.out.println("CLEARTEXTPASSWORD : Use " + (this.profiledata[CLEARTEXTPASSWORD][USE].equals(TRUE)) + " Used " + clearpwd);     
       System.out.println("CLEARTEXTPASSWORD : Required " + (this.profiledata[CLEARTEXTPASSWORD][ISREQUIRED].equals(TRUE)));  
       System.out.println("CLEARTEXTPASSWORD : Profile Value " + this.profiledata[CLEARTEXTPASSWORD][VALUE].equals(TRUE) + " User value " + clearpwd);     */  
      if(this.profiledata[CLEARTEXTPASSWORD][USE].equals(FALSE) && clearpwd)
          return false;
      
      if(this.profiledata[CLEARTEXTPASSWORD][ISREQUIRED].equals(TRUE)){
        if(this.profiledata[CLEARTEXTPASSWORD][VALUE].equals(TRUE) && !clearpwd)
          return false;             
        if(this.profiledata[CLEARTEXTPASSWORD][VALUE].equals(FALSE) && clearpwd)      
          return false;                 
      }             
       
       return  doesUserFulfillProfileWithoutPassword(username, dn, email, type, certificatetypeid) ;
       
    }    
    
    public boolean doesUserFulfillProfileWithoutPassword(String username,  String dn, String email, int type,  int certificatetypeid){ 
      DNFieldExtractor dnfields = new DNFieldExtractor(dn);
      String dnfield;
      String[] values;  
      
  //      System.out.println("USERNAME");
      if(!checkIfDataFullfillProfile(USERNAME,username))
        return false;
   //     System.out.println("COMMONNAME");      
      if(!checkIfDataFullfillProfile(COMMONNAME,dnfields.getField(DNFieldExtractor.COMMONNAME)))
        return false;
   //     System.out.println("ORGANIZATIONUNIT");      
      if(!checkIfDataFullfillProfile(ORGANIZATIONUNIT,dnfields.getField(DNFieldExtractor.ORGANIZATIONUNIT)))
        return false;      
   //     System.out.println("ORGANIZATION");
      if(!checkIfDataFullfillProfile(ORGANIZATION,dnfields.getField(DNFieldExtractor.ORGANIZATION)))
        return false;             
    //    System.out.println("LOCALE");      
      if(!checkIfDataFullfillProfile(LOCALE,dnfields.getField(DNFieldExtractor.LOCALE)))
        return false;     
   //     System.out.println("STATE");      
      if(!checkIfDataFullfillProfile(STATE,dnfields.getField(DNFieldExtractor.STATE)))
        return false;  
    //   System.out.println("COUNTRY");
      if(!checkIfDataFullfillProfile(COUNTRY,dnfields.getField(DNFieldExtractor.COUNTRY)))
        return false;       
    //  System.out.println("EMAIL");
      if(!checkIfDataFullfillProfile(EMAIL,email))
        return false;   

 /*      System.out.println("TYPE_ENDUSER : Use " + (this.profiledata[TYPE_ENDUSER][USE].equals(TRUE)) + " Used " + ((type & SecConst.USER_ENDUSER) != 0));     
       System.out.println("TYPE_ENDUSER : Required " + (this.profiledata[TYPE_ENDUSER][ISREQUIRED].equals(TRUE)));  
       System.out.println("TYPE_ENDUSER : Profile Value " + this.profiledata[TYPE_ENDUSER][VALUE].equals(TRUE) + " User value " + ((type & SecConst.USER_ENDUSER) != 0)); */
      if(this.profiledata[TYPE_ENDUSER][USE].equals(FALSE) &&  (type & SecConst.USER_ENDUSER) != 0)
          return false; 
  
      if(this.profiledata[TYPE_ENDUSER][ISREQUIRED].equals(TRUE)){
        if(this.profiledata[TYPE_ENDUSER][VALUE].equals(TRUE) && (type & SecConst.USER_ENDUSER) == 0)
          return false;          
        if(this.profiledata[TYPE_ENDUSER][VALUE].equals(FALSE) && (type & SecConst.USER_ENDUSER) != 0)      
          return false;            
      }  
 /*      System.out.println("TYPE_CA : Use " + (this.profiledata[TYPE_CA][USE].equals(TRUE)) + " Used " + ((type & SecConst.USER_CA) != 0));     
       System.out.println("TYPE_CA : Required " + (this.profiledata[TYPE_CA][ISREQUIRED].equals(TRUE)));  
       System.out.println("TYPE_CA : Profile Value " + this.profiledata[TYPE_CA][VALUE].equals(TRUE) + " User value " + ((type & SecConst.USER_CA) != 0)); */
      if(this.profiledata[TYPE_CA][USE].equals(FALSE) &&  (type & SecConst.USER_CA) != 0)
          return false;
      
      if(this.profiledata[TYPE_CA][ISREQUIRED].equals(TRUE)){
        if(this.profiledata[TYPE_CA][VALUE].equals(TRUE) && (type & SecConst.USER_CA) == 0)
          return false;           
        if(this.profiledata[TYPE_CA][VALUE].equals(FALSE) && (type & SecConst.USER_CA) != 0)      
          return false;                
      }  
/*       System.out.println("TYPE_RA : Use " + (this.profiledata[TYPE_RA][USE].equals(TRUE)) + " Used " + ((type & SecConst.USER_RA) != 0));     
       System.out.println("TYPE_RA : Required " + (this.profiledata[TYPE_RA][ISREQUIRED].equals(TRUE)));  
       System.out.println("TYPE_RA : Profile Value " + this.profiledata[TYPE_RA][VALUE].equals(TRUE) + " User value " + ((type & SecConst.USER_RA) != 0)); */
      if(this.profiledata[TYPE_RA][USE].equals(FALSE) &&  (type & SecConst.USER_RA) != 0)
          return false;    
      
      if(this.profiledata[TYPE_RA][ISREQUIRED].equals(TRUE)){
        if(this.profiledata[TYPE_RA][VALUE].equals(TRUE) && (type & SecConst.USER_RA) == 0)
          return false;            
        if(this.profiledata[TYPE_RA][VALUE].equals(FALSE) && (type & SecConst.USER_RA) != 0)      
          return false;                    
      }  
  /*     System.out.println("TYPE_ROOTCA : Use " + (this.profiledata[TYPE_ROOTCA][USE].equals(TRUE)) + " Used " + ((type & SecConst.USER_ROOTCA) != 0));     
       System.out.println("TYPE_ROOTCA : Required " + (this.profiledata[TYPE_ROOTCA][ISREQUIRED].equals(TRUE)));  
       System.out.println("TYPE_ROOTCA : Profile Value " + this.profiledata[TYPE_ROOTCA][VALUE].equals(TRUE) + " User value " + ((type & SecConst.USER_ROOTCA) != 0)); */
      if(this.profiledata[TYPE_ROOTCA][USE].equals(FALSE) &&  (type & SecConst.USER_ROOTCA) != 0)
          return false;
      
      if(this.profiledata[TYPE_ROOTCA][ISREQUIRED].equals(TRUE)){
        if(this.profiledata[TYPE_ROOTCA][VALUE].equals(TRUE) && (type & SecConst.USER_ROOTCA) == 0)
          return false;         
        if(this.profiledata[TYPE_ROOTCA][VALUE].equals(FALSE) && (type & SecConst.USER_ROOTCA) != 0)      
          return false;             
      }  
 /*      System.out.println("TYPE_CAADMIN : Use " + (this.profiledata[TYPE_CAADMIN][USE].equals(TRUE)) + " Used " + ((type & SecConst.USER_CAADMIN) != 0));     
       System.out.println("TYPE_CAADMIN : Required " + (this.profiledata[TYPE_CAADMIN][ISREQUIRED].equals(TRUE)));  
       System.out.println("TYPE_CAADMIN : Profile Value " + this.profiledata[TYPE_CAADMIN][VALUE].equals(TRUE) + " User value " + ((type & SecConst.USER_CAADMIN) != 0));  */
      if(this.profiledata[TYPE_CAADMIN][USE].equals(FALSE) &&  (type & SecConst.USER_CAADMIN) != 0)
          return false;
      
      if(this.profiledata[TYPE_CAADMIN][ISREQUIRED].equals(TRUE)){
        if(this.profiledata[TYPE_CAADMIN][VALUE].equals(TRUE) && (type & SecConst.USER_CAADMIN) == 0)
          return false;           
        if(this.profiledata[TYPE_CAADMIN][VALUE].equals(FALSE) && (type & SecConst.USER_CAADMIN) != 0)      
          return false;                   
      }  
 /*      System.out.println("TYPE_RAADMIN : Use " + (this.profiledata[TYPE_RAADMIN][USE].equals(TRUE)) + " Used " + ((type & SecConst.USER_RAADMIN) != 0));     
       System.out.println("TYPE_RAADMIN : Required " + (this.profiledata[TYPE_RAADMIN][ISREQUIRED].equals(TRUE)));  
       System.out.println("TYPE_RAADMIN : Profile Value " + this.profiledata[TYPE_RAADMIN][VALUE].equals(TRUE) + " User value " + ((type & SecConst.USER_RAADMIN) != 0));   */
      if(this.profiledata[TYPE_RAADMIN][USE].equals(FALSE) &&  (type & SecConst.USER_RAADMIN) != 0)
          return false;
      
      if(this.profiledata[TYPE_RAADMIN][ISREQUIRED].equals(TRUE)){
        if(this.profiledata[TYPE_RAADMIN][VALUE].equals(TRUE) && (type & SecConst.USER_RAADMIN) == 0)
          return false;            
        if(this.profiledata[TYPE_RAADMIN][VALUE].equals(FALSE) && (type & SecConst.USER_RAADMIN) != 0)      
          return false;                          
      } 
       
//      System.out.println("AVAILABLECERTTYPES : " + this.profiledata[AVAILABLECERTTYPES][VALUE] + " certtypeid " + certificatetypeid);       
      String[] availablecerttypes; 
      try{
        availablecerttypes = new RE(SPLITCHAR, false).split(this.profiledata[AVAILABLECERTTYPES][VALUE]);  
      }catch(Exception e){
        return false;   
      }
      if(availablecerttypes == null)
          return false;     
      else{
        boolean found=false;  
        for(int i=0; i < availablecerttypes.length;i++){
          if( Integer.parseInt(availablecerttypes[i]) == certificatetypeid)
            found=true;
        }
        
        if(!found)
          return false;
      }
      System.out.println("Check profile : return true");   
      return true;  
    }
    
    public Object clone() throws CloneNotSupportedException {
      return super.clone();
    }
    // Private Methods
    
    private boolean checkIfDataFullfillProfile(int field, String data){
 /*      System.out.println(" Use :" + (this.profiledata[field][USE].equals(TRUE)));     
       System.out.println(" Required :" + (this.profiledata[field][ISREQUIRED].equals(TRUE)));  
       System.out.println(" Changeable :" + (this.profiledata[field][CHANGEABLE].equals(TRUE))); 
       System.out.println(" Profile Value : '" + this.profiledata[field][VALUE] + "' User value '" + data + "'");   */      
     try{  
      if(data !=null)        
        if(this.profiledata[field][USE].equals(FALSE) && !data.trim().equals(""))
          return false;
      
      if(!this.profiledata[field][CHANGEABLE].equals(TRUE)){
        String[] values = new RE(SPLITCHAR, false).split(this.profiledata[field][VALUE]);  
        boolean exists = false;
        for(int i = 0; i < values.length ; i++){
          if(data.equals(values[i].trim())) 
            exists = true;
        }   
        if(!exists)
          return false;   
      }
      else
        if(this.profiledata[field][ISREQUIRED].equals(TRUE)){
          if(data == null || data.trim().equals(""))
          return false;          
        }        
      return true;
     }catch(Exception e){
       return false;   
     }
    }

    // Private Constants.

    // Private fields.
    private String[][] profiledata;

}
