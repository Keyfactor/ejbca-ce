/*
 * UserViewFilter.java
 *
 * Created on den 18 april 2002, 16:38
 */

package se.anatom.ejbca.webdist.rainterface;

/**
 * A class representing a filter used when searching the database.
 *
 * @author  Philip Vendil
 */
public class UserViewFilter {
    // Public constants.
    public static final String TYPE_EQUAL = " ";
    public static final String TYPE_NOTEQUAL = "NOT";
    
    public static final String WITH_USERNAME         = "username";
    public static final String WITH_COMMONNAME       = "commonname";
    public static final String WITH_ORGANIZATIONUNIT = "organizationunit";
    public static final String WITH_ORGANIZATION     = "organization";
    public static final String WITH_LOCALE           = "locale";
    public static final String WITH_STATE            = "state";
    public static final String WITH_COUNTRY          = "country";
    public static final String WITH_EMAIL            = "email";
    public static final String WITH_TYPE_INVALID     = "typeinvalid";
    public static final String WITH_TYPE_ENDUSER     = "typeenduser";
    public static final String WITH_TYPE_CA          = "typeca";
    public static final String WITH_TYPE_RA          = "typera";
    public static final String WITH_TYPE_ROOTCA      = "typerootca";
    public static final String WITH_TYPE_CAADMIN     = "typecaadmin";
    public static final String WITH_TYPE_RAADMIN     = "typeraadmin";
    
    public static final String VALUE_ALL             = "*";
    
    /** Creates a new instance of UserViewFilter */
    public UserViewFilter() {
      filtertype=TYPE_EQUAL;
      matchwith=WITH_USERNAME;
      matchvalue=VALUE_ALL;
    }
    
    public UserViewFilter(String filtertype, String matchwith, String matchvalue){
      this.filtertype=filtertype;
      this.matchwith=matchwith;
      this.matchvalue=matchvalue;
    }
    
    // Public metods
    
    public String getFilterType(){
      return filtertype;   
    }
    
    public void setFilterType(String filtertype){
      this.filtertype=filtertype;
    }
    
    public String getMatchWith(){
      return matchwith;   
    }
    
    public void setMatchWith(String matchwith){
      this.matchwith=matchwith;
    }
    
    public String getMatchValue(){
      return matchvalue;
    }
    
    public void setMatchValue(String matchvalue){
      this.matchvalue=matchvalue;   
    }
    // Private constants
    
    // Private fields
    private String filtertype;
    private String matchwith;
    private String matchvalue;
}
