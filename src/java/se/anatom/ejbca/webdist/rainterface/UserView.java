/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package se.anatom.ejbca.webdist.rainterface;

import java.util.Date;
import java.util.HashMap;

import se.anatom.ejbca.ra.UserAdminData;
import se.anatom.ejbca.ra.raadmin.DNFieldExtractor;
import se.anatom.ejbca.util.StringTools;

/**
 * A class representing a web interface view of a user in the ra user database.
 *
 * @version $Id: UserView.java,v 1.17 2004-04-16 07:38:55 anatom Exp $
 */
public class UserView implements java.io.Serializable, Cloneable, Comparable {
    // Public constants.

   public UserView(HashMap  caidtonamemap){
      userdata = new UserAdminData();
      userdata.setType(1);
      subjectdnfields = new DNFieldExtractor("", DNFieldExtractor.TYPE_SUBJECTDN);
      subjectaltnames = new DNFieldExtractor("", DNFieldExtractor.TYPE_SUBJECTALTNAME);
   }


    public UserView(UserAdminData newuserdata, HashMap caidtonamemap){
      userdata = newuserdata;
      this.caname = (String) caidtonamemap.get(new Integer(newuserdata.getCAId()));
      subjectdnfields = new DNFieldExtractor(userdata.getDN(), DNFieldExtractor.TYPE_SUBJECTDN);
      subjectaltnames = new DNFieldExtractor(userdata.getSubjectAltName(), DNFieldExtractor.TYPE_SUBJECTALTNAME);
      setCommonName(); 

      cleartextpwd = userdata.getPassword() != null;
    }

    public void setUsername(String user) { userdata.setUsername(StringTools.strip(user));}
    public String getUsername() {return userdata.getUsername();}

    public void setSubjectDN(String dn) {
      userdata.setDN(dn);
      subjectdnfields.setDN(dn, DNFieldExtractor.TYPE_SUBJECTDN);
      
      setCommonName();
    }
    public String getSubjectDN() {return userdata.getDN();}

    public void setSubjectAltName( String subjectaltname) {
      userdata.setSubjectAltName(subjectaltname);
      subjectaltnames.setDN(subjectaltname, DNFieldExtractor.TYPE_SUBJECTALTNAME);
    }
    public String getSubjectAltName() {return userdata.getSubjectAltName();}

    public void setEmail(String email) { userdata.setEmail(email);}
    public String getEmail() {return userdata.getEmail();}

    public void setPassword(String pwd) {userdata.setPassword(pwd);}
    public String getPassword() {return userdata.getPassword();}

    public boolean getClearTextPassword(){ return cleartextpwd;}
    public void setClearTextPassword(boolean cleartextpwd){ this.cleartextpwd=cleartextpwd;}

    public void setStatus(int status) {userdata.setStatus(status);}
    public int getStatus() {return userdata.getStatus();}
    public void setType(int type) {userdata.setType(type);}
    public int getType() {return userdata.getType();}
    public void setAdministrator(boolean admin) {userdata.setAdministrator(admin);}
    public boolean getAdministrator() {return userdata.getAdministrator();}
    public void setKeyRecoverable(boolean keyrecoverable) {userdata.setKeyRecoverable(keyrecoverable);}
    public boolean getKeyRecoverable() {return userdata.getKeyRecoverable();}
    public void setSendNotification(boolean sendnotification) {userdata.setSendNotification(sendnotification);}
    public boolean getSendNotification() {return userdata.getSendNotification();}
    public void setEndEntityProfileId(int profileid) { userdata.setEndEntityProfileId(profileid); }
    public int getEndEntityProfileId(){ return userdata.getEndEntityProfileId(); }
    public void setCertificateProfileId(int profileid) { userdata.setCertificateProfileId(profileid); }
    public int getCertificateProfileId() {return userdata.getCertificateProfileId();}
    public void setTimeCreated(Date timecreated) { userdata.setTimeCreated(timecreated); }
    public Date getTimeCreated() {return userdata.getTimeCreated();}
    public void setTimeModified(Date timemodified) { userdata.setTimeModified(timemodified); }
    public Date getTimeModified() {return userdata.getTimeModified();}
    public int getTokenType(){ return userdata.getTokenType();}
    public void setTokenType(int tokentype) {userdata.setTokenType(tokentype);}
    public int getHardTokenIssuerId() {return userdata.getHardTokenIssuerId();}
    public void setHardTokenIssuerId(int hardtokenissuerid) { userdata.setHardTokenIssuerId(hardtokenissuerid);}
    public int getCAId() {return userdata.getCAId();}
    public void setCAId(int caid) { userdata.setCAId(caid);}
    public String getCAName() { return caname;}

    
    public String getSubjectDNField(int parameter, int number){
      return subjectdnfields.getField(parameter,number);
    }

    public String getSubjectAltNameField(int parameter, int number){
      return subjectaltnames.getField(parameter,number);
    }
    
    /**
     * getCommonName is a special function used in list end entity gui to display names in cases not a CN field exists in dn only, surname and givennamn
     */
    public String getCommonName(){
      return commonname;   
    }
    
    private void setCommonName(){
        commonname = getSubjectDNField(DNFieldExtractor.CN,0);
        if(commonname.equals("")){
          commonname = getSubjectDNField(DNFieldExtractor.GIVENNAME,0) + " " + getSubjectDNField(DNFieldExtractor.SURNAME,0);
        }                    
    }

    public int compareTo(Object obj) {
      int returnvalue = -1;
      int sortby = this.sortby.getSortBy();
      switch(sortby){
          case SortBy.USERNAME :
            returnvalue = getUsername().compareTo(((UserView) obj).getUsername());
            break;
          case SortBy.COMMONNAME :
            returnvalue = this.commonname.compareTo(((UserView) obj).getCommonName());
            break;
          case SortBy.SERIALNUMBER :
            returnvalue = getSubjectDNField(DNFieldExtractor.SN,0).compareTo(((UserView) obj).getSubjectDNField(DNFieldExtractor.SN,0));
            break;
          case SortBy.TITLE :
            returnvalue = getSubjectDNField(DNFieldExtractor.T,0).compareTo(((UserView) obj).getSubjectDNField(DNFieldExtractor.T,0));
            break;
          case SortBy.ORGANIZATIONUNIT :
            returnvalue = getSubjectDNField(DNFieldExtractor.OU,0).compareTo(((UserView) obj).getSubjectDNField(DNFieldExtractor.OU,0));
            break;
          case SortBy.ORGANIZATION :
            returnvalue = getSubjectDNField(DNFieldExtractor.O,0).compareTo(((UserView) obj).getSubjectDNField(DNFieldExtractor.O,0));
            break;
          case SortBy.LOCALE :
            returnvalue = getSubjectDNField(DNFieldExtractor.L,0).compareTo(((UserView) obj).getSubjectDNField(DNFieldExtractor.L,0));
            break;
          case SortBy.STATE :
            returnvalue = getSubjectDNField(DNFieldExtractor.ST,0).compareTo(((UserView) obj).getSubjectDNField(DNFieldExtractor.ST,0));
            break;
          case SortBy.DOMAINCOMPONENT :
            returnvalue = getSubjectDNField(DNFieldExtractor.DC,0).compareTo(((UserView) obj).getSubjectDNField(DNFieldExtractor.DC,0));
            break;
          case SortBy.COUNTRY :
            returnvalue = getSubjectDNField(DNFieldExtractor.C,0).compareTo(((UserView) obj).getSubjectDNField(DNFieldExtractor.C,0));
            break;
          case SortBy.EMAIL :
            returnvalue = getEmail().compareTo(((UserView) obj).getEmail());
            break;
          case SortBy.STATUS :
            returnvalue = (new Integer(getStatus())).compareTo(new Integer(((UserView) obj).getStatus()));
            break;
          case SortBy.TIMECREATED :
            returnvalue = getTimeCreated().compareTo(((UserView) obj).getTimeCreated());
            break;
          case SortBy.TIMEMODIFIED :
            returnvalue = getTimeModified().compareTo(((UserView) obj).getTimeModified());
            break;
          case SortBy.CA :
            returnvalue =  getCAName().compareTo(((UserView) obj).getCAName());
            break;            
          default:
            returnvalue = getUsername().compareTo(((UserView) obj).getUsername());

      }
      if(this.sortby.getSortOrder() == SortBy.DECENDING)
        returnvalue = 0-returnvalue;

      return returnvalue;
    }

    public void setSortBy(SortBy sortby){
      this.sortby=sortby;
    }

    // Private constants.

    // Private methods.
    private SortBy sortby;
    private UserAdminData userdata;
    private DNFieldExtractor subjectdnfields;
    private DNFieldExtractor subjectaltnames;
    private String commonname = "";
    private String caname;
    private boolean cleartextpwd;
}
