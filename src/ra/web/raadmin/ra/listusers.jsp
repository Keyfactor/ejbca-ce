<html>
<%@page contentType="text/html"%>
<%@page errorPage="/errorpage.jsp"  import="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean,se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration, 
                 se.anatom.ejbca.webdist.rainterface.UserView, se.anatom.ejbca.webdist.rainterface.SortBy,
                 se.anatom.ejbca.webdist.rainterface.RAInterfaceBean, se.anatom.ejbca.ra.UserData,
                 javax.ejb.CreateException, java.rmi.RemoteException" %>
<jsp:useBean id="ejbcawebbean" scope="session" class="se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean" />
<jsp:setProperty name="ejbcawebbean" property="*" /> 
<jsp:useBean id="rabean" scope="session" class="se.anatom.ejbca.webdist.rainterface.RAInterfaceBean" />
<jsp:setProperty name="rabean" property="*" /> 
<%! // Declarations

  static final String ACTION                   = "action";
  static final String ACTION_LISTUSERS         = "listusers";

  static final String USER_PARAMETER           = "userparameter";
  static final String SUBJECTDN_PARAMETER      = "subjectdnparameter";

  static final String VIEWUSER_LINK            = "viewuser.jsp";
  static final String EDITUSER_LINK            = "edituser.jsp";
  static final String VIEWCERT_LINK            = "viewcertificate.jsp";

  static final String OLD_ACTION               = "oldaction";
  static final String OLD_ACTION_LISTUSERS     = "oldactionlistusers";
  static final String OLD_ACTION_FINDUSER      = "oldactionfinduser";
  static final String OLD_ACTION_ISREVOKED     = "oldactionisrevoked";
  static final String OLD_ACTION_LISTEXPIRED   = "oldactionlistexpired";
  static final String OLD_ACTION_NOACTION      = "oldactionnoaction";  
  static final String OLD_ACTION_VALUE         = "oldactionvalue";

  static final String BUTTON_VIEW_USER         = "buttonviewuser"; 
  static final String BUTTON_EDIT_USER         = "buttonedituser"; 
  static final String BUTTON_VIEW_CERTIFICATE  = "buttonviewcertificate"; 
  static final String BUTTON_DELETE_USERS      = "buttondeleteusers";
  static final String BUTTON_CHANGESTATUS      = "buttonchangestatus"; 
  static final String BUTTON_REVOKE_USERS      = "buttonrevokeusers";  
  static final String BUTTON_FIND              = "buttonfind";
  static final String BUTTON_LIST              = "buttonlist";
  static final String BUTTON_ISREVOKED         = "buttonisrevoked";
  static final String BUTTON_LISTEXPIRED       = "buttonlistexpired";

  static final String BUTTON_NEXT              = "buttonnext";
  static final String BUTTON_PREVIOUS          = "buttonprevious";
  static final String BUTTON_SELECTALL         = "buttonselectall";
  static final String BUTTON_DESELECTALL       = "buttondeselectall";
  static final String BUTTON_INVERTSELECTION   = "buttoninvertselection";

  static final String SORTBY_USERNAME_ACC         = "sortbyusernameaccending";
  static final String SORTBY_USERNAME_DEC         = "sortbyusernamedecending";
  static final String SORTBY_COMMONNAME_ACC       = "sortbycommonnameaccending";
  static final String SORTBY_COMMONNAME_DEC       = "sortbycommonnamedecending";
  static final String SORTBY_ORGANIZATIONUNIT_ACC = "sortbyorganizationunitaccending";
  static final String SORTBY_ORGANIZATIONUNIT_DEC = "sortbyorganizationunitdecending";
  static final String SORTBY_ORGANIZATION_ACC     = "sortbyorganizationaccending";
  static final String SORTBY_ORGANIZATION_DEC     = "sortbyorganizationdecending";
  static final String SORTBY_STATUS_ACC           = "sortbystatusaccending";
  static final String SORTBY_STATUS_DEC           = "sortbystatusdecending";

  static final String SELECT_LIST_STATUS        = "selectliststatus";
  static final String SELECT_CHANGE_STATUS      = "selectchangestatus"; 

  static final String CHECKBOX_SELECT_USER      = "checkboxselectuser";
  static final String CHECKBOX_VALUE            = "true";

  static final String TEXTFIELD_USERNAME        = "textfieldusername";
  static final String TEXTFIELD_SERIALNUMBER    = "textfieldserialnumber";
  static final String TEXTFIELD_DAYS            = "textfielddays";

  static final String HIDDEN_SORTBY             = "hiddensortby";
  static final String HIDDEN_USERNAME           = "hiddenusername";
  static final String HIDDEN_USERDN             = "hiddenuserdn";
  static final String HIDDEN_RECORDNUMBER       = "hiddenrecordnumber"; 
%><%
  // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request); 

  String oldaction      = OLD_ACTION_NOACTION; 
  String oldactionvalue = null;
  String sortby         = SORTBY_USERNAME_ACC;

  boolean blank                   = true;
  String THIS_FILENAME            =  globalconfiguration.getRaPath()  + "/listusers.jsp";
  String[][] users                = null;
  int numcheckboxes               = 0;
  boolean editbuttonpressed       = false;




  // Determine action 
  int record   = 0;
  int size = ejbcawebbean.getEntriesPerPage();
 
  if (request.getParameter(HIDDEN_RECORDNUMBER) != null ){
    record =  Integer.parseInt(request.getParameter(HIDDEN_RECORDNUMBER)); 
  } 

  if (request.getParameter(HIDDEN_SORTBY) != null ){
    sortby =  request.getParameter(HIDDEN_SORTBY); 
  } 

  if( request.getParameter(OLD_ACTION) != null){
    oldaction = request.getParameter(OLD_ACTION);
    if(request.getParameter(OLD_ACTION_VALUE) != null){
      oldactionvalue= request.getParameter(OLD_ACTION_VALUE);
    }
  }

  if( request.getParameter(ACTION) != null){
    if( request.getParameter(ACTION).equals(ACTION_LISTUSERS)){
      blank=false;
      if( request.getParameter(BUTTON_VIEW_USER) != null){
        editbuttonpressed=true;

      }

      if( request.getParameter(BUTTON_EDIT_USER) != null){
        editbuttonpressed=true;

      }
      if( request.getParameter(BUTTON_VIEW_CERTIFICATE) != null){
        editbuttonpressed=true;

      }
      if( request.getParameter(BUTTON_DELETE_USERS) != null){
          // Delete selected users
          // TEMPORATE
       editbuttonpressed=true;
       java.util.Enumeration parameters = request.getParameterNames();
       java.util.Vector indexes = new  java.util.Vector();
       int index;
       while(parameters.hasMoreElements()){
        String parameter = (String) parameters.nextElement();
         if(parameter.startsWith(CHECKBOX_SELECT_USER) && request.getParameter(parameter).equals(CHECKBOX_VALUE)) {
           index = java.lang.Integer.parseInt(parameter.substring(CHECKBOX_SELECT_USER.length())); //Without []
           indexes.addElement(new Integer(index));
         }
       }
       
       if(indexes.size() > 0){
         String[] usernames = new String[indexes.size()];
         for(int i = 0; i < indexes.size(); i++){
           index = ((java.lang.Integer) indexes.elementAt(i)).intValue();
           usernames[i] = request.getParameter(HIDDEN_USERNAME+index);
         }
         rabean.deleteUsers(usernames);
       }
      }
      if( request.getParameter(BUTTON_REVOKE_USERS) != null){
          // Revoke selected users
          // TEMPORATE
       editbuttonpressed=true;
       java.util.Enumeration parameters = request.getParameterNames();
       java.util.Vector indexes = new  java.util.Vector();
       int index;
       while(parameters.hasMoreElements()){
        String parameter = (String) parameters.nextElement();
         if(parameter.startsWith(CHECKBOX_SELECT_USER) && request.getParameter(parameter).equals(CHECKBOX_VALUE)) {
           index = java.lang.Integer.parseInt(parameter.substring(CHECKBOX_SELECT_USER.length())); //Without []
           indexes.addElement(new Integer(index));
         }
       }
       
       if(indexes.size() > 0){
         String[] usernames = new String[indexes.size()];
         for(int i = 0; i < indexes.size(); i++){
           index = ((java.lang.Integer) indexes.elementAt(i)).intValue();
           usernames[i] = request.getParameter(HIDDEN_USERNAME+index);
         }
         rabean.revokeUsers(usernames);
       }
      }
      if( request.getParameter(BUTTON_CHANGESTATUS) != null){
          // Change statuse on selected users
          // TEMPORATE
       editbuttonpressed=true;
       java.util.Enumeration parameters = request.getParameterNames();
       java.util.Vector indexes = new  java.util.Vector();
       int index;
       while(parameters.hasMoreElements()){
        String parameter = (String) parameters.nextElement();
         if(parameter.startsWith(CHECKBOX_SELECT_USER) && request.getParameter(parameter).equals(CHECKBOX_VALUE)) {
         out.write(parameter+" , ");
           index = java.lang.Integer.parseInt(parameter.substring(CHECKBOX_SELECT_USER.length())); //Without []
           indexes.addElement(new Integer(index));
         }
       }
       
       String newstatus = request.getParameter(SELECT_CHANGE_STATUS);
       if(indexes.size() > 0){
         String[] usernames = new String[indexes.size()];
         for(int i = 0; i < indexes.size(); i++){
           index = ((java.lang.Integer) indexes.elementAt(i)).intValue();
           usernames[i] = request.getParameter(HIDDEN_USERNAME+index);
         }
         if(newstatus != null && !newstatus.trim().equals("")) 
           rabean.setUserStatuses(usernames,newstatus);
       }
      }
    }
   }
 
   if( request.getParameter(SORTBY_USERNAME_ACC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_USERNAME_ACC;
     rabean.sortUserData(SortBy.USERNAME,SortBy.ACCENDING);
   }
   if( request.getParameter(SORTBY_USERNAME_DEC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_USERNAME_DEC;
     rabean.sortUserData(SortBy.USERNAME,SortBy.DECENDING);
   }
   if( request.getParameter(SORTBY_COMMONNAME_ACC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_COMMONNAME_ACC;
     rabean.sortUserData(SortBy.COMMONNAME,SortBy.ACCENDING);
   }
   if( request.getParameter(SORTBY_COMMONNAME_DEC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_COMMONNAME_DEC;
     rabean.sortUserData(SortBy.COMMONNAME,SortBy.DECENDING);
   }
   if( request.getParameter(SORTBY_ORGANIZATIONUNIT_ACC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_ORGANIZATIONUNIT_ACC;
     rabean.sortUserData(SortBy.ORGANIZATIONUNIT,SortBy.ACCENDING);
   }
   if( request.getParameter(SORTBY_ORGANIZATIONUNIT_DEC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_ORGANIZATIONUNIT_DEC;
     rabean.sortUserData(SortBy.ORGANIZATIONUNIT,SortBy.DECENDING);
   }
   if( request.getParameter(SORTBY_ORGANIZATION_ACC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_ORGANIZATION_ACC;
     rabean.sortUserData(SortBy.ORGANIZATION,SortBy.ACCENDING);
   }
   if( request.getParameter(SORTBY_ORGANIZATION_DEC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_ORGANIZATION_DEC;
     rabean.sortUserData(SortBy.ORGANIZATION,SortBy.DECENDING);
   }
   if( request.getParameter(SORTBY_STATUS_ACC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_STATUS_ACC;
     rabean.sortUserData(SortBy.STATUS,SortBy.ACCENDING);
   }
   if( request.getParameter(SORTBY_STATUS_DEC+".x") != null ){
     // Sortby username accending
     sortby = SORTBY_STATUS_DEC;
     rabean.sortUserData(SortBy.STATUS,SortBy.DECENDING);
   }

   if( request.getParameter(BUTTON_PREVIOUS) != null ){
     record = Integer.parseInt(request.getParameter(HIDDEN_RECORDNUMBER));
     record -= ejbcawebbean.getEntriesPerPage();
     if(record < 0 ) record=0;
   }
   if( request.getParameter(BUTTON_NEXT) != null ){
     record = Integer.parseInt(request.getParameter(HIDDEN_RECORDNUMBER));
     record += ejbcawebbean.getEntriesPerPage();
   }

   if( editbuttonpressed && oldaction.equals(OLD_ACTION_FINDUSER) ){
        String user = oldactionvalue; 
       if(user != null){
         if(!user.trim().equals("")){
           users = rabean.filterByUsername(user);
         }
       }
     }else{
       if( editbuttonpressed && oldaction.equals(OLD_ACTION_LISTUSERS) ){
         String status = oldactionvalue;
         if(status != null){
           if(!status.trim().equals("")){
             users = rabean.filterByStatus(status,record,size);
         }
       }
     }else{
       if( editbuttonpressed && oldaction.equals(OLD_ACTION_ISREVOKED) ){
         String serialnumber = oldactionvalue;
         if(serialnumber != null){
           if(!serialnumber.trim().equals("")){
             users = rabean.filterByCertificateSerialNumber(serialnumber.trim(),record,size);
         }
       }
     }else{
       if( editbuttonpressed && oldaction.equals(OLD_ACTION_LISTEXPIRED) ){
         String days = oldactionvalue;
         if(days != null){
           if(!days.trim().equals("")){
             users = rabean.filterByExpiringCertificates(days.trim(),record,size);
         }
       }
     }
     else{
       if( request.getParameter(BUTTON_FIND) != null){
         String username = request.getParameter(TEXTFIELD_USERNAME); 
         if(username != null){
           username=username.trim();
           if(!username.equals("")){
             record=0;
             users = rabean.filterByUsername(username);
             oldaction=OLD_ACTION_FINDUSER;
             oldactionvalue=username;
          }
        }
      }else{
         if( request.getParameter(BUTTON_LIST) != null){
           String status = request.getParameter(SELECT_LIST_STATUS); 
           if(status != null){
             status= status.trim();
             if(!status.equals("")){
               record=0;
               users = rabean.filterByStatus(status,record,size);
               oldaction=OLD_ACTION_LISTUSERS;
               oldactionvalue=status;
             }
           }
         }else{
           if( request.getParameter(BUTTON_ISREVOKED) != null){
               String serialnumber = request.getParameter(TEXTFIELD_SERIALNUMBER);  
               if(serialnumber != null){
                 serialnumber=serialnumber.trim();
                 if(!serialnumber.equals("")){
                   record=0;   
                   users = rabean.filterByCertificateSerialNumber(serialnumber,record,size);
                   oldaction=OLD_ACTION_ISREVOKED;
                   oldactionvalue=serialnumber;  
                 }
               }

           }else{
             if( request.getParameter(BUTTON_LISTEXPIRED) != null){
               String days = request.getParameter(TEXTFIELD_DAYS); 
               if(days != null){
                 days=days.trim();
                 if(!days.equals("")){                
                   record=0;   
                   users = rabean.filterByExpiringCertificates(days,record,size);
                   oldaction=OLD_ACTION_LISTEXPIRED;
                   oldactionvalue=days; 
                 }
               }
            }else{
            users = rabean.getUsers(record,size);
            }}}
          }
        }
      }
    }
  }
  if(users != null){ 
    numcheckboxes= users.length;
  }

%>

<%@ include file="listuserhtml.jsp" %>
