<%@ page pageEncoding="ISO-8859-1"%>
<%@ page contentType="text/html; charset=@page.encoding@" %>
<%@ page language="java" import="javax.naming.*,javax.rmi.*,java.util.*,java.security.cert.*,org.ejbca.ui.web.RequestHelper,
                                 org.ejbca.core.model.log.Admin, org.ejbca.core.model.ApplyBean, org.ejbca.core.model.SecConst"%>

<jsp:useBean id="applybean" scope="session" class="org.ejbca.core.model.ApplyBean" />
<%!
  static final String ACTION                              = "action";
  static final String ACTION_GENERATETOKEN                = "generatetoken";

  static final String BUTTON_SUBMIT_USERNAME               = "buttonsubmitusername"; 
  static final String TEXTFIELD_USERNAME                   = "textfieldusername";
  static final String TEXTFIELD_PASSWORD                   = "textfieldpassword";

  static final String HIDDEN_BROWSER                       = "hiddenbrowser";
  static final String FORCE_BROWSER                        = "forcebrowser";

  static final String BROWSER_NETSCAPE                     = "netscape";
  static final String BROWSER_EXPLORER                     = "explorer";
  static final String BROWSER_UNKNOWN                      = "browserunknown";
%>

<%
  applybean.initialize(request);

  int[] defaultkeylengths        = {512,1024,2048};
  String includefile = "apply_auth.jspf";
  String username = "";
  String password = "";
  String browser  = null;
  int[] availablekeylengths = null;
  int caid =0;

  RequestHelper.setDefaultCharacterEncoding(request);
try  {
   if( request.getParameter(ACTION) != null){
     if( request.getParameter(ACTION).equals(ACTION_GENERATETOKEN)){
       username = request.getParameter(TEXTFIELD_USERNAME);
       password = request.getParameter(TEXTFIELD_PASSWORD);
       browser  = request.getParameter(HIDDEN_BROWSER);
       String forcedBrowser = request.getParameter(FORCE_BROWSER);
       if (forcedBrowser != null) {
           browser = forcedBrowser;
       }

       if(username != null && password != null && browser != null){
         int tokentype = applybean.getTokenType(username);
         availablekeylengths = applybean.availableBitLengths(username);
         caid = applybean.getCAId(username);
         if(tokentype == 0){
            request.setAttribute("ErrorMessage","User does not exist : " + username);
            request.getRequestDispatcher("error.jsp").forward(request, response);
            return;
         }
         if(tokentype != SecConst.TOKEN_SOFT_BROWSERGEN)
           includefile = "apply_token.jspf";   
         else{
           if(browser.equals(BROWSER_NETSCAPE))
             includefile = "apply_nav.jspf"; 
           if(browser.equals(BROWSER_EXPLORER))
             includefile = "apply_exp.jspf";
           if(browser.equals(BROWSER_UNKNOWN))
             includefile = "apply_unknown.html"; 
         }
       }
     }
   }

  if(availablekeylengths == null)
   availablekeylengths = defaultkeylengths;
} catch(Exception ex) {
    ex.printStackTrace();
}                                             

  // Include page
  if( includefile.equals("apply_auth.jspf")){ 
%>
   <%@ include file="apply_auth.jspf" %>
<%}  if( includefile.equals("apply_token.jspf")){ %>
   <%@ include file="apply_token.jspf" %> 
<%} if( includefile.equals("apply_unknown.html")){ %>
   <%@ include file="apply_unknown.html" %> 
<%}
  if( includefile.equals("apply_nav.jspf")){ %>
   <%@ include file="apply_nav.jspf" %> 
<%}
  if( includefile.equals("apply_exp.jspf")){ %>
   <%@ include file="apply_exp.jspf" %> 
<%} %>
