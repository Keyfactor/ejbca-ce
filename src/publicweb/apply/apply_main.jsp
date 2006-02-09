<%@ page pageEncoding="ISO-8859-1"%>
<%@ page contentType="text/html; charset=@page.encoding@" %>
<%@ page language="Java" import="javax.naming.*,javax.rmi.*,java.util.*,java.security.cert.*,
                                 org.ejbca.core.model.log.Admin, org.ejbca.core.model.ApplyBean, org.ejbca.core.model.SecConst"%>

<HTML>
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

  String THIS_FILENAME            =  "/@ejbca@/publicweb/apply/apply_main.jsp";
  int[] defaultkeylengths        = {512,1024,2048};
  String includefile = "apply_auth.jsp";
  String username = "";
  String password = "";
  String browser  = null;
  int[] availablekeylengths = null;
  int caid =0;

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
           includefile = "apply_token.jsp";   
         else{
           if(browser.equals(BROWSER_NETSCAPE))
             includefile = "apply_nav.jsp"; 
           if(browser.equals(BROWSER_EXPLORER))
             includefile = "apply_exp.jsp";
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
%>


<%
 // Include page
  if( includefile.equals("apply_auth.jsp")){ 
%>
   <%@ include file="apply_auth.jsp" %>
<%}  if( includefile.equals("apply_token.jsp")){ %>
   <%@ include file="apply_token.jsp" %> 
<%} if( includefile.equals("apply_unknown.html")){ %>
   <%@ include file="apply_unknown.html" %> 
<%}
  if( includefile.equals("apply_nav.jsp")){ %>
   <%@ include file="apply_nav.jsp" %> 
<%}
  if( includefile.equals("apply_exp.jsp")){ %>
   <%@ include file="apply_exp.jsp" %> 
<%} %>
