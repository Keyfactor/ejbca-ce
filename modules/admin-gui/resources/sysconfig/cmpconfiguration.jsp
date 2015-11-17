<%@page import="org.apache.commons.lang.StringUtils"%>
<%@page import="org.apache.commons.lang.ArrayUtils"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="java.util.*, org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.config.GlobalConfiguration, 
				org.ejbca.core.model.SecConst, org.cesecore.authorization.AuthorizationDeniedException, org.ejbca.ui.web.RequestHelper,
				org.ejbca.ui.web.admin.cainterface.CAInterfaceBean, org.cesecore.certificates.certificateprofile.CertificateProfile, 
				org.cesecore.certificates.certificateprofile.CertificateProfileExistsException, 
				org.cesecore.certificates.certificateprofile.CertificateProfileConstants, org.ejbca.ui.web.CertificateView, 
				org.cesecore.certificates.util.DNFieldExtractor, org.cesecore.certificates.util.DnComponents, 
				org.cesecore.certificates.certificate.certextensions.CertificateExtensionFactory, 
				org.cesecore.certificates.certificateprofile.CertificatePolicy,
                org.cesecore.certificates.ca.CAInfo, org.cesecore.util.ValidityDate, org.ejbca.ui.web.ParameterException, 
                org.cesecore.certificates.util.AlgorithmConstants, org.cesecore.certificates.certificate.CertificateConstants, 
                org.ejbca.core.model.authorization.AccessRulesConstants,org.ejbca.config.CmpConfiguration, org.ejbca.core.model.ra.UsernameGeneratorParams,
                org.cesecore.authorization.control.StandardRules"%>
                
<%@page import="org.cesecore.util.YearMonthDayTime"%>
<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />

<%! // Declarations 


	static final String ACTION                              		= "action";
	static final String ACTION_EDIT_ALIAS                  		= "actioneditcmpalias";
	static final String ACTION_VIEW_ALIAS                  		= "actionviewcmpalias";
	static final String ACTION_EDIT_ALIASES						= "actioneditcmpaliases";

	static final String TEXTFIELD_ALIAS                       	 	= "textfieldalias";
	static final String TEXTFIELD_CMP_RANAMEGENPARAM			  	= "textfieldcmpranamegenerationparameter";
	static final String TEXTFIELD_CMP_RANAMEGENPREFIX		  		= "textfieldcmpranamegenerationprefix";
	static final String TEXTFIELD_CMP_RANAMEGENPOSTFIX		  		= "textfieldcmpranamegenerationpostfix";
	static final String TEXTFIELD_CMP_RAPASSWORDGENPARAM		  	= "textfieldcmprapasswordgenerationparameter";
	static final String TEXTFIELD_HMACPASSWORD						= "textfieldhmacpassword";
	static final String TEXTFIELD_NESTEDMESSAGETRUSTEDCERTPATH		= "textfieldnestedmessagetrustedcertificatespath";
	
	static final String BUTTON_ADD_ALIAS						= "buttonaliasadd";
	static final String BUTTON_DELETE_ALIAS					 	= "buttondeletealias";
	static final String BUTTON_EDIT_ALIAS					 	= "buttoneditalias";
	static final String BUTTON_VIEW_ALIAS						= "buttonviewalias";
	static final String BUTTON_RENAME_ALIAS					 	= "buttonaliasrename";
	static final String BUTTON_CLONE_ALIAS						= "buttonaliasclone";
	static final String BUTTON_SAVE							 	= "buttonsave";
	static final String BUTTON_CANCEL							= "buttoncancel";
	static final String BUTTON_RELOAD							= "buttonreload";
	static final String BUTTON_ADDVENDORCA						= "buttonaddvendorca";
	static final String BUTTON_REMOVEVENDORCA					= "buttonremovevendorca";
	static final String BUTTON_ADD_NAMEGENPARAM_DN				= "buttonaddnamegenparamdn";
	static final String BUTTON_REMOVE_NAMEGENPARAM_DN			= "buttonremovenamegenparamdn";
	
	static final String RADIO_CMPMODE								= "radiocmpmode";
	static final String RADIO_NAMEGENSCHEME						= "radionnamegenscheme";
	static final String RADIO_HMACPASSWORD							= "radiohmacpassword";

	
	static final String CHECKBOX_CMP_VENDORMODE					= "checkcmpvendormode";
	static final String CHECKBOX_CMP_KUR_USEAUTOMATICKEYUPDATE  	= "checkboxcmpuseautomatickeyupdate";
	static final String CHECKBOX_CMP_KUR_USESAMEKEYS				= "checkboxcmpkurusesamekeys";
	static final String CHECKBOX_CMP_ALLOWRAVERIFYPOPO				= "checkboxcmpallowraverifypopo";
	static final String CHECKBOX_CMP_ALLOWCUSTOMSERNO				= "checkboxcmpallowcustomserno";
	static final String CHECKBOX_HMAC								= "checkboxhmac";
	static final String CHECKBOX_EEC								= "checkboxeec";
	static final String CHECKBOX_REGTOKEN							= "checkboxregtoken";
	static final String CHECKBOX_DNPART							= "checkboxdnpart";
	static final String CHECKBOX_OMITVERIFICATIONINECC				= "checkboxomitverificationsinecc";

	
	static final String LIST_CMPDEFAULTCA					   		= "listcmpdefaultca";
	static final String LIST_CMPRACAS						   		= "listcmpracas";
	static final String LIST_CMPRESPONSEPROTECTION		   		    = "listcmpresponseprotection";
	static final String LIST_CMPEEPROFILES					   		= "listcmpeeprofile";
	static final String LIST_CMPCERTPROFILES				   		= "listcmpcertprofiles";
	static final String LIST_ECCCAS								= "listecccas";
	static final String LIST_DNPARTS								= "listdnparts";
	static final String LIST_EXTRACTUSERNAMECOMP					= "listextractusernamecomp";
	static final String LIST_VENDORCA								= "listvendorca";
	static final String LIST_NAMEGENPARAM_DN						= "listnamegenparamdn";
		
	static final String SELECT_ALIASES                       		= "selectaliases";
	static final String HIDDEN_ALIAS                         		= "hiddenalias";
	static final String CHECKBOX_VALUE								= "true"; 
	 
	 
	List<String> dnfields = Arrays.asList("CN", "UID", "OU", "O", "L", "ST", "DC", "C", "emailAddress", "serialNumber", "givenName", "initials", "surname", "title", 
			   		"unstructuredAddress", "unstructuredName", "postalCode", "businessCategory", "dnQualifier", "postalAddress", 
			   		"telephoneNumber", "pseudonym", "streetAddress", "name", "CIF", "NIF");


 

  // Declare Language file.
%>
<%
    // Initialize environment
  String alias = null;
  String includefile = "cmpaliasespage.jspf"; 

  boolean  triedtoaddexistingalias    = false;
  boolean  aliasDeletionFailed = false;
  boolean  triedrenametoexistingalias = false;
  boolean  triedclonetoexistingalias = false;
  
  boolean ramode = false;
  boolean pbe = false;
  boolean authorizedToEdit =  ejbcawebbean.isAuthorizedNoLogSilent(StandardRules.SYSTEMCONFIGURATION_EDIT.resource());

  GlobalConfiguration gc = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_VIEW.resource()); 
                                    cabean.initialize(ejbcawebbean); 
  
  ejbcawebbean.clearCMPCache();
  CmpConfiguration cmpconfig = ejbcawebbean.getCmpConfiguration();
  CmpConfiguration cmpConfigClone = null;

  String THIS_FILENAME            = gc.getAdminWebPath() +  "/sysconfig/cmpconfiguration.jsp";
%>
 
<head>
  <title><c:out value="<%= gc.getEjbcaTitle() %>" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
  <script type="text/javascript" src="<%= gc.getAdminWebPath() %>ejbcajslib.js"></script>
</head>

<body>

<%
	// Determine action 
 	RequestHelper.setDefaultCharacterEncoding(request);

  	if( request.getParameter(ACTION) != null){
    		if( request.getParameter(ACTION).equals(ACTION_EDIT_ALIASES)){			
    			ejbcawebbean.clearCmpConfigClone();    			
    				if( request.getParameter(BUTTON_VIEW_ALIAS) != null){
      					// Display  cmpaliaspage.jsp
     					alias = request.getParameter(SELECT_ALIASES);
     					if(alias != null){
       							if(!alias.trim().equals("")){
    	   								if(!cmpconfig.aliasExists(alias)) {
    	   										cmpconfig.addAlias(alias);
    	   								}
    	   							   	cmpConfigClone = ejbcawebbean.getCmpConfigForEdit(alias);
           								includefile="cmpaliaspage.jspf"; 
       							}
     					}
     					if(alias == null){   
      							includefile="cmpaliasespage.jspf";     
     					}
  				}
    				
    				if( request.getParameter(BUTTON_VIEW_ALIAS) != null){
    				    authorizedToEdit = false;
    				}
      				if( request.getParameter(BUTTON_EDIT_ALIAS) != null){
      				  authorizedToEdit = ejbcawebbean.isAuthorizedNoLogSilent(StandardRules.SYSTEMCONFIGURATION_EDIT.resource());
          					// Display  cmpaliaspage.jsp
         					alias = request.getParameter(SELECT_ALIASES);
         					if(alias != null){
           							if(!alias.trim().equals("")){
        	   								if(!cmpconfig.aliasExists(alias)) {
        	   										cmpconfig.addAlias(alias);
        	   								}
        	   							   	cmpConfigClone = ejbcawebbean.getCmpConfigForEdit(alias);
               								includefile="cmpaliaspage.jspf"; 
           							}
         					}
         					if(alias == null){   
          							includefile="cmpaliasespage.jspf";     
         					}
      				}
      			
      				if( request.getParameter(BUTTON_DELETE_ALIAS) != null) {
          					// Delete profile and display profilespage. 
          					alias = request.getParameter(SELECT_ALIASES);
          					if(alias != null && (!alias.trim().equals("")) ){
              						cmpconfig.removeAlias(alias);
                					ejbcawebbean.saveCMPConfiguration(cmpconfig);
                					if(cmpconfig.aliasExists(alias)) {
                						aliasDeletionFailed = true;
                					}
          					}
          					includefile="cmpaliasespage.jspf";             
      				}

      				if( request.getParameter(BUTTON_RENAME_ALIAS) != null){ 
      						// Rename selected profile and display profilespage.
      					    String newalias = request.getParameter(TEXTFIELD_ALIAS);
      					    String oldalias = request.getParameter(SELECT_ALIASES);
      					    if(oldalias != null && newalias != null && !newalias.trim().equals("") && !oldalias.trim().equals("") ){
      					    		if(cmpconfig.aliasExists(newalias)) {
      					    				triedrenametoexistingalias = true;
      					    		} else {
      					    				cmpconfig.renameAlias(oldalias, newalias);
			      					    	ejbcawebbean.saveCMPConfiguration(cmpconfig);
      					    		}
      					    }
      					    includefile="cmpaliasespage.jspf"; 
      				}
      				
      				if( request.getParameter(BUTTON_ADD_ALIAS) != null){
      						alias = request.getParameter(TEXTFIELD_ALIAS);
      					    if(alias != null && (!alias.trim().equals("")) ) {
      					    		if(cmpconfig.aliasExists(alias)) {
      					    			triedtoaddexistingalias = true;
      					    		} else {
      					    			cmpconfig.addAlias(alias);
      					    			ejbcawebbean.saveCMPConfiguration(cmpconfig);
      					    		}
      					    }
      					    includefile="cmpaliasespage.jspf"; 
      				}
      				
      				if( request.getParameter(BUTTON_CLONE_ALIAS) != null){
      						// clone profile and display profilespage.
      					    String newalias = request.getParameter(TEXTFIELD_ALIAS);
      					    String oldalias = request.getParameter(SELECT_ALIASES);
      					    if(oldalias != null && newalias != null && !newalias.trim().equals("") && !oldalias.trim().equals("")){
      					    			if(cmpconfig.aliasExists(newalias)) {
      					    					triedclonetoexistingalias = true;
      					    			} else {
      					        				cmpconfig.cloneAlias(oldalias, newalias);
					      					    ejbcawebbean.saveCMPConfiguration(cmpconfig);
      					    			}
      					    }
      					    includefile="cmpaliasespage.jspf"; 
      				}

    		}      				
      				
    		
    		if(request.getParameter(ACTION).equals(ACTION_EDIT_ALIAS)) {
    				alias = request.getParameter(HIDDEN_ALIAS);
    		       	if(alias != null) {
    		       		if(!alias.trim().equals("")) {
    		       	    	
    		       		   	cmpConfigClone = ejbcawebbean.getCmpConfigForEdit(alias);
    		       			
    		       			//Save changes
    		       						
    		       			//defaultCA
    		       			String value = request.getParameter(LIST_CMPDEFAULTCA);
    		       			if((value==null) || (value.length() == 0)) {
    		       					cmpConfigClone.setCMPDefaultCA(alias, "");
    		       			} else {
    		                		String cadn = cabean.getCAInfo(value).getCAInfo().getSubjectDN();
    		                		cmpConfigClone.setCMPDefaultCA(alias, cadn);
    		       			}
    		       						
    		    			//operational mode
    		    			String mode = request.getParameter(RADIO_CMPMODE);
    		    			if(mode!=null) {
    		    					if(mode.equals("client")) {
    		    							ramode = false;
    		    					} else if(mode.equals("ra")) {
    		    							ramode = true;
    		    					}
    		           		}
    		           		cmpConfigClone.setRAMode(alias, ramode);
    		           					
    		           		//response protection
    		    			value = request.getParameter(LIST_CMPRESPONSEPROTECTION);
    						cmpConfigClone.setResponseProtection(alias, value);
    						if(value != null && value.equals("pbe")) {
    								pbe = true;
    						} else {
    								pbe = false;
    						}
    									
    						// authentication module and parameters
    						// TODO fix it better
    			            ArrayList<String> authmodule = new ArrayList<String>();
    			            ArrayList<String> authparam = new ArrayList<String>();
    			            if(pbe && ramode) {
    			            		value = CmpConfiguration.AUTHMODULE_HMAC;
    			            } else {
    			            		value = request.getParameter(CHECKBOX_HMAC);
    			            }
    			            if(value !=null) {
    			            		authmodule.add(value);
    			            		if(ramode) {
    			            				value = request.getParameter(RADIO_HMACPASSWORD);
    			            				if((value != null) && value.equals("hmacsecret")) {
    												String secret = request.getParameter(TEXTFIELD_HMACPASSWORD);
    			            						if(secret != null) {
    			            								authparam.add(secret);
    			            						}
    			            				} else {
    			            						authparam.add("-");
    			            				}
    			            		} else {
    			            			authparam.add("-");
    			            		}
    			            }
    			            if(!pbe) {
    			            		value = request.getParameter(CHECKBOX_EEC);
    			            		if(value != null) {
    			            				authmodule.add(value);
    			            				authparam.add(ramode ? request.getParameter(LIST_ECCCAS) : "-");
    			            		}
    			            		if(!ramode) {
    			            				value = request.getParameter(CHECKBOX_REGTOKEN);
    			            				if(value != null) {
    			            						authmodule.add(value);
    			            						authparam.add("-");
    			            				}
    			            				value = request.getParameter(CHECKBOX_DNPART);
    			            				if(value != null) {
    			            						authmodule.add(value);
    			            						authparam.add(request.getParameter(LIST_DNPARTS));
    			            				}
    			            		}
    			            }
	    			        cmpConfigClone.setAuthenticationProperties(alias, authmodule, authparam);
    		
    			            			
	    			        
	    			        
    			            if(!ramode) { // client mode
    			            		// extract username component
    			            		value = request.getParameter(LIST_EXTRACTUSERNAMECOMP);
    			            		if(value != null){
    			            				cmpConfigClone.setExtractUsernameComponent(alias, value);
    			            		}
    			            		
    			            		// vendor mode
    			            		value = request.getParameter(CHECKBOX_CMP_VENDORMODE);
    			            		boolean vendormode = false;
    			            		if(value != null){
    			            				vendormode = true;
    			            		}
    			            		cmpConfigClone.setVendorMode(alias, vendormode);
    			            } else { // ra mode
    			            		// allow verify popo
    			            		value = request.getParameter(CHECKBOX_CMP_ALLOWRAVERIFYPOPO);
    			            		cmpConfigClone.setAllowRAVerifyPOPO(alias, (value != null));
    			            		
    			            		// ra name generation scheme	           					
    			           			String namegenscheme = request.getParameter(RADIO_NAMEGENSCHEME);
    			           			if(namegenscheme != null) {
    			           					cmpConfigClone.setRANameGenScheme(alias, namegenscheme);
    										if(namegenscheme.equals(UsernameGeneratorParams.FIXED)) {
    												value = request.getParameter(TEXTFIELD_CMP_RANAMEGENPARAM);
    												if((value != null) && (value.length() > 0)) {
    														cmpConfigClone.setRANameGenParams(alias, value);
    												}
											} else if(namegenscheme.equals(UsernameGeneratorParams.DN)) {
    												// do nothing here. handle it with the buttons
											} else { 
													cmpConfigClone.setRANameGenParams(alias, "");
											}
    			           			}
    			           			
    			           			// ra name generation prefix
    			            		value = request.getParameter(TEXTFIELD_CMP_RANAMEGENPREFIX);
    			            		cmpConfigClone.setRANameGenPrefix(alias, value == null ? "" : value);
    			            		
    			            		// ra name generation postfix
    			            		value = request.getParameter(TEXTFIELD_CMP_RANAMEGENPOSTFIX);
    			            		cmpConfigClone.setRANameGenPostfix(alias, value==null ? "" : value);
    			            		
    			            		// ra password generation parameters
    			            		value = request.getParameter(TEXTFIELD_CMP_RAPASSWORDGENPARAM);
    			            		cmpConfigClone.setRAPwdGenParams(alias, value==null ? "random" : value);
    			            		
    			            		// allow custom serno
    			            		value = request.getParameter(CHECKBOX_CMP_ALLOWCUSTOMSERNO);
    			            		cmpConfigClone.setAllowRACustomSerno(alias, (value != null));
    			            		
    			            		// ra endentity profile
    			            		value = request.getParameter(LIST_CMPEEPROFILES);
    			            		if(value != null){
    			            				cmpConfigClone.setRAEEProfile(alias, value);
    			            		}
    			            		
    			            		// ra certprofile
    			            		value = request.getParameter(LIST_CMPCERTPROFILES);
    			            		if(value != null) {
    			            				cmpConfigClone.setRACertProfile(alias, value);
    			            		}
    			            		
    			            		// ra CA  
    					 			value = request.getParameter(LIST_CMPRACAS);
    			     				if ( (value != null) && (value.trim().length() > 0) ) {
    			     					cmpConfigClone.setRACAName(alias, value);
    			     				}
    			     				
    			            } // if(ramode)
    			            
    			            	
    			            // KUR automatic keyupdate
    			            value = request.getParameter(CHECKBOX_CMP_KUR_USEAUTOMATICKEYUPDATE);
    			            cmpConfigClone.setKurAllowAutomaticUpdate(alias, (value != null));
    			            
    			            // KUR update with same key
    			            value = request.getParameter(CHECKBOX_CMP_KUR_USESAMEKEYS);
    			            cmpConfigClone.setKurAllowSameKey(alias, (value != null));
    			            
    			            
    			            
    			            // Nested message content
    			            value = request.getParameter(TEXTFIELD_NESTEDMESSAGETRUSTEDCERTPATH);
    			            cmpConfigClone.setRACertPath(alias, value == null ? "" : value);
    			            
    			            // Nested message content - omit some verifications in EndEntityCertificate authentication module
    			            value = request.getParameter(CHECKBOX_OMITVERIFICATIONINECC);
    			            cmpConfigClone.setOmitVerificationsInECC(alias, (value != null));
    			            
    		       		
    			            
    			   			// ------------------- BUTTONS -------------------------
    			            
    			        	if(request.getParameter(BUTTON_ADDVENDORCA) != null) {
    		      				  authorizedToEdit = ejbcawebbean.isAuthorizedNoLogSilent(StandardRules.SYSTEMCONFIGURATION_EDIT.resource());
    			        			if(request.getParameter(CHECKBOX_CMP_VENDORMODE) != null) {
    			        					value = request.getParameter(LIST_VENDORCA);
    			           					String vendorcas = cmpConfigClone.getVendorCA(alias);
    			           					if(!StringUtils.contains(vendorcas, value)) {
    			           							if(StringUtils.isEmpty(vendorcas)) {
    			           								vendorcas = value;
    			           							} else {
    			           								vendorcas += ";" + value;
    			           							}
    			           							cmpConfigClone.setVendorCA(alias, vendorcas);
    			           					}
    			        			}
    			        	}
    			            
    			        	if(request.getParameter(BUTTON_REMOVEVENDORCA) != null) {
    		      				  authorizedToEdit = ejbcawebbean.isAuthorizedNoLogSilent(StandardRules.SYSTEMCONFIGURATION_EDIT.resource());
    			           			value = request.getParameter(LIST_VENDORCA);
    			           			String vendorcas = cmpConfigClone.getVendorCA(alias);
    			           			if(StringUtils.contains(vendorcas, value)) {
    			           					String[] cas = vendorcas.split(";");
    			           					if(cas.length == 1) {
    			           							vendorcas = "";
    			           					} else {
    			           							if(StringUtils.equals(cas[0], value)) {
	           											vendorcas = StringUtils.remove(vendorcas, value + ";");
	           										} else {
	           											vendorcas = StringUtils.remove(vendorcas, ";" + value);
	           										}
    			           					}
    		           						cmpConfigClone.setVendorCA(alias, vendorcas);
    			           			}
	    			        }
    			            
    				        if(request.getParameter(BUTTON_ADD_NAMEGENPARAM_DN)!= null) {
    				           		if(request.getParameter(RADIO_NAMEGENSCHEME).equals(UsernameGeneratorParams.DN)) {
    				           				value = request.getParameter(LIST_NAMEGENPARAM_DN);
    				           				String namegenparam = cmpConfigClone.getRANameGenParams(alias);
    			    	       				String[] params = namegenparam.split(";");
    			        	   				if((params.length > 0) && ( dnfields.contains(params[0]) )) { // the dnfields check is to 
    			        	   																			// ensure that the parameter 
    			        	   																			// from the start is a list of DN fields 
    			        	   																			// and not parameter left from another previously 
    			        	   																			// chosen namegenscheme
    			        	   						if(!ArrayUtils.contains(params, value)) {
    			        	   							namegenparam += ";" + value;
    			        	   						}
    			           					} else {
    			           							namegenparam = value;
    			           					}
    										cmpConfigClone.setRANameGenParams(alias, namegenparam);
    			           			}
	    			        }
    			            			
    			        	if(request.getParameter(BUTTON_REMOVE_NAMEGENPARAM_DN) != null) {
    			           			value = request.getParameter(LIST_NAMEGENPARAM_DN);
    			           			String namegenparam = cmpConfigClone.getRANameGenParams(alias);
    			           			if(StringUtils.contains(namegenparam, value)) {
			           						String[] params = namegenparam.split(";");
			           						if(params.length == 1) {
			           								namegenparam = "";
			           						} else {
			           								if(StringUtils.equals(params[0], value)) {
           													namegenparam = StringUtils.remove(namegenparam, value + ";");
           											} else {
           													namegenparam = StringUtils.remove(namegenparam, ";" + value);
           											}
			           						}
		           							cmpConfigClone.setRANameGenParams(alias, namegenparam);
    			           			}
	    			        }
    			        	
    				        includefile="cmpaliaspage.jspf";
    			        
    				        if(request.getParameter(BUTTON_SAVE) != null) {
    				                if (authmodule.size() == 0) {
                                        throw new ParameterException(ejbcawebbean.getText("CMPNOAUTHMODULE"));
                                    }
    				                
    				                if (cmpConfigClone.getRAEEProfile(alias).equals("-1")) {
    				                	throw new ParameterException(ejbcawebbean.getText("CMPERROREEPNOTFOUND"));
    				                }
    				        		ejbcawebbean.updateCmpConfigFromClone(alias);
    			        	   		includefile="cmpaliasespage.jspf";
    			        	}
    				        
    		       		} // if(!alias.trim().equals(""))
    		       			
               			if(request.getParameter(BUTTON_CANCEL) != null){
              				// Don't save changes.
             				includefile="cmpaliasespage.jspf";
           				}
    		       		
    		       	} // if((alias != null) )
    	    } // if(request.getParameter(ACTION).equals(ACTION_EDIT_ALIAS))

  		} // if( request.getParameter(ACTION) != null)

 // Include page
  if( includefile.equals("cmpaliaspage.jspf")){
%>
   <%@ include file="cmpaliaspage.jspf" %>
<%}
  if( includefile.equals("cmpaliasespage.jspf")){ %>
   <%@ include file="cmpaliasespage.jspf" %> 
<%}

   // Include Footer 
   String footurl =   gc.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />

</body>
</html>
