package se.anatom.ejbca.webdist.hardtokeninterface;

import java.io.*;
import java.util.Iterator;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.fileupload.*;

import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.hardtoken.HardTokenProfileExistsException;
import se.anatom.ejbca.hardtoken.hardtokenprofiles.EnhancedEIDProfile;
import se.anatom.ejbca.hardtoken.hardtokenprofiles.HardTokenProfile;
import se.anatom.ejbca.hardtoken.hardtokenprofiles.HardTokenProfileWithPINEnvelope;
import se.anatom.ejbca.hardtoken.hardtokenprofiles.HardTokenProfileWithVisualLayout;
import se.anatom.ejbca.hardtoken.hardtokenprofiles.IPINEnvelopeSettings;
import se.anatom.ejbca.hardtoken.hardtokenprofiles.IVisualLayoutSettings;
import se.anatom.ejbca.hardtoken.hardtokenprofiles.SwedishEIDProfile;
import se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean;

/**
 * Contains help methods used to parse a hard token profile jsp page requests.
 *
 * @author  Philip Vendil
 * @version $Id: EditHardTokenProfileJSPHelper.java,v 1.1 2003-12-05 14:50:27 herrvendil Exp $
 */
public class EditHardTokenProfileJSPHelper {
	
	public static final String ACTION                              = "action";
	public static final String ACTION_EDIT_HARDTOKENPROFILES       = "edithardtokenprofiles";
	public static final String ACTION_EDIT_HARDTOKENPROFILE        = "edithardtokenprofile";
    public static final String ACTION_UPLOADENVELOPETEMP           = "uploadenvelopetemp";
	public static final String ACTION_UPLOADVISUALTEMP             = "uploadvisualtemp";

	public static final String ACTION_CHANGE_PROFILETYPE           = "changeprofiletype";


	public static final String CHECKBOX_VALUE           = HardTokenProfile.TRUE;

//	  Used in profiles.jsp
	public static final String BUTTON_EDIT_HARDTOKENPROFILES      = "buttonedithardtokenprofile"; 
	public static final String BUTTON_DELETE_HARDTOKENPROFILES    = "buttondeletehardtokenprofile";
	public static final String BUTTON_ADD_HARDTOKENPROFILES       = "buttonaddhardtokenprofile"; 
	public static final String BUTTON_RENAME_HARDTOKENPROFILES    = "buttonrenamehardtokenprofile";
	public static final String BUTTON_CLONE_HARDTOKENPROFILES     = "buttonclonehardtokenprofile";

	public static final String SELECT_HARDTOKENPROFILES           = "selecthardtokenprofile";
	public static final String TEXTFIELD_HARDTOKENPROFILESNAME    = "textfieldhardtokenprofilename";
	public static final String HIDDEN_HARDTOKENPROFILENAME        = "hiddenhardtokenprofilename";
 
//	 Buttons used in profile.jsp
	public static final String BUTTON_SAVE              = "buttonsave";
	public static final String BUTTON_CANCEL            = "buttoncancel";
	public static final String BUTTON_UPLOADENVELOPETEMP= "buttonuploadenvelopetemplate"; 
	public static final String BUTTON_UPLOADVISUALTEMP  = "buttonuploadvisualtemplate";
	public static final String BUTTON_UPLOADFILE        = "buttonuploadfile";
 
	public static final String TYPE_SWEDISHEID          = "typeswedisheid";
	public static final String TYPE_ENCHANCEDEID        = "typeenchancedeid";

	public static final String TEXTFIELD_VISUALVALIDITY = "textfieldvisualvalidity";
	public static final String TEXTFIELD_SNPREFIX       = "textfieldsnprefix";

	public static final String CHECKBOX_EREASBLE        = "checkboxereasable";
	public static final String CHECKBOX_KEYRECOVERABLE  = "checkboxkeyrecoverable";
	public static final String CHECKBOX_USEIDENTICALPINS= "useidenticalpins";

	public static final String HIDDEN_HARDTOKENTYPE     = "hiddenhardtokentype";

	public static final String SELECT_HARDTOKENTYPE      = "selecthardtokentype";
	public static final String SELECT_CERTIFICATEPROFILE = "selectcertificateprofile";
	public static final String SELECT_PINTYPE            = "selectpintype";
	public static final String SELECT_MINKEYLENGTH       = "selectminkeylength";
	public static final String SELECT_ENVELOPETYPE       = "selectenvelopetype";
	public static final String SELECT_NUMOFENVELOPECOPIES= "selectenvelopecopies";
	public static final String SELECT_VISUALLAYOUTTYPE   = "selectvisuallayouttype";
	public static final String SELECT_NUMOFTOKENCOPIES   = "selectnumoftokencopies";
	
	public static final String FILE_TEMPLATE             = "filetemplate";
	
	public static final int UPLOADMODE_ENVELOPE = 0; 
	public static final int UPLOADMODE_VISUAL   = 1;

    /** Creates new LogInterfaceBean */
    public EditHardTokenProfileJSPHelper(){     	    	
    }
    // Public methods.
    /**
     * Method that initialized the bean.
     *
     * @param request is a reference to the http request.
     */
    public void initialize(HttpServletRequest request, EjbcaWebBean ejbcawebbean,
                           HardTokenInterfaceBean hardtokenbean) throws  Exception{

      if(!initialized){
        this.ejbcawebbean = ejbcawebbean;
        this.hardtokenbean = hardtokenbean;
        initialized = true;
		issuperadministrator = false;
		try{
		  issuperadministrator = ejbcawebbean.isAuthorizedNoLog("/super_administrator");
		}catch(AuthorizationDeniedException ade){}
      }
    }
    
    public String parseRequest(HttpServletRequest request) throws AuthorizationDeniedException{
      String includefile = "hardtokenprofilespage.jsp"; 
	  String profile = null;
	  HardTokenProfileDataHandler handler  = hardtokenbean.getHardTokenProfileDataHandler();	
      String action = null;

	  InputStream file = null;
	  
	  boolean errorrecievingfile = false;
      boolean buttoncancel = false;
      boolean buttonupload = false;
      String filename = null;

	  if(FileUpload.isMultipartContent(request)){
	  	try{     	  	
		  errorrecievingfile = true;
		  DiskFileUpload upload = new DiskFileUpload();
		  upload.setSizeMax(500000);                   
		  upload.setSizeThreshold(499999);
		  List /* FileItem */ items = upload.parseRequest(request);     

		  Iterator iter = items.iterator();
		  while (iter.hasNext()) {     
		  FileItem item = (FileItem) iter.next();

		    if (item.isFormField()) {         
			  if(item.getFieldName().equals(ACTION))
			    action = item.getString(); 
			  if(item.getFieldName().equals(HIDDEN_HARDTOKENPROFILENAME))
			    profilename = item.getString();
			  if(item.getFieldName().equals(BUTTON_CANCEL))
			    buttoncancel = true;
			  if(item.getFieldName().equals(BUTTON_UPLOADFILE))
			    buttonupload = true;
		    }else{         
			  file = item.getInputStream();
			  filename = item.getName(); 
			  errorrecievingfile = false;                          
		    }
		  }
	  	}catch(IOException e){
	  	  fileuploadfailed = true;
		  includefile="hardtokenprofilepage.jsp";	  
	  	}catch(FileUploadException e){
		  fileuploadfailed = true;	  
		  includefile="hardtokenprofilepage.jsp";
	    }
	  }else{
		action = request.getParameter(ACTION);
	  }



	  if( action != null){
		if( action.equals(ACTION_EDIT_HARDTOKENPROFILES)){						
		  if( request.getParameter(BUTTON_EDIT_HARDTOKENPROFILES) != null){
			  // Display  profilepage.jsp
			 profile = request.getParameter(SELECT_HARDTOKENPROFILES);
			 if(profile != null){
			   if(!profile.trim().equals("")){
				   includefile="hardtokenprofilepage.jsp";
				   this.profilename = profile;
				   this.profiledata = handler.getHardTokenProfile(profilename);  
			   } 
			   else{ 
				profile= null;
			  } 
			}
			if(profile == null){   
			  includefile="hardtokenprofilespage.jsp";     
			}
		  }
		  if( request.getParameter(BUTTON_DELETE_HARDTOKENPROFILES) != null) {
			  // Delete profile and display profilespage. 
			  profile = request.getParameter(SELECT_HARDTOKENPROFILES);
			  if(profile != null){
				if(!profile.trim().equals("")){      					        
					hardtokenprofiledeletefailed = handler.removeHardTokenProfile(profile);          
				}
			  }
			  includefile="hardtokenprofilespage.jsp";             
		  }
		  if( request.getParameter(BUTTON_RENAME_HARDTOKENPROFILES) != null){ 
			 // Rename selected profile and display profilespage.
		   String newhardtokenprofilename = request.getParameter(TEXTFIELD_HARDTOKENPROFILESNAME);
		   String oldhardtokenprofilename = request.getParameter(SELECT_HARDTOKENPROFILES);
		   if(oldhardtokenprofilename != null && newhardtokenprofilename != null){
			 if(!newhardtokenprofilename.trim().equals("") && !oldhardtokenprofilename.trim().equals("")){
			   try{
				 handler.renameHardTokenProfile(oldhardtokenprofilename.trim(),newhardtokenprofilename.trim());
			   }catch( HardTokenProfileExistsException e){
				  hardtokenprofileexists=true;
			   }
			 }
		   }      
		   includefile="hardtokenprofilespage.jsp"; 
		  }
		  if( request.getParameter(BUTTON_ADD_HARDTOKENPROFILES) != null){
			 // Add profile and display profilespage.
			 profile = request.getParameter(TEXTFIELD_HARDTOKENPROFILESNAME);
			 if(profile != null){
			   if(!profile.trim().equals("")){          
				 try{
				   handler.addHardTokenProfile(profile.trim(), new SwedishEIDProfile());
				 }catch( HardTokenProfileExistsException e){
				   hardtokenprofileexists=true;
				 }             
			   }      
			 }
			 includefile="hardtokenprofilespage.jsp"; 
		  }
		  if( request.getParameter(BUTTON_CLONE_HARDTOKENPROFILES) != null){
			 // clone profile and display profilespage.
		   String newhardtokenprofilename = request.getParameter(TEXTFIELD_HARDTOKENPROFILESNAME);
		   String oldhardtokenprofilename = request.getParameter(SELECT_HARDTOKENPROFILES);
		   if(oldhardtokenprofilename != null && newhardtokenprofilename != null){
			 if(!newhardtokenprofilename.trim().equals("") && !oldhardtokenprofilename.trim().equals("")){            
			   try{ 
				 handler.cloneHardTokenProfile(oldhardtokenprofilename.trim(),newhardtokenprofilename.trim());
			   }catch(HardTokenProfileExistsException e){
				   hardtokenprofileexists=true;
			   }
			 }
		   }      
			  includefile="hardtokenprofilespage.jsp"; 
		  }
		}
		if( action.equals(ACTION_EDIT_HARDTOKENPROFILE)){
			 // Display edit access rules page.
		   profile = request.getParameter(HIDDEN_HARDTOKENPROFILENAME);
		   if(profile != null){
			 if(!profile.trim().equals("")){
			   if(request.getParameter(BUTTON_SAVE) != null ||
			      request.getParameter(BUTTON_UPLOADENVELOPETEMP) != null ||
				  request.getParameter(BUTTON_UPLOADVISUALTEMP) != null){
		
             
				 if(profiledata == null){               
				   String tokentype = request.getParameter(HIDDEN_HARDTOKENTYPE);
				   if(tokentype.equals(TYPE_SWEDISHEID))
					 profiledata = new SwedishEIDProfile();
				   if(tokentype.equals(TYPE_ENCHANCEDEID))
					 profiledata = new EnhancedEIDProfile();
				 }
				 // Save changes.
                    
				 // General settings   
				 String value = request.getParameter(TEXTFIELD_SNPREFIX);
				 if(value != null){                              
				   value = value.trim();
				   profiledata.setHardTokenSNPrefix(value); 
				 }
				 value = request.getParameter(CHECKBOX_EREASBLE);
				 if(value != null){                              
				   profiledata.setEreasableToken(value.equals(CHECKBOX_VALUE));
				 }else
				   profiledata.setEreasableToken(false);

				 value = request.getParameter(SELECT_NUMOFTOKENCOPIES);
				 if(value != null){                              				   
				   profiledata.setNumberOfCopies(Integer.parseInt(value)); 
				 }

				value = request.getParameter(CHECKBOX_USEIDENTICALPINS);
				if(value != null){                              
				  profiledata.setGenerateIdenticalPINForCopies(value.equals(CHECKBOX_VALUE));
				}else
				  profiledata.setGenerateIdenticalPINForCopies(false);
				 				 
				 if(profiledata instanceof HardTokenProfileWithPINEnvelope){
				   value = request.getParameter(SELECT_ENVELOPETYPE);
				   if(value != null)                                               
					 ((HardTokenProfileWithPINEnvelope) profiledata).setPINEnvelopeType(Integer.parseInt(value));            
				   value = request.getParameter(SELECT_NUMOFENVELOPECOPIES);
				   if(value != null)                                               
					((HardTokenProfileWithPINEnvelope) profiledata).setNumberOfPINEnvelopeCopies(Integer.parseInt(value));
					value = request.getParameter(TEXTFIELD_VISUALVALIDITY);
					if(value != null)                                        
					  ((HardTokenProfileWithPINEnvelope) profiledata).setVisualValidity(Integer.parseInt(value));       													
            				   
				 }
  
				 if(profiledata instanceof HardTokenProfileWithVisualLayout){
				   HardTokenProfileWithVisualLayout visprof = (HardTokenProfileWithVisualLayout) profiledata;
				   value = request.getParameter(SELECT_VISUALLAYOUTTYPE);
				   if(value != null)                                        
				     visprof.setVisualLayoutType(Integer.parseInt(value));       
				 }

				 if(profiledata instanceof SwedishEIDProfile){
                   SwedishEIDProfile sweprof = (SwedishEIDProfile) profiledata;
                   
				   value = request.getParameter(SELECT_MINKEYLENGTH);
				   if(value!= null){
					 int val = Integer.parseInt(value);				   
					 sweprof.setMinimumKeyLength(SwedishEIDProfile.CERTUSAGE_SIGN, val);
					 sweprof.setMinimumKeyLength(SwedishEIDProfile.CERTUSAGE_AUTHENC, val);
					 sweprof.setKeyType(SwedishEIDProfile.CERTUSAGE_SIGN, SwedishEIDProfile.KEYTYPE_RSA);
					 sweprof.setKeyType(SwedishEIDProfile.CERTUSAGE_AUTHENC, SwedishEIDProfile.KEYTYPE_RSA);
				   }
				   	  
                   value = request.getParameter(SELECT_CERTIFICATEPROFILE + "0");
                   if(value!= null)
                     sweprof.setCertificateProfileId(SwedishEIDProfile.CERTUSAGE_SIGN, Integer.parseInt(value));
				   value = request.getParameter(SELECT_PINTYPE + "0");
				   if(value!= null)
					 sweprof.setPINType(SwedishEIDProfile.CERTUSAGE_SIGN, Integer.parseInt(value));
                    
				   value = request.getParameter(SELECT_CERTIFICATEPROFILE + "1");
				   if(value!= null)
					 sweprof.setCertificateProfileId(SwedishEIDProfile.CERTUSAGE_AUTHENC, Integer.parseInt(value));
				   value = request.getParameter(SELECT_PINTYPE + "1");
				   if(value!= null)
				     sweprof.setPINType(SwedishEIDProfile.CERTUSAGE_AUTHENC, Integer.parseInt(value));
                  
                     
				 }

				 if(profiledata instanceof EnhancedEIDProfile){
				   EnhancedEIDProfile enhprof = (EnhancedEIDProfile) profiledata;

				   value = request.getParameter(SELECT_MINKEYLENGTH);
				   if(value!= null){				   
				   	 int val = Integer.parseInt(value);
					 enhprof.setMinimumKeyLength(EnhancedEIDProfile.CERTUSAGE_SIGN, val);
					 enhprof.setMinimumKeyLength(EnhancedEIDProfile.CERTUSAGE_AUTH, val);
					 enhprof.setMinimumKeyLength(EnhancedEIDProfile.CERTUSAGE_ENC, val);
					 enhprof.setKeyType(EnhancedEIDProfile.CERTUSAGE_SIGN, SwedishEIDProfile.KEYTYPE_RSA);
					 enhprof.setKeyType(EnhancedEIDProfile.CERTUSAGE_ENC, SwedishEIDProfile.KEYTYPE_RSA);
					 enhprof.setKeyType(EnhancedEIDProfile.CERTUSAGE_ENC, SwedishEIDProfile.KEYTYPE_RSA);
				   }	  
				   
				   value = request.getParameter(SELECT_CERTIFICATEPROFILE + "0");
				   if(value!= null)
					 enhprof.setCertificateProfileId(EnhancedEIDProfile.CERTUSAGE_SIGN, Integer.parseInt(value));
				   value = request.getParameter(SELECT_PINTYPE + "0");
				   if(value!= null)
					 enhprof.setPINType(EnhancedEIDProfile.CERTUSAGE_SIGN, Integer.parseInt(value));
                   enhprof.setIsKeyRecoverable(EnhancedEIDProfile.CERTUSAGE_SIGN, false); 
                    
				   value = request.getParameter(SELECT_CERTIFICATEPROFILE + "1");
				   if(value!= null)
					 enhprof.setCertificateProfileId(EnhancedEIDProfile.CERTUSAGE_AUTH, Integer.parseInt(value));
				   value = request.getParameter(SELECT_PINTYPE + "1");
				   if(value!= null)
					 enhprof.setPINType(EnhancedEIDProfile.CERTUSAGE_AUTH, Integer.parseInt(value));
				   enhprof.setIsKeyRecoverable(EnhancedEIDProfile.CERTUSAGE_AUTH, false);

				   value = request.getParameter(SELECT_CERTIFICATEPROFILE + "2");
				   if(value!= null)
					 enhprof.setCertificateProfileId(EnhancedEIDProfile.CERTUSAGE_ENC, Integer.parseInt(value));
				   value = request.getParameter(SELECT_PINTYPE + "2");
				   if(value!= null)
					 enhprof.setPINType(EnhancedEIDProfile.CERTUSAGE_ENC, Integer.parseInt(value));				   
				   value = request.getParameter(CHECKBOX_KEYRECOVERABLE + "2");
					if(value != null)                              
					enhprof.setIsKeyRecoverable(EnhancedEIDProfile.CERTUSAGE_ENC, value.equals(CHECKBOX_VALUE));
					else
					  enhprof.setIsKeyRecoverable(EnhancedEIDProfile.CERTUSAGE_ENC, false);
				   				
				 }

             				 				 
				 if(request.getParameter(BUTTON_SAVE) != null){
				   handler.changeHardTokenProfile(profile,profiledata);					
				   includefile="hardtokenprofilespage.jsp";
				 }				 
				 if(request.getParameter(BUTTON_UPLOADENVELOPETEMP) != null){
				   uploadmode = UPLOADMODE_ENVELOPE;
				   includefile="uploadtemplate.jsp";
				 }
				 if(request.getParameter(BUTTON_UPLOADVISUALTEMP) != null){
				   uploadmode =	UPLOADMODE_VISUAL;
				   includefile="uploadtemplate.jsp";
				 }				 
				 
			   }
			   if(request.getParameter(BUTTON_CANCEL) != null){
				  // Don't save changes.
				 includefile="hardtokenprofilespage.jsp";
			   }

			 }
		  }
		}
		
		if( action.equals(ACTION_CHANGE_PROFILETYPE)){
		  String value = request.getParameter(SELECT_HARDTOKENTYPE);
		  if(value!=null){        
			int profiletype = Integer.parseInt(value);
			switch(profiletype){          
			  case SwedishEIDProfile.TYPE_SWEDISHEID :
				profiledata = new SwedishEIDProfile();
				break;
			  case EnhancedEIDProfile.TYPE_ENHANCEDEID:
				profiledata =  new EnhancedEIDProfile();				      
				break;  		
			}   
		  }

		  includefile="hardtokenprofilepage.jsp";
		}
		if( action.equals(ACTION_UPLOADENVELOPETEMP)){
          if(buttonupload){
          	if(profiledata instanceof IPINEnvelopeSettings){
          	  try{	
                BufferedReader br = new BufferedReader(new InputStreamReader(file,"UTF8"));
				String filecontent = "";
				String nextline = "";
				while(nextline!=null){
				  nextline = br.readLine();
				  if(nextline != null)				    
				    filecontent += nextline + "\n";
				}                
			    ((IPINEnvelopeSettings) profiledata).setPINEnvelopeData(filecontent);
			    ((IPINEnvelopeSettings) profiledata).setPINEnvelopeTemplateFilename(filename);
			    fileuploadsuccess = true;
			  }catch(IOException ioe){
			    fileuploadfailed = true;              	 
			  }            	 
			}
          }
		  includefile="hardtokenprofilepage.jsp";
		}
		if( action.equals(ACTION_UPLOADVISUALTEMP)){
			if(profiledata instanceof IVisualLayoutSettings){
			  try{			  
			    BufferedReader br = new BufferedReader(new InputStreamReader(file,"UTF8"));
			    String filecontent = "";
			    String nextline = "";
			    while(nextline!=null){
				  nextline = br.readLine();
				  if(nextline != null)				    
				    filecontent += nextline + "\n";
			    }
			    ((IVisualLayoutSettings) profiledata).setVisualLayoutData(filecontent);
			    ((IVisualLayoutSettings) profiledata).setVisualLayoutTemplateFilename(filename);
			    fileuploadsuccess = true;
			  }catch(IOException ioe){
				fileuploadfailed = true;              	 
			  }
			}
		  includefile="hardtokenprofilepage.jsp";
		}		
						
	  }    
  	    
      return includefile;	
    }
    
    public int getProfileType(){    	
      int retval = SwedishEIDProfile.TYPE_SWEDISHEID;
      
      if(profiledata instanceof SwedishEIDProfile)
        retval = SwedishEIDProfile.TYPE_SWEDISHEID;	
      
	  if(profiledata instanceof EnhancedEIDProfile)
      	retval = EnhancedEIDProfile.TYPE_ENHANCEDEID;	  
	      	
	  return retval;    	
    }

    

    // Private fields.
    private EjbcaWebBean ejbcawebbean;
    private HardTokenInterfaceBean hardtokenbean;
    private boolean initialized=false;
	public boolean  hardtokenprofileexists       = false;
	public boolean  hardtokenprofiledeletefailed = false;
    public boolean  issuperadministrator = false;
    public boolean  fileuploadsuccess = false;
	public boolean  fileuploadfailed  = false;
    public HardTokenProfile profiledata = null;
	public String profilename = null;
	public int uploadmode = 0;
	
}
