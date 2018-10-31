package org.ejbca.ui.web.pub;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ejb.ObjectNotFoundException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.DecoderException;
import org.cesecore.ErrorCode;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.PublicWebPrincipal;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.configuration.GlobalConfigurationSession;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.FileTools;
import org.cesecore.util.StringTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.KeyStoreCreateSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.ui.web.CertificateRequestResponse;
import org.ejbca.ui.web.CertificateResponseType;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.util.HTMLTools;

/**
 *
 * @version $Id$
 *
 */

public class RequestInstance {

	private static final Logger log = Logger.getLogger(RequestInstance.class);
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    /** Max size of request parameters that we will receive */
    private static final int REQUEST_MAX_SIZE = 10000;

    private class IncomatibleTokenTypeException extends EjbcaException {
        private static final long serialVersionUID = 5435852400591856793L;

        public IncomatibleTokenTypeException() {
            super(ErrorCode.BAD_USER_TOKEN_TYPE);
        }
    }

	private ServletContext servletContext;
	private ServletConfig servletConfig;
	private CaSessionLocal caSession;
    private CertificateProfileSessionLocal certificateProfileSession;
    private EndEntityProfileSessionLocal endEntityProfileSession;
	private KeyStoreCreateSessionLocal keyStoreCreateSession;
	private SignSessionLocal signSession;
	private EndEntityManagementSessionLocal endEntityManagementSession;
	private GlobalConfigurationSession globalConfigurationSession;
	private EndEntityAccessSessionLocal endEntityAccessSession;

	private String password=null;
	private String username=null;
	private String openvpn=null;
	private String certprofile=null;
	private String keylength="2048";
	private String keyalg=AlgorithmConstants.KEYALGORITHM_RSA;
	// Possibility to override by code and ignore parameters
	private String keylengthstring=null;
	private String keyalgstring=null;

	/** HttpServletrequest.getParametersMap has changed from Map<String,Object> to Map<String,String[]> so
	 * we can not be type safe here */
    @SuppressWarnings("rawtypes")
    private Map params = null;

	protected RequestInstance(ServletContext servletContext, ServletConfig servletConfig, EndEntityAccessSessionLocal endEntityAccessSession, CaSessionLocal caSession,
	        CertificateProfileSessionLocal certificateProfileSession, EndEntityProfileSessionLocal endEntityProfileSession, KeyStoreCreateSessionLocal keyStoreCreateSession,
	        SignSessionLocal signSession, EndEntityManagementSessionLocal endEntityManagementSession, GlobalConfigurationSession globalConfigurationSession) {
		this.servletContext = servletContext;
		this.servletConfig = servletConfig;
		this.caSession = caSession;
		this.certificateProfileSession = certificateProfileSession;
		this.endEntityProfileSession = endEntityProfileSession;
		this.keyStoreCreateSession = keyStoreCreateSession;
		this.signSession = signSession;
		this.endEntityManagementSession = endEntityManagementSession;
		this.endEntityAccessSession = endEntityAccessSession;
		this.globalConfigurationSession = globalConfigurationSession;
	}

	/**************************************************************
     ** If you want to force some parameters, you
     ** may set them here. These settings will
     ** override parameters in request
     **************************************************************/
    public String getPassword() {
        return password;
    }


    public void setPassword(String password) {
        this.password = password;
    }


    public String getUsername() {
        return username;
    }


    public void setUsername(String username) {
        this.username = username;
    }

    public String getOpenvpn() {
        return openvpn;
    }


    public void setOpenvpn(String openvpn) {
        this.openvpn = openvpn;
    }


    public String getCertprofile() {
        return certprofile;
    }


    public void setCertprofile(String certprofile) {
        this.certprofile = certprofile;
    }


    public String getKeylength() {
        return keylength;
    }


    // set key lengths, but can be overridden by request parameter
    public void setKeylength(String keylength) {
        this.keylength = keylength;
    }


    public String getKeyalg() {
        return keyalg;
    }

    // set key algorithm, but can be overridden by request parameter
    public void setKeyalg(String keyalg) {
        this.keyalg = keyalg;
    }

    public String getKeylengthstring() {
        return keylengthstring;
    }


    // Override request parameters with "hardcoded" key length from your code
    public void setKeylengthstring(String keylengthstring) {
        this.keylengthstring = keylengthstring;
    }


    public String getKeyalgstring() {
        return keyalgstring;
    }


    // Override request parameters with "hardcoded" key algorithm from your code
    public void setKeyalgstring(String keyalgstring) {
        this.keyalgstring = keyalgstring;
    }


    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		ServletDebug debug = new ServletDebug(request, response);
		boolean usekeyrecovery = false;

		RequestHelper.setDefaultCharacterEncoding(request);
		String iErrorMessage = null;
		try {
			setParameters(request);

            /*********************************************************************
             ** If parameters are not set by Set... they must be
             ** provided by request
             *********************************************************************/
            if (username==null) {
                username = StringUtils.strip(getParameter("user"));
            }
            if (password==null) {
                password = getParameter("password");
            }
            if (openvpn==null) {
                openvpn = getParameter("openvpn");
            }
            if (certprofile==null) {
                certprofile = getParameter("certprofile");
            }
            if (keyalgstring==null && keylengthstring==null) {
            	// For token generation the option comes in the form "KEYALGORITHM_KEYSPEC"
                final String tokenKeySpec = getParameter("tokenKeySpec");
                if (tokenKeySpec!=null) {
                    final String[] tokenKeySpecSplit = tokenKeySpec.split("_");
                    if (tokenKeySpecSplit.length==2) {
                        keyalgstring = tokenKeySpecSplit[0];
                        keylengthstring = tokenKeySpecSplit[1];
                    }
                }
            }
            if (keylengthstring==null) {
                keylengthstring = getParameter("keylength");
            }
            if (keyalgstring==null) {
                keyalgstring = getParameter("keyalg");
            }
            // If nothing has been set by setKeyLengthString and nothing is received by request parameters use default value of keylength
            if (keylengthstring != null) {
                keylength = keylengthstring;
            }
            // If nothing has been set by setKeyAlgString and nothing is received by request parameters use default value of keyalg
            if (keyalgstring != null) {
                keyalg = keyalgstring;
            }

			CertificateResponseType resulttype = CertificateResponseType.UNSPECIFIED;
			if(getParameter("resulttype") != null) {
				resulttype = CertificateResponseType.fromNumber(getParameter("resulttype")); // Indicates if certificate or PKCS7 should be returned on manual PKCS10 request.
			}

			String classid = "clsid:127698e4-e730-4e5c-a2b1-21490a70c8a1\" CODEBASE=\"/CertControl/xenroll.cab#Version=5,131,3659,0";

			if ((getParameter("classid") != null) &&
					!getParameter("classid").equals("")) {
				classid = getParameter("classid");
			}

            final AuthenticationToken administrator = new AlwaysAllowLocalAuthenticationToken(new PublicWebPrincipal("RequestInstance", request.getRemoteAddr()));

			RequestHelper helper = new RequestHelper(administrator, debug);

			log.info(intres.getLocalizedMessage("certreq.receivedcertreq", username, request.getRemoteAddr()));
			debug.print("Username: " + HTMLTools.htmlescape(username));

			// Check user
			int tokentype = SecConst.TOKEN_SOFT_BROWSERGEN;

			usekeyrecovery = ((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableKeyRecovery();

			EndEntityInformation data = endEntityAccessSession.findUser(administrator, username);

			if (data == null) {
				throw new ObjectNotFoundException();
			}

			boolean savekeys = data.getKeyRecoverable() && usekeyrecovery &&  (data.getStatus() != EndEntityConstants.STATUS_KEYRECOVERY);
			boolean loadkeys = (data.getStatus() == EndEntityConstants.STATUS_KEYRECOVERY) && usekeyrecovery;

			int endEntityProfileId = data.getEndEntityProfileId();
			int certificateProfileId = data.getCertificateProfileId();
			EndEntityProfile endEntityProfile = endEntityProfileSession.getEndEntityProfile(endEntityProfileId);
			boolean reusecertificate = endEntityProfile.getReUseKeyRecoveredCertificate();
			// Set a new certificate profile, if we have requested one specific
			if (StringUtils.isNotEmpty(certprofile)) {
				boolean clearpwd = StringUtils.isNotEmpty(data.getPassword());
				int id = certificateProfileSession.getCertificateProfileId(certprofile);
				// Change the value if there exists a certprofile with the requested name, and it is not the same as
				// the one already registered to be used by default
                if (id > 0) {
					if (id != certificateProfileId) {
						// Check if it is in allowed profiles in the entity profile
						final Collection<Integer> ids = endEntityProfile.getAvailableCertificateProfileIds();
						if (ids.contains(id)) {
							data.setCertificateProfileId(id);
							// This admin can be the public web user, which may not be allowed to change status,
							// this is a bit ugly, but what can a man do...
							AuthenticationToken tempadmin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("RequestInstance"+request.getRemoteAddr()));
							endEntityManagementSession.changeUser(tempadmin, data, clearpwd);
						} else {
							String defaultCertificateProfileName = certificateProfileSession.getCertificateProfileName(certificateProfileId);
							log.info(intres.getLocalizedMessage("certreq.badcertprofile", certprofile, defaultCertificateProfileName));
						}
					}
				} else {
					String defaultCertificateProfileName = certificateProfileSession.getCertificateProfileName(certificateProfileId);
					log.info(intres.getLocalizedMessage("certreq.nosuchcertprofile", certprofile, defaultCertificateProfileName));
				}
			}

			// get users Token Type.
			tokentype = data.getTokenType();
			if(tokentype == SecConst.TOKEN_SOFT_P12){
			    // If the user is configured for a server generated token, but submitted a CSR, it is most likely an administrative error.
			    // The RA admin should probably have set token type usergenerated instead.
			    if (hasCSRInRequest()) {
			        throw new IncomatibleTokenTypeException();
			    }
                KeyStore ks = keyStoreCreateSession.generateOrKeyRecoverToken(administrator, username, password, data.getCAId(), keylength, keyalg,
                        null, null, false, loadkeys, savekeys, reusecertificate, endEntityProfileId);
				if (StringUtils.equals(openvpn, "on")) {
					sendOpenVPNToken(ks, username, password, response);
				} else {
					sendP12Token(ks, username, password, response);
				}
			}
			if(tokentype == SecConst.TOKEN_SOFT_JKS){
                // If the user is configured for a server generated token, but submitted a CSR, it is most likely an administrative error.
                // The RA admin should probably have set token type usergenerated instead.
                if (hasCSRInRequest()) {
                    throw new IncomatibleTokenTypeException();
                }
                KeyStore ks = keyStoreCreateSession.generateOrKeyRecoverToken(administrator, username, password, data.getCAId(), keylength, keyalg,
                        null, null, true, loadkeys, savekeys, reusecertificate, endEntityProfileId);
				sendJKSToken(ks, username, password, response);
			}
			if(tokentype == SecConst.TOKEN_SOFT_PEM){
                // If the user is configured for a server generated token, but submitted a CSR, it is most likely an administrative error.
                // The RA admin should probably have set token type usergenerated instead.
                if (hasCSRInRequest()) {
                    throw new IncomatibleTokenTypeException();
                }
                KeyStore ks = keyStoreCreateSession.generateOrKeyRecoverToken(administrator, username, password, data.getCAId(), keylength, keyalg,
                        null, null, false, loadkeys, savekeys, reusecertificate, endEntityProfileId);
				sendPEMTokens(ks, username, password, response);
			}
			if(tokentype == SecConst.TOKEN_SOFT_BROWSERGEN){

				// first check if it is a Firefox request,
				if (getParameter("keygen") != null) {
					byte[] reqBytes=getParameter("keygen").getBytes();
					if ((reqBytes != null) && (reqBytes.length>0)) {
					    if (log.isDebugEnabled()) {
					        log.debug("Received NS request: "+new String(reqBytes));
					    }
						byte[] certs = helper.nsCertRequest(signSession, reqBytes, username, password);
						if (Boolean.valueOf(getParameter("showResultPage")) && !isCertIssuerThrowAwayCA(certs, username)) {
						  // Send info page that redirects to download URL that
						  // retrieves the new certificate from the database
						  RequestHelper.sendResultPage(certs, response, "true".equals(getParameter("hidemenu")), "netscape");
						} else {
						  // The certificate will not be stored in the database,
						  // so we must send the certificate while we still have it
						  RequestHelper.sendNewCertToNSClient(certs, response);
						}
					} else {
						throw new SignRequestException("No request bytes received.");
					}
				} else if ( (getParameter("pkcs10") != null) || (getParameter("PKCS10") != null) ) {
					// if not firefox, check if it's IE
					byte[] reqBytes = getParameter("pkcs10").getBytes();
					if (reqBytes == null) {
						reqBytes=getParameter("PKCS10").getBytes();
					}
					if ((reqBytes != null) && (reqBytes.length>0)) {
                        if (log.isDebugEnabled()) {
                            log.debug("Received IE request: "+new String(reqBytes));
                        }
						byte[] b64cert=helper.pkcs10CertRequest(signSession, caSession, reqBytes, username, password, CertificateResponseType.ENCODED_PKCS7).getEncoded();
						debug.ieCertFix(b64cert);
						response.setContentType("text/html");
						RequestHelper.sendNewCertToIEClient(b64cert, response.getOutputStream(), servletContext, servletConfig.getInitParameter("responseTemplate"),classid);
					} else {
						throw new SignRequestException("No request bytes received.");
					}
				} else if ( ((getParameter("pkcs10req") != null) || (getParameter("pkcs10file") != null)) && resulttype != CertificateResponseType.UNSPECIFIED) {
					byte[] reqBytes = null;
					String pkcs10req = getParameter("pkcs10req");
					if (StringUtils.isEmpty(pkcs10req)) {
						// did we upload a file instead?
                        if (log.isDebugEnabled()) {
                            log.debug("No pasted request received, checking for uploaded file.");
                        }
						pkcs10req = getParameter("pkcs10file");
						if (StringUtils.isNotEmpty(pkcs10req)) {
							// The uploaded file has been converted to a base64 encoded string
							reqBytes = Base64.decode(pkcs10req.getBytes());

						}
					} else {
						reqBytes=pkcs10req.getBytes(); // The pasted request
					}

					if ((reqBytes != null) && (reqBytes.length>0)) {
					    try {
					        pkcs10Req(request, response, username, password, resulttype, helper, reqBytes);
					    } catch(Exception exp) {
					        if(exp.getCause() instanceof NullPointerException) {
					            iErrorMessage = "Failed to parse request";
					        } else {
					            iErrorMessage = intres.getLocalizedMessage("certreq.failed", exp.getLocalizedMessage());
					        }
                        }
					} else {
						throw new SignRequestException("No request bytes received.");
					}
				} else if ( ((getParameter("cvcreq") != null) || (getParameter("cvcreqfile") != null)) && resulttype != CertificateResponseType.UNSPECIFIED) {
					// It's a CVC certificate request (EAC ePassports)
					byte[] reqBytes = null;
					String req = getParameter("cvcreq");
					if (StringUtils.isEmpty(req)) {
						// did we upload a file instead?
                        if (log.isDebugEnabled()) {
                            log.debug("No pasted request received, checking for uploaded file.");
                        }
						req = getParameter("cvcreqfile");
						if (StringUtils.isNotEmpty(req)) {
							// The uploaded file has been converted to a base64 encoded string
							reqBytes = Base64.decode(req.getBytes());

						}
					} else {
						reqBytes=req.getBytes(); // The pasted request
					}

					if ((reqBytes != null) && (reqBytes.length>0)) {
                        if (log.isDebugEnabled()) {
                            log.debug("Received CVC request: "+new String(reqBytes));
                        }
						byte[] b64cert=helper.cvcCertRequest(signSession, reqBytes, username, password);
						CVCertificate cvccert = (CVCertificate) CertificateParser.parseCVCObject(Base64.decode(b64cert));
						String filename = "";
						CAReferenceField carf = cvccert.getCertificateBody().getAuthorityReference();
						if (carf != null) {
							String car = carf.getConcatenated();
							filename += car;
						}
						HolderReferenceField chrf = cvccert.getCertificateBody().getHolderReference();
						if (chrf != null) {
							String chr = chrf.getConcatenated();
							if (filename.length() > 0) {
								filename += "_";
							}
							filename +=chr;
						}
						if (filename.length() == 0) {
							filename = username;
						}
                        if (log.isDebugEnabled()) {
                            log.debug("Filename: "+filename);
                        }
						if(resulttype == CertificateResponseType.BINARY_CERTIFICATE) {
							RequestHelper.sendBinaryBytes(Base64.decode(b64cert), response, "application/octet-stream", filename+".cvcert");
						}
						if(resulttype == CertificateResponseType.ENCODED_CERTIFICATE) {
							RequestHelper.sendNewB64File(b64cert, response, filename+".pem", CertTools.BEGIN_CERTIFICATE_WITH_NL, CertTools.END_CERTIFICATE_WITH_NL);
						}
					} else {
						throw new SignRequestException("No request bytes received.");
					}
				} else {
				    // throw general exception, will be caught below and all parameters printed.
                    throw new Exception("No known request type received.");
				}
			}
		} catch (AuthStatusException ase) {
			iErrorMessage = intres.getLocalizedMessage("certreq.wrongstatus");
        } catch (ObjectNotFoundException oe) {
            // Same error message for user not found and wrong password
            iErrorMessage = intres.getLocalizedMessage("ra.wrongusernameorpassword");
            // But debug log the real issue if needed
            if (log.isDebugEnabled()) {
                log.debug(intres.getLocalizedMessage("ra.errorentitynotexist", username));
            }
		} catch (AuthLoginException ale) {
			iErrorMessage = intres.getLocalizedMessage("ra.wrongusernameorpassword");
			log.info(iErrorMessage + " - username: " + username);
        } catch (IncomatibleTokenTypeException re) {
            iErrorMessage = intres.getLocalizedMessage("certreq.csrreceivedforservergentoken");
		} catch (SignRequestException re) {
		    log.info(re.getMessage(), re);
			iErrorMessage = intres.getLocalizedMessage("certreq.invalidreq", re.getMessage());
		} catch (SignRequestSignatureException se) {
			String iMsg = intres.getLocalizedMessage("certreq.invalidsign");
			log.info(iMsg, se);
			debug.printMessage(iMsg);
			debug.printDebugInfo();
			return;
		} catch (ArrayIndexOutOfBoundsException | DecoderException ae) {
			iErrorMessage = intres.getLocalizedMessage("certreq.invalidreq");
		} catch (IllegalKeyException e) {
			iErrorMessage = intres.getLocalizedMessage("certreq.invalidkey", e.getMessage());
		} catch (CryptoTokenOfflineException ctoe) {
		    String ctoeMsg = ctoe.getMessage();
		    for (Throwable e = ctoe; e != null; e = e.getCause()) {
		        //We can not do "if (e instanceof sun.security.pkcs11.wrapper.PKCS11Exception)" here because these classes are not guaranteed to exist on all platforms
                if (e.getClass().getName().contains("PKCS11")) {
		            ctoeMsg = "PKCS11 error "+e.getMessage();
		            break;
		        }
		    }
            iErrorMessage = intres.getLocalizedMessage("certreq.catokenoffline", ctoeMsg);
		} catch (AuthorizationDeniedException e) {
		    iErrorMessage = intres.getLocalizedMessage("certreq.authorizationdenied") + e.getLocalizedMessage();
		} catch(CertificateCreateException e) {
		    if (e.getErrorCode()!=null && e.getErrorCode().equals(ErrorCode.CERTIFICATE_WITH_THIS_SUBJECTDN_ALREADY_EXISTS_FOR_ANOTHER_USER)) {
		        iErrorMessage = e.getLocalizedMessage();
		    } else {
		        if (e.getErrorCode()!=null && e.getErrorCode().equals(ErrorCode.NOT_AUTHORIZED)) {
		            debug.print(e.getLocalizedMessage());
		            debug.printDebugInfo();
		        } else {
		            debug.takeCareOfException(e);
		            debug.printDebugInfo();
		        }
		    }
		} catch (Exception e) {
			Throwable e1 = e.getCause();
			if (e1 instanceof CryptoTokenOfflineException) {
				String iMsg = intres.getLocalizedMessage("certreq.catokenoffline", e1.getMessage());
				// this is already logged as an error, so no need to log it one more time
				debug.printMessage(iMsg);
				debug.printDebugInfo();
				return;
			} else {
				if (e1 == null) { e1 = e; }
                String iMsg = intres.getLocalizedMessage("certreq.errorgeneral", e1.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug(iMsg, e);
                }
				iMsg = intres.getLocalizedMessage("certreq.parameters", e1.getMessage());
				debug.print(iMsg + ":\n");
				@SuppressWarnings("unchecked")
                Set<String> paramNames = params.keySet();
				for(String name : paramNames) {
					String parameter = getParameter(name);
                    if (!StringUtils.equals(name, "password")) {
                        debug.print(HTMLTools.htmlescape(name) + ": '" + HTMLTools.htmlescape(parameter) + "'\n");
                    } else {
                        debug.print(HTMLTools.htmlescape(name) + ": <hidden>\n");
                    }
				}
				// Don't print back details to the client, this is considered information leak
				//debug.takeCareOfException(e);
				debug.printDebugInfo();
			}
		}
		if (iErrorMessage != null) {
            if (log.isDebugEnabled()) {
                log.debug(iErrorMessage);
            }
			debug.printMessage(iErrorMessage);
			debug.printDebugInfo();
			return;
		}
	}

    /** Check is a request to this servlet contains a Certificate Signing Request (CSR) in any
     * format that we support.
     */
    private boolean hasCSRInRequest() {
        if ((getParameter("cvcreq") != null) || (getParameter("cvcreqfile") != null)
                || (getParameter("pkcs10req") != null) || (getParameter("pkcs10file") != null)
                || (getParameter("pkcs10") != null) || (getParameter("PKCS10") != null)
                || (getParameter("iidPkcs10") != null)
                || (getParameter("keygen") != null)) {
            return true;
        }
        return false;
    }

    /**
     * Determines whether the issuer of a certificate is a "throw away" CA, i.e.
     * if it does not store certificates it issues in the database.
     *
     * @param certbytes DER encoded certificate.
     * @throws CertificateException
     */
    private boolean isCertIssuerThrowAwayCA(final byte[] certbytes, final String username) throws CADoesntExistsException, CertificateException {
        Certificate cert = CertTools.getCertfromByteArray(certbytes, Certificate.class);
        String issuerDN = CertTools.getIssuerDN(cert);
        int caid = issuerDN.hashCode();
        CAInfo caInfo = caSession.getCAInfoInternal(caid);
        EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(username);
        CertificateProfile certificateProfile = certificateProfileSession.getCertificateProfile(endEntityInformation.getCertificateProfileId());
        return (!caInfo.isUseCertificateStorage() && !certificateProfile.getUseCertificateStorage()) || !certificateProfile.getStoreCertificateData();
    }

	/**
	 * Method creating a Map of request values, designed to handle both
	 * regular x-encoded forms and multipart encoded upload forms.
	 *
	 * @param request
	 *            HttpServletRequest
	 * @throws FileUploadException
	 *             if multipart request can not be parsed
	 * @throws IOException
	 *             If input stream of uploaded object can not be read
	 */
	@SuppressWarnings("unchecked")
    private void setParameters(HttpServletRequest request) throws FileUploadException, IOException {
		if (ServletFileUpload.isMultipartContent(request)) {
			params = new HashMap<String, String>();
            final DiskFileItemFactory diskFileItemFactory = new DiskFileItemFactory();
            diskFileItemFactory.setSizeThreshold(9999);
            ServletFileUpload upload = new ServletFileUpload(diskFileItemFactory);
			upload.setSizeMax(REQUEST_MAX_SIZE);
            List<FileItem> items = upload.parseRequest(request);
			Iterator<FileItem> iter = items.iterator();
			while (iter.hasNext()) {
                FileItem item = iter.next();
				if (item.isFormField()) {
					params.put(item.getFieldName(), item.getString());
				} else {
					InputStream is = item.getInputStream();
					byte[] bytes = FileTools.readInputStreamtoBuffer(is);
					params.put(item.getFieldName(), new String(Base64.encode(bytes)));
				}
			}
		} else {
			params = request.getParameterMap();
		}
	}

	private String getParameter(String param) {
		String ret = null;
		Object o = params.get(param);
		if (o != null) {
			if (o instanceof String) {
			    if ( ((String)o).length() > REQUEST_MAX_SIZE ) {
			        if (log.isDebugEnabled()) {
			            log.debug("Parameter '"+param+"' exceed size limit of "+REQUEST_MAX_SIZE);
			        }
			    } else {
			        ret = (String) o;
			    }
			} else if (o instanceof String[]) { // keygen is of this type
			    // for some reason...
			    String[] str = (String[]) o;
			    if ((str != null) && (str.length > 0)) {
			        if ( str[0].length() > REQUEST_MAX_SIZE ) {
			            if (log.isDebugEnabled()) {
			                log.debug("Parameter (first in list) '"+param+"' exceed size limit of "+REQUEST_MAX_SIZE);
			            }
			        } else {
			            ret = str[0];
			        }
			    }
			} else {
				log.debug("Can not cast object of type: " + o.getClass().getName());
			}
		}
		return ret;
	}

	private void pkcs10Req(HttpServletRequest request, HttpServletResponse response, String username, String password, CertificateResponseType resulttype,
			RequestHelper helper, byte[] reqBytes) throws Exception, IOException {
        if (log.isDebugEnabled()) {
            log.debug("Received PKCS10 request: " + new String(reqBytes));
        }
		CertificateRequestResponse result = helper.pkcs10CertRequest(signSession, caSession, reqBytes, username, password, resulttype);
		byte[] b64data = result.getEncoded(); // PEM cert, cert-chain or PKCS7
		byte[] b64subject = result.getCertificate().getEncoded(); // always a PEM cert of the subject
		if (Boolean.valueOf(getParameter("showResultPage")) && !isCertIssuerThrowAwayCA(b64subject, username)) {
            RequestHelper.sendResultPage(b64subject, response, "true".equals(getParameter("hidemenu")), resulttype);
        } else {
            switch (resulttype) {
            case ENCODED_PKCS7:
                RequestHelper.sendNewB64File(b64data, response, username + ".pem", RequestHelper.BEGIN_PKCS7_WITH_NL, RequestHelper.END_PKCS7_WITH_NL);
                break;
            case ENCODED_CERTIFICATE:
                RequestHelper.sendNewB64File(b64data, response, username + ".pem", CertTools.BEGIN_CERTIFICATE_WITH_NL,
                        CertTools.END_CERTIFICATE_WITH_NL);
                break;
            case ENCODED_CERTIFICATE_CHAIN:
                //Begin/end keys have already been set in the serialized object
                RequestHelper.sendNewB64File(b64data, response, username + ".pem", "", "");
                break;
            default:
                log.warn("Unknown resulttype requested from pkcs10 request.");
                break;
            }
        }
	}

	/**
	 * method to create an install package for OpenVPN including keys and
	 * send to user. Contributed by: Jon Bendtsen,
	 * jon.bendtsen(at)laerdal.dk
	 */
	private void sendOpenVPNToken(KeyStore ks, String username, String kspassword, HttpServletResponse out) throws Exception {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		ks.store(buffer, kspassword.toCharArray());

		String tempDirectory = System.getProperty("java.io.tmpdir");
		File fout = new File(tempDirectory + System.getProperty("file.separator") + username + ".p12");
		String IssuerDN = null;
		String SubjectDN = null;
		try (FileOutputStream certfile = new FileOutputStream(fout)) {
		    Enumeration<String> en = ks.aliases();
		    String alias = en.nextElement();
		    // Then get the certificates
		    Certificate[] certs = KeyTools.getCertChain(ks, alias);
		    // The first one (certs[0]) is the users cert and the last
		    // one (certs [certs.lenght-1]) is the CA-cert
		    X509Certificate x509cert = (X509Certificate) certs[0];
		    IssuerDN = x509cert.getIssuerDN().toString();
		    SubjectDN = x509cert.getSubjectDN().toString();

		    // export the users certificate to file
		    buffer.writeTo(certfile);
		    buffer.flush();
		    buffer.close();
		    certfile.close();
		}
		// run shell script, which will also remove the created files
		// parameters are the username, IssuerDN and SubjectDN
		// IssuerDN and SubjectDN will be used to select the right
		// openvpn configuration file
		// they have to be written to stdin of the script to support
		// spaces in the username, IssuerDN or SubjectDN
		Runtime rt = Runtime.getRuntime();
		if (rt == null) {
			log.error(intres.getLocalizedMessage("certreq.ovpntnoruntime"));
		} else {
			final String script = WebConfiguration.getOpenVPNCreateInstallerScript();
			Process p = rt.exec(script);
			if (p == null) {
				log.error(intres.getLocalizedMessage("certreq.ovpntfailedexec", script));
			} else {
				OutputStream pstdin = p.getOutputStream();
				PrintStream stdoutp = new PrintStream(pstdin);
				stdoutp.println(username);
				stdoutp.println(IssuerDN);
				stdoutp.println(SubjectDN);
				stdoutp.flush();
				stdoutp.close();
				pstdin.close();
				int exitVal = p.waitFor();
				if (exitVal != 0) {
					log.error(intres.getLocalizedMessage("certreq.ovpntexiterror", exitVal));
				} else {
                    if (log.isDebugEnabled()) {
                        log.debug(intres.getLocalizedMessage("certreq.ovpntexiterror", exitVal));
                    }
				}
			}
		}

		// we ought to check if the script was okay or not, but in a little
		// while we will look for the openvpn-gui-install-$username.exe
		// and fail there if the script failed. Also, one could question
		// what to do if it did fail, serve the user the certificate?

		// sending the OpenVPN windows installer
		String filename = "openvpn-gui-install-" + username + ".exe";
		File fin = new File(tempDirectory + System.getProperty("file.separator") + filename);
		FileInputStream vpnfile = new FileInputStream(fin);
		out.setContentType("application/x-msdos-program");
		out.setHeader("Content-disposition", "filename=\"" + StringTools.stripFilename(filename) + "\"");
		out.setContentLength((int)fin.length());
		OutputStream os = out.getOutputStream();
		byte[] buf = new byte[4096];
		int bytes = 0;
		while ((bytes = vpnfile.read(buf)) != -1) {
			os.write(buf, 0, bytes);
		}
		vpnfile.close();
		// delete OpenVPN windows installer, the script will delete cert.
		fin.delete();
		out.flushBuffer();
	} // sendOpenVPNToken

	private void sendP12Token(KeyStore ks, String username, String kspassword, HttpServletResponse out) throws Exception {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		ks.store(buffer, kspassword.toCharArray());

		out.setContentType("application/x-pkcs12");
		out.setHeader("Content-disposition", "filename=\"" + StringTools.stripFilename(username + ".p12") + "\"");
		out.setContentLength(buffer.size());
		buffer.writeTo(out.getOutputStream());
		out.flushBuffer();
		buffer.close();
	}

	private void sendJKSToken(KeyStore ks, String username, String kspassword, HttpServletResponse out) throws Exception {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		ks.store(buffer, kspassword.toCharArray());

		out.setContentType("application/octet-stream");
		out.setHeader("Content-disposition", "filename=\"" + StringTools.stripFilename(username + ".jks") + "\"");
		out.setContentLength(buffer.size());
		buffer.writeTo(out.getOutputStream());
		out.flushBuffer();
		buffer.close();
	}

	private void sendPEMTokens(KeyStore ks, String username, String kspassword, HttpServletResponse out) throws Exception {
		out.setContentType("application/octet-stream");
		out.setHeader("Content-disposition", " attachment; filename=\"" + StringTools.stripFilename(username + ".pem") + "\"");
		out.getOutputStream().write(KeyTools.getSinglePemFromKeyStore(ks, kspassword.toCharArray()));
		out.flushBuffer();
	}
}

