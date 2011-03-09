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

import org.apache.commons.fileupload.DiskFileUpload;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUpload;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.core.ejb.ca.store.CertificateProfileSessionLocal;
import org.cesecore.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.config.ConfigurationHolder;
import org.ejbca.core.ejb.ca.auth.AuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.config.GlobalConfigurationSession;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.ra.UserAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionLocal;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ca.SignRequestSignatureException;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.util.GenerateToken;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.util.Base64;
import org.ejbca.util.FileTools;
import org.ejbca.util.keystore.KeyTools;

public class RequestInstance {

	private static final Logger log = Logger.getLogger(RequestInstance.class);
    private static final InternalResources intres = InternalResources.getInstance();
	
	private ServletContext servletContext;
	private ServletConfig servletConfig;
	private AuthenticationSessionLocal authenticationSession;
	private CAAdminSessionLocal caAdminSession;
    private CertificateProfileSessionLocal certificateProfileSession;
    private EndEntityProfileSessionLocal endEntityProfileSession;
	private KeyRecoverySessionLocal keyRecoverySession;
	private SignSessionLocal signSession;
	private UserAdminSessionLocal userAdminSession;
	private GlobalConfigurationSession globalConfigurationSession;
	
	protected RequestInstance(ServletContext servletContext, ServletConfig servletConfig, AuthenticationSessionLocal authenticationSession, CAAdminSessionLocal caAdminSession,
	        CertificateProfileSessionLocal certificateProfileSession, EndEntityProfileSessionLocal endEntityProfileSession, KeyRecoverySessionLocal keyRecoverySession, RaAdminSessionLocal raAdminSession,
			SignSessionLocal signSession, UserAdminSessionLocal userAdminSession, GlobalConfigurationSession globalConfigurationSession) {
		this.servletContext = servletContext;
		this.servletConfig = servletConfig;
		this.authenticationSession = authenticationSession;
		this.caAdminSession = caAdminSession;
		this.certificateProfileSession = certificateProfileSession;
		this.endEntityProfileSession = endEntityProfileSession;
		this.keyRecoverySession = keyRecoverySession;
		this.raAdminSession = raAdminSession;
		this.signSession = signSession;
		this.userAdminSession = userAdminSession;
		this.globalConfigurationSession = globalConfigurationSession;
	}

	void doPost(HttpServletRequest request, HttpServletResponse response)
	throws IOException, ServletException {
		ServletDebug debug = new ServletDebug(request, response);
		boolean usekeyrecovery = false;

		RequestHelper.setDefaultCharacterEncoding(request);
		String iErrorMessage = null;
		try {
			setParameters(request);

			String username = getParameter("user");
			String password = getParameter("password");
			String keylengthstring = getParameter("keylength");
			String keyalgstring = getParameter("keyalg");
			String openvpn = getParameter("openvpn");
			String certprofile = getParameter("certprofile");
			String keylength = "1024";
			String keyalg = AlgorithmConstants.KEYALGORITHM_RSA;

			int resulttype = 0;
			if(getParameter("resulttype") != null) {
				resulttype = Integer.parseInt(getParameter("resulttype")); // Indicates if certificate or PKCS7 should be returned on manual PKCS10 request.
			}

			String classid = "clsid:127698e4-e730-4e5c-a2b1-21490a70c8a1\" CODEBASE=\"/CertControl/xenroll.cab#Version=5,131,3659,0";

			if ((getParameter("classid") != null) &&
					!getParameter("classid").equals("")) {
				classid = getParameter("classid");
			}

			if (keylengthstring != null) {
				keylength = keylengthstring;
			}
			if (keyalgstring != null) {
				keyalg = keyalgstring;
			}

			Admin administrator = new Admin(Admin.TYPE_PUBLIC_WEB_USER, request.getRemoteAddr());

			RequestHelper helper = new RequestHelper(administrator, debug);

			log.info(intres.getLocalizedMessage("certreq.receivedcertreq", username, request.getRemoteAddr()));
			debug.print("Username: " + username);

			// Check user
			int tokentype = SecConst.TOKEN_SOFT_BROWSERGEN;

			usekeyrecovery = (globalConfigurationSession.getCachedGlobalConfiguration(administrator)).getEnableKeyRecovery();

			UserDataVO data = userAdminSession.findUser(administrator, username);

			if (data == null) {
				throw new ObjectNotFoundException();
			}

			boolean savekeys = data.getKeyRecoverable() && usekeyrecovery &&  (data.getStatus() != UserDataConstants.STATUS_KEYRECOVERY);
			boolean loadkeys = (data.getStatus() == UserDataConstants.STATUS_KEYRECOVERY) && usekeyrecovery;

			int endEntityProfileId = data.getEndEntityProfileId();
			int certificateProfileId = data.getCertificateProfileId();
			EndEntityProfile endEntityProfile = endEntityProfileSession.getEndEntityProfile(administrator, endEntityProfileId);
			boolean reusecertificate = endEntityProfile.getReUseKeyRecoveredCertificate();
			// Set a new certificate profile, if we have requested one specific
			if (StringUtils.isNotEmpty(certprofile)) {
				boolean clearpwd = StringUtils.isNotEmpty(data.getPassword());
				int id = certificateProfileSession.getCertificateProfileId(administrator, certprofile);
				// Change the value if there exists a certprofile with the requested name, and it is not the same as 
				// the one already registered to be used by default
				if ( (id > 0) ) {
					if (id != certificateProfileId) {
						// Check if it is in allowed profiles in the entity profile
						Collection c = endEntityProfile.getAvailableCertificateProfileIds();
						if (c.contains(String.valueOf(id))) {
							data.setCertificateProfileId(id);
							// This admin can be the public web user, which may not be allowed to change status,
							// this is a bit ugly, but what can a man do...
							Admin tempadmin = new Admin(Admin.TYPE_INTERNALUSER);
							userAdminSession.changeUser(tempadmin, data, clearpwd);            		            			
						} else {
							String defaultCertificateProfileName = certificateProfileSession.getCertificateProfileName(administrator, certificateProfileId);
							log.info(intres.getLocalizedMessage("certreq.badcertprofile", certprofile, defaultCertificateProfileName));
						}
					}
				} else {
					String defaultCertificateProfileName = certificateProfileSession.getCertificateProfileName(administrator, certificateProfileId);
					log.info(intres.getLocalizedMessage("certreq.nosuchcertprofile", certprofile, defaultCertificateProfileName));
				}
			}

			// get users Token Type.
			tokentype = data.getTokenType();
			GenerateToken tgen = new GenerateToken(authenticationSession, userAdminSession, caAdminSession, keyRecoverySession, signSession);
			if(tokentype == SecConst.TOKEN_SOFT_P12){
				KeyStore ks = tgen.generateOrKeyRecoverToken(administrator, username, password, data.getCAId(), keylength, keyalg, false, loadkeys, savekeys, reusecertificate, endEntityProfileId);
				if (StringUtils.equals(openvpn, "on")) {            	  
					sendOpenVPNToken(ks, username, password, response);
				} else {
					sendP12Token(ks, username, password, response);
				}
			}
			if(tokentype == SecConst.TOKEN_SOFT_JKS){
				KeyStore ks = tgen.generateOrKeyRecoverToken(administrator, username, password, data.getCAId(), keylength, keyalg, true, loadkeys, savekeys, reusecertificate, endEntityProfileId);
				sendJKSToken(ks, username, password, response);
			}
			if(tokentype == SecConst.TOKEN_SOFT_PEM){
				KeyStore ks = tgen.generateOrKeyRecoverToken(administrator, username, password, data.getCAId(), keylength, keyalg, false, loadkeys, savekeys, reusecertificate, endEntityProfileId);
				sendPEMTokens(ks, username, password, response);
			}
			if(tokentype == SecConst.TOKEN_SOFT_BROWSERGEN){

				// first check if it is a Firefox request,
				if (getParameter("keygen") != null) {
					byte[] reqBytes=getParameter("keygen").getBytes();
					if ((reqBytes != null) && (reqBytes.length>0)) {
						log.debug("Received NS request: "+new String(reqBytes));
						byte[] certs = helper.nsCertRequest(signSession, reqBytes, username, password);
						RequestHelper.sendNewCertToNSClient(certs, response);
					} else {
						throw new SignRequestException("No request bytes received.");
					}
				} else if ( getParameter("iidPkcs10") != null && !getParameter("iidPkcs10").equals("")) {
					// NetID iid?
					byte[] reqBytes = getParameter("iidPkcs10").getBytes();
					if ((reqBytes != null) && (reqBytes.length>0)) {
						log.debug("Received iidPkcs10 request: "+new String(reqBytes));
						byte[] b64cert=helper.pkcs10CertRequest(signSession, reqBytes, username, password, RequestHelper.ENCODED_CERTIFICATE, false);
						response.setContentType("text/html");
						RequestHelper.sendNewCertToIidClient(b64cert, request, response.getOutputStream(), servletContext, servletConfig.getInitParameter("responseIidTemplate"),classid);
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
						log.debug("Received IE request: "+new String(reqBytes));
						byte[] b64cert=helper.pkcs10CertRequest(signSession, reqBytes, username, password, RequestHelper.ENCODED_PKCS7);
						debug.ieCertFix(b64cert);
						RequestHelper.sendNewCertToIEClient(b64cert, response.getOutputStream(), servletContext, servletConfig.getInitParameter("responseTemplate"),classid);
					} else {
						throw new SignRequestException("No request bytes received.");
					}
				} else if ( ((getParameter("pkcs10req") != null) || (getParameter("pkcs10file") != null)) && resulttype != 0) {
					byte[] reqBytes = null;
					String pkcs10req = getParameter("pkcs10req");
					if (StringUtils.isEmpty(pkcs10req)) {
						// did we upload a file instead?
						log.debug("No pasted request received, checking for uploaded file.");
						pkcs10req = getParameter("pkcs10file");
						if (StringUtils.isNotEmpty(pkcs10req)) {
							// The uploaded file has been converted to a base64 encoded string
							reqBytes = Base64.decode(pkcs10req.getBytes());

						}
					} else {
						reqBytes=pkcs10req.getBytes(); // The pasted request            		  
					}

					if ((reqBytes != null) && (reqBytes.length>0)) {
						pkcs10Req(response, username, password, resulttype, signSession, helper, reqBytes);
					} else {
						throw new SignRequestException("No request bytes received.");
					}
				} else if ( ((getParameter("cvcreq") != null) || (getParameter("cvcreqfile") != null)) && resulttype != 0) {
					// It's a CVC certificate request (EAC ePassports)
					byte[] reqBytes = null;
					String req = getParameter("cvcreq");
					if (StringUtils.isEmpty(req)) {
						// did we upload a file instead?
						log.debug("No pasted request received, checking for uploaded file.");
						req = getParameter("cvcreqfile");
						if (StringUtils.isNotEmpty(req)) {
							// The uploaded file has been converted to a base64 encoded string
							reqBytes = Base64.decode(req.getBytes());

						}
					} else {
						reqBytes=req.getBytes(); // The pasted request            		  
					}

					if ((reqBytes != null) && (reqBytes.length>0)) {
						log.debug("Received CVC request: "+new String(reqBytes));
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
						log.debug("Filename: "+filename);
						if(resulttype == RequestHelper.BINARY_CERTIFICATE) {  
							RequestHelper.sendBinaryBytes(Base64.decode(b64cert), response, "application/octet-stream", filename+".cvcert");
						}
						if(resulttype == RequestHelper.ENCODED_CERTIFICATE) {
							RequestHelper.sendNewB64File(b64cert, response, filename+".pem", RequestHelper.BEGIN_CERTIFICATE_WITH_NL, RequestHelper.END_CERTIFICATE_WITH_NL);
						}
					} else {
						throw new SignRequestException("No request bytes received.");
					}
				}
			}
		} catch (ObjectNotFoundException oe) {
			iErrorMessage = intres.getLocalizedMessage("certreq.nosuchusername");
		} catch (AuthStatusException ase) {
			iErrorMessage = intres.getLocalizedMessage("certreq.wrongstatus");
		} catch (AuthLoginException ale) {
			iErrorMessage = intres.getLocalizedMessage("certreq.wrongpassword");
		} catch (SignRequestException re) {
			iErrorMessage = intres.getLocalizedMessage("certreq.invalidreq", re.getMessage());
		} catch (SignRequestSignatureException se) {
			String iMsg = intres.getLocalizedMessage("certreq.invalidsign");
			log.error(iMsg, se);
			debug.printMessage(iMsg);
			debug.printDebugInfo();
			return;
		} catch (ArrayIndexOutOfBoundsException ae) {
			iErrorMessage = intres.getLocalizedMessage("certreq.invalidreq");
		} catch (org.ejbca.core.model.ca.IllegalKeyException e) {
			iErrorMessage = intres.getLocalizedMessage("certreq.invalidkey", e.getMessage());
		} catch (Exception e) {
			Throwable e1 = e.getCause();
			if (e1 instanceof CATokenOfflineException) {
				String iMsg = intres.getLocalizedMessage("certreq.catokenoffline", e1.getMessage());
				// this is already logged as an error, so no need to log it one more time
				debug.printMessage(iMsg);
				debug.printDebugInfo();
				return;				
			} else {
				if (e1 == null) { e1 = e; }
				String iMsg = intres.getLocalizedMessage("certreq.errorgeneral", e1.getMessage());
				log.debug(iMsg, e);
				iMsg = intres.getLocalizedMessage("certreq.parameters", e1.getMessage());
				debug.print(iMsg + ":\n");
				Set paramNames = params.keySet();
				Iterator iter = paramNames.iterator();
				while (iter.hasNext()) {
					String name = (String)iter.next();
					String parameter = getParameter(name);
					if (!StringUtils.equals(name, "password")) {
						debug.print(name + ": '" + parameter + "'\n");                	
					} else {
						debug.print(name + ": <hidden>\n");
					}
				}
				debug.takeCareOfException(e);
				debug.printDebugInfo();
			}
		}
		if (iErrorMessage != null) {
			log.debug(iErrorMessage);
			debug.printMessage(iErrorMessage);
			debug.printDebugInfo();
			return;
		}
	}

	private Map params = null;

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
	private void setParameters(HttpServletRequest request) throws FileUploadException, IOException {
		if (FileUpload.isMultipartContent(request)) {
			params = new HashMap();
			DiskFileUpload upload = new DiskFileUpload();
			upload.setSizeMax(10000);
			upload.setSizeThreshold(9999);
			List items;
			items = upload.parseRequest(request);
			Iterator iter = items.iterator();
			while (iter.hasNext()) {
				FileItem item = (FileItem) iter.next();
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
				ret = (String) o;
			} else if (o instanceof String[]) { // keygen is of this type
				// for some reason...
				String[] str = (String[]) o;
				if ((str != null) && (str.length > 0)) {
					ret = str[0];
				}
			} else {
				log.debug("Can not cast object of type: " + o.getClass().getName());
			}
		}
		return ret;
	}

	private void pkcs10Req(HttpServletResponse response, String username, String password, int resulttype, SignSessionLocal signsession,
			RequestHelper helper, byte[] reqBytes) throws Exception, IOException {
		log.debug("Received PKCS10 request: " + new String(reqBytes));
		byte[] b64cert = helper.pkcs10CertRequest(signsession, reqBytes, username, password, resulttype);
		if (resulttype == RequestHelper.ENCODED_PKCS7) {
			RequestHelper.sendNewB64File(b64cert, response, username + ".pem", RequestHelper.BEGIN_PKCS7_WITH_NL, RequestHelper.END_PKCS7_WITH_NL);
		}
		if (resulttype == RequestHelper.ENCODED_CERTIFICATE) {
			RequestHelper.sendNewB64File(b64cert, response, username + ".pem", RequestHelper.BEGIN_CERTIFICATE_WITH_NL,
					RequestHelper.END_CERTIFICATE_WITH_NL);
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
		FileOutputStream certfile = new FileOutputStream(fout);

		Enumeration en = ks.aliases();
		String alias = (String) en.nextElement();
		// Then get the certificates
		Certificate[] certs = KeyTools.getCertChain(ks, alias);
		// The first one (certs[0]) is the users cert and the last
		// one (certs [certs.lenght-1]) is the CA-cert
		X509Certificate x509cert = (X509Certificate) certs[0];
		String IssuerDN = x509cert.getIssuerDN().toString();
		String SubjectDN = x509cert.getSubjectDN().toString();

		// export the users certificate to file
		buffer.writeTo(certfile);
		buffer.flush();
		buffer.close();
		certfile.close();

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
			final String script = ConfigurationHolder
			.getString("web.openvpn.createInstallerScript", "/usr/local/ejbca/bin/mk_openvpn_windows_installer.sh");
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
					log.debug(intres.getLocalizedMessage("certreq.ovpntexiterror", exitVal));
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
		out.setHeader("Content-disposition", "filename=" + filename);
		out.setContentLength(new Long(fin.length()).intValue());
		OutputStream os = out.getOutputStream();
		byte[] buf = new byte[4096];
		int offset = 0;
		int bytes = 0;
		while ((bytes = vpnfile.read(buf)) != -1) {
			os.write(buf, 0, bytes);
			offset += bytes;
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
		out.setHeader("Content-disposition", "filename=" + username + ".p12");
		out.setContentLength(buffer.size());
		buffer.writeTo(out.getOutputStream());
		out.flushBuffer();
		buffer.close();
	}

	private void sendJKSToken(KeyStore ks, String username, String kspassword, HttpServletResponse out) throws Exception {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		ks.store(buffer, kspassword.toCharArray());

		out.setContentType("application/octet-stream");
		out.setHeader("Content-disposition", "filename=" + username + ".jks");
		out.setContentLength(buffer.size());
		buffer.writeTo(out.getOutputStream());
		out.flushBuffer();
		buffer.close();
	}

	private void sendPEMTokens(KeyStore ks, String username, String kspassword, HttpServletResponse out) throws Exception {
		out.setContentType("application/octet-stream");
		out.setHeader("Content-disposition", " attachment; filename=" + username + ".pem");
		out.getOutputStream().write(KeyTools.getSinglePemFromKeyStore(ks, kspassword.toCharArray()));
		out.flushBuffer();
	}
}

