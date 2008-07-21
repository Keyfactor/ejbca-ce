package org.ejbca.ui.cli;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Writer;
import java.util.ArrayList;
 
/**
 * A small CLI that uses the EJBCA CLI for importing certificates from a MS CA dump. The dump is assumed to be produced with
 *  certutil -view -restrict "GeneralFlags>0" /out "UPN,CertificateTemplate,Disposition,RawCertificate" > certdump.txt
 *
 *  And the CA has to be imported before this script is run.
 */
public class ImportMSCACertificates {
	
	static ArrayList<String>usedNames = new ArrayList<String>();

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		if (args.length < 2) {
			System.out.println(
					"Usage: ImportMSCACertificates.class <input-file> <CA name>\n" +
					" where <input-file> is generated with \n  certutil -view -restrict \"GeneralFlags>0\" /out "+
					"\"UPN,CertificateTemplate,Disposition,RawCertificate\" > certdump.txt\n on the CA-server."
			);
			return;
		}
		File infile = new File(args[0]);
		if (!infile.exists() || !infile.isFile()) {
			System.out.println(infile + " is not a file.");
			return;
		}
		String caname = args[1];
		String ejbcaCLICommand = System.getenv("EJBCA_HOME") + File.separator + "bin" + File.separator + "ejbca.";
		if (File.separator.equals("\\")) {
			ejbcaCLICommand += "cmd";
		} else {
			ejbcaCLICommand += "sh";
		}

		/**
		 * Locates next line that starts with "Row"
		 * Parses UPN
		 * Parses TempateName
		 * Parses certificate status from the Disposition-field
		 * writes PEM-certificate to temporary file
		 * runs the import-CLI
	          o Username: UPN-TempateName
	          o Password: foo123
	          o Ca name: From the command line of the script. Should be the name of the imported MS CA.
	          o status: ACTIVE if issued and REVOKED if revoked
	          o filename: the temporary file
	          o EndEntityProfile: TemplateName (this of course have to exist.. maybe easily importable from this page)
	          o CertificateProfile: TemplateName (this of course have to exist.. maybe easily importable from this page)
		 * Start over until there are no more "Row"s
		 */

		FileInputStream fstream;
		try {
			fstream = new FileInputStream(infile);
			BufferedReader br = new BufferedReader(new InputStreamReader(fstream));
			String strLine;
			int currentCertificate = 0;
			String currentUPN = null;
			String currentTemplate = null;
			String currentStatus = null;
			boolean isProcessingCertificate = false;
			File tempFile = null;
			Writer bw = null;
			while ((strLine = br.readLine()) != null)   {
				if (strLine.startsWith("Row ")) {
					currentCertificate++;
				}
				if (strLine.startsWith("  User Principal Name:")) {
					currentUPN = strLine.split("\"")[1];
				}
				if (strLine.startsWith("  Certificate Template:")) {
					currentTemplate = strLine.split("\"")[1];
				}
				if (strLine.startsWith("  Request Disposition:")) {
					if (strLine.endsWith("Issued")) {
						currentStatus = "ACTIVE";
					} else {
						currentStatus = "REVOKED";
					}
				}
				if (strLine.equals("-----BEGIN CERTIFICATE-----")) {
					isProcessingCertificate = true;
					tempFile = File.createTempFile("certificate-",".pem");
					bw = new BufferedWriter(new FileWriter(tempFile));
				}
				if (isProcessingCertificate) {
					bw.write( strLine + "\n");
				}
				if (strLine.equals("-----END CERTIFICATE-----")) {
					bw.close();
					isProcessingCertificate = false;
					System.out.println("Wrote certificate to " + tempFile);
					System.out.println ("Template : " + currentTemplate + " UPN: " + currentUPN);
					String commandLine = ejbcaCLICommand + " ca importcert";
					String username = currentUPN+"-"+currentTemplate;
					int i = 2;
					while (usedNames.contains(username)) {
						username = currentUPN+"-"+currentTemplate + "-" + i;
						i++;
					}
					usedNames.add(username);
					//  bin/ejbca.sh ca importcert <username> <password> <caname> <status> <certificate file> [<endentityprofile> | <endentityprofile> <certificateprofile>]
					commandLine += " " + username + " foo123 " + caname + " " + currentStatus + " " + tempFile.getCanonicalPath();
					commandLine += " " + currentTemplate + " " + currentTemplate;
					System.out.println("Running: " + commandLine);
					Process externalProcess = Runtime.getRuntime().exec(commandLine);
					BufferedReader stdError = new BufferedReader( new InputStreamReader( externalProcess.getErrorStream() ) );
					BufferedReader stdInput = new BufferedReader( new InputStreamReader( externalProcess.getInputStream() ) );
					if ( externalProcess.waitFor() != 0) {
						System.out.println("Excecution failed.");
					}
					String line = null;
					while ( (line = stdInput.readLine()) != null ) {
						System.out.println(line);
					}
					while ( (line = stdError.readLine()) != null ) {
						System.err.println(line);
					}
					tempFile.delete();
				}
			}
			fstream.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

	}

}
