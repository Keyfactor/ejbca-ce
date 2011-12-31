package org.ejbca.ui.cli.ca;

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

import org.ejbca.ui.cli.ErrorAdminCommandException;
 
/**
 * Used for importing certificates from a MS CA dump. The dump is assumed to be produced with
 *  certutil -view -restrict "GeneralFlags>0" /out "UPN,CertificateTemplate,Disposition,RawCertificate" > certdump.txt
 *
 *  The CA has to be imported before this code runs.
 */
public class ImportMSCACertificates extends CaImportCertCommand {
	
	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "importcertsms"; }
	public String getDescription() { return "Used for importing certificates from a MS CA certificate dump"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
		ArrayList<String>usedNames = new ArrayList<String>();
		if (args.length < 3) {
    		getLogger().info("Description: " + getDescription());
			getLogger().info("Usage: " + getCommand() + " <input-file> <CA name>");
    		getLogger().info(" <input-file> is generated with");
    		getLogger().info("  'certutil -view -restrict \"GeneralFlags>0\" /out \"UPN,CertificateTemplate,Disposition,RawCertificate\" > certdump.txt'");
    		getLogger().info(" on the MS CA-server.");
			return;
		}
		File infile = new File(args[1]);
		if (!infile.exists() || !infile.isFile()) {
			getLogger().error(infile + " is not a file.");
			return;
		}
		String caname = args[2];
		/*
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
			String currentUPN = null;
			String currentTemplate = null;
			String currentStatus = null;
			boolean isProcessingCertificate = false;
			File tempFile = null;
			Writer bw = null;
			while ((strLine = br.readLine()) != null)   {
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
					getLogger().info("Wrote certificate to " + tempFile);
					getLogger().info ("Template : " + currentTemplate + " UPN: " + currentUPN);
					String username = currentUPN + "-" + currentTemplate;
					int i = 2;
					while (usedNames.contains(username)) {
						username = currentUPN+"-"+currentTemplate + "-" + i;
						i++;
					}
					usedNames.add(username);
					String[] newArgs = {super.getMainCommand(), super.getSubCommand(), username, "foo123", caname, currentStatus, tempFile.getCanonicalPath(), currentTemplate, currentTemplate}; 
					super.execute(newArgs);
					tempFile.delete();
				}
			}
			fstream.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
