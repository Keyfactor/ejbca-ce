package org.ejbca.core.model.log;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Serializable;
import java.util.Properties;

import org.apache.log4j.Logger;

/**
 * Stores the last taken action so that the JUnit test can read the result.
 */
public class ProtectedLogTestAction implements IProtectedLogAction, Serializable {

	private static final long serialVersionUID = -7056505975194222536L;

    private static Logger log = Logger.getLogger(ProtectedLogTestAction.class);

	/**
	 * @see org.ejbca.core.model.log.IProtectedLogAction
	 */
	public ProtectedLogTestAction(Properties properties) {
	}
	
	/**
	 * @see org.ejbca.core.model.log.IProtectedLogAction
	 */
	public void action(String causeIdentifier) {
		log.info("Got action " + causeIdentifier);
		try {
			BufferedWriter out = new BufferedWriter(new FileWriter(getFilenameInTempDir()));
			out.write(causeIdentifier);
			out.close();
		} catch (IOException e) {
		}
	}

	/**
	 * @return the last status and then resetts the status
	 */
	public static String getLastActionCause() {
        String causeIdentifier = null;
	    try {
	        BufferedReader in = new BufferedReader(new FileReader(getFilenameInTempDir()));
	        causeIdentifier = in.readLine();
	        in.close();
	    } catch (IOException e) {
	    }
		log.info("Read " + causeIdentifier);
		removeFileInTempDir();
		return causeIdentifier;
	}
	
	private static String getFilenameInTempDir() {
		String filename = getTempDir() + "testing_" + ProtectedLogTestAction.class.getName() + ".tmp";
		log.debug("Using \""+filename+"\" to read last test status.");
		return filename;
	}
	
	public static String getTempDir() {
		String dirname = null;
		try {
			File file = File.createTempFile("ejbca-testing", "tmp");
			dirname = file.getCanonicalPath().substring(0, file.getCanonicalPath().lastIndexOf(File.separatorChar)+1);
			file.delete();
		} catch (IOException e) {
			log.error(e);
		}
		return dirname;
	}
	
	public static void removeFileInTempDir() {
		new File(getFilenameInTempDir()).delete();
	}

}
