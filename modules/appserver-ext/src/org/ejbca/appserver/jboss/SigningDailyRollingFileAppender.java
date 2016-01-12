package org.ejbca.appserver.jboss;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Random;
import java.util.TimeZone;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.InputStreamRequestEntity;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.log4j.FileAppender;
import org.apache.log4j.Layout;
import org.apache.log4j.helpers.LogLog;
import org.apache.log4j.spi.LoggingEvent;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.FileTools;

/**
 * A shameless copy of DailyRollingFileAppender from log4j and merged (also shamelessly)
 * with DailyRollingFileAppender from jboss.
 * 
 * This was the only way I could find to implement the desired functionality.
 * 
 * @version $Id$
 */
public class SigningDailyRollingFileAppender extends FileAppender {

	private Thread signerThread; // NOPMD this is not run in the ejb app

	/**
	     The date pattern. By default, the pattern is set to
	     "'.'yyyy-MM-dd" meaning daily rollover.
	 */
	private String datePattern = "'.'yyyy-MM-dd";

	/** The method use to create a signature */
	private String signMethod;

	/** The URL to a TSA server used to create time stamps for rolled over log files */
	private String tsaUrl;
	
	/**
	     The log file will be renamed to the value of the
	     scheduledFilename variable when the next interval is entered. For
	     example, if the rollover period is one hour, the log file will be
	     renamed to the value of "scheduledFilename" at the beginning of
	     the next hour. 

	     The precise time when a rollover occurs depends on logging
	     activity. 
	 */
	private String scheduledFilename;

	/**
	     The next time we estimate a rollover should occur. */
	private long nextCheck = System.currentTimeMillis () - 1;

	Date now = new Date();

	SimpleDateFormat sdf;

	RollingCalendar rc = new RollingCalendar();

	int checkPeriod = RollingCalendar.TOP_OF_TROUBLE;

	// The gmtTimeZone is used only in computeCheckPeriod() method.
	static final TimeZone gmtTimeZone = TimeZone.getTimeZone("GMT");


	/**
	     The default constructor does nothing. */
	public SigningDailyRollingFileAppender() {
	}

	/**
	    Instantiate a <code>DailyRollingFileAppender</code> and open the
	    file designated by <code>filename</code>. The opened filename will
	    become the ouput destination for this appender.

	 */
	public SigningDailyRollingFileAppender (Layout layout, String filename,
			String datePattern) throws IOException {
		super(layout, filename, true);
		this.datePattern = datePattern;
		activateOptions();
	}

	/** This is from org.jboss.logging.appender.DailyRollingFileAppender,
	 *  which will make the directory structure for the set log file. 
	 */
	@Override
	public void setFile(final String filename){
	    makePath(filename);
		super.setFile(filename);
	}

	/**
     * Copied from org.jboss.logging.appender.FileAppender.Helper.makePath(String filename);
     * 
     */
    private static void makePath(final String filename) {
        File dir;

        try {
            URL url = new URL(filename.trim());
            dir = new File(url.getFile()).getParentFile();
        } catch (MalformedURLException e) {
            dir = new File(filename.trim()).getParentFile();
        }

        if (!dir.exists()) {
            boolean success = dir.mkdirs();
            if (!success) {
                LogLog.error("Failed to create directory structure: " + dir);
            }
        }
    }
	
	/**
	     The <b>DatePattern</b> takes a string in the same format as
	     expected by {@link SimpleDateFormat}. This options determines the
	     rollover schedule.
	 */
	public void setDatePattern(String pattern) {
		datePattern = pattern;
	}

	/** Returns the value of the <b>DatePattern</b> option. */
	public String getDatePattern() {
		return datePattern;
	}
	
	public void setSignMethod(String method) {
		signMethod = method;
	}
	public String getSignMethod() {
		return signMethod;
	}
	public void setTsaUrl(String url) {
		tsaUrl = url;
	}
	public String getTsaUrl() {
		return tsaUrl;
	}

	public void activateOptions() {
		super.activateOptions();
		if(datePattern != null && fileName != null) {
			now.setTime(System.currentTimeMillis());
			sdf = new SimpleDateFormat(datePattern);
			int type = computeCheckPeriod();
			printPeriodicity(type);
			rc.setType(type);
			File file = new File(fileName);
			scheduledFilename = fileName+sdf.format(new Date(file.lastModified()));

		} else {
			LogLog.error("Either File or DatePattern options are not set for appender ["+name+"].");
		}
		if (signMethod != null) {
			if (tsaUrl == null) {
				LogLog.error("TsaUrl option is not set for appender ["+name+"].");				
			}
		} else {
			LogLog.error("SignMethod option is not set for appender ["+name+"].");			
		}
		CryptoProviderTools.installBCProvider();
	}

	void printPeriodicity(int type) {
		switch(type) {
		case RollingCalendar.TOP_OF_MINUTE:
			LogLog.debug("Appender ["+name+"] to be rolled every minute.");
			break;
		case RollingCalendar.TOP_OF_HOUR:
			LogLog.debug("Appender ["+name
					+"] to be rolled on top of every hour.");
			break;
		case RollingCalendar.HALF_DAY:
			LogLog.debug("Appender ["+name
					+"] to be rolled at midday and midnight.");
			break;
		case RollingCalendar.TOP_OF_DAY:
			LogLog.debug("Appender ["+name
					+"] to be rolled at midnight.");
			break;
		case RollingCalendar.TOP_OF_WEEK:
			LogLog.debug("Appender ["+name
					+"] to be rolled at start of week.");
			break;
		case RollingCalendar.TOP_OF_MONTH:
			LogLog.debug("Appender ["+name
					+"] to be rolled at start of every month.");
			break;
		default:
			LogLog.warn("Unknown periodicity for appender ["+name+"].");
		}
	}


	// This method computes the roll over period by looping over the
	// periods, starting with the shortest, and stopping when the r0 is
	// different from from r1, where r0 is the epoch formatted according
	// the datePattern (supplied by the user) and r1 is the
	// epoch+nextMillis(i) formatted according to datePattern. All date
	// formatting is done in GMT and not local format because the test
	// logic is based on comparisons relative to 1970-01-01 00:00:00
	// GMT (the epoch).

	int computeCheckPeriod() {
		RollingCalendar rollingCalendar = new RollingCalendar(gmtTimeZone, Locale.ENGLISH);
		// set sate to 1970-01-01 00:00:00 GMT
		Date epoch = new Date(0);
		if(datePattern != null) {
			for(int i = RollingCalendar.TOP_OF_MINUTE; i <= RollingCalendar.TOP_OF_MONTH; i++) {
				SimpleDateFormat simpleDateFormat = new SimpleDateFormat(datePattern);
				simpleDateFormat.setTimeZone(gmtTimeZone); // do all date formatting in GMT
				String r0 = simpleDateFormat.format(epoch);
				rollingCalendar.setType(i);
				Date next = new Date(rollingCalendar.getNextCheckMillis(epoch));
				String r1 =  simpleDateFormat.format(next);
				//System.out.println("Type = "+i+", r0 = "+r0+", r1 = "+r1);
				if(r0 != null && r1 != null && !r0.equals(r1)) {
					return i;
				}
			}
		}
		return RollingCalendar.TOP_OF_TROUBLE; // Deliberately head for trouble...
	}

	/**
	     Rollover the current file to a new file.
	 */
	void rollOver() throws IOException {

		/* Compute filename, but only if datePattern is specified */
		if (datePattern == null) {
			errorHandler.error("Missing DatePattern option in rollOver().");
			return;
		}

		String datedFilename = fileName+sdf.format(now);
		// It is too early to roll over because we are still within the
		// bounds of the current interval. Rollover will occur once the
		// next interval is reached.
		if (scheduledFilename.equals(datedFilename)) {
			return;
		}

		// close current file, and rename it to datedFilename
		this.closeFile();

		File target  = new File(scheduledFilename);
		if (target.exists()) {
			target.delete();
		}

		File file = new File(fileName);
		boolean result = file.renameTo(target);
		if(result) {
			LogLog.debug(fileName +" -> "+ scheduledFilename);
		} else {
			LogLog.error("Failed to rename ["+fileName+"] to ["+scheduledFilename+"].");
		}

		try {
			// This will also close the file. This is OK since multiple
			// close operations are safe.
			this.setFile(fileName, false, this.bufferedIO, this.bufferSize);
		}
		catch(IOException e) {
			errorHandler.error("setFile("+fileName+", false) call failed.");
		}
		if (signMethod.equalsIgnoreCase("tsa")) {
			if (tsaUrl != null) {
				// Now do the actual signing
				// Check first if an old instance of the thread is blocking
				if ( (signerThread != null) && signerThread.isAlive() ) {
					System.out.println("Stopping old hanging signerthread");
					signerThread.interrupt();
				}
				signerThread = new Thread(new SignerThread(tsaUrl, scheduledFilename, scheduledFilename+".tsp")); // NOPMD this is not run in the ejb app
				signerThread.start();							
			} else {
				System.out.println("No TsaUrl set, can not sign logs!");
			}
		}

		scheduledFilename = datedFilename;
	}

	/**
	 * This method differentiates DailyRollingFileAppender from its
	 * super class.
	 *
	 * <p>Before actually logging, this method will check whether it is
	 * time to do a rollover. If it is, it will schedule the next
	 * rollover time and then rollover.
	 * */
	protected void subAppend(LoggingEvent event) {
		long n = System.currentTimeMillis();
		if (n >= nextCheck) {
			now.setTime(n);
			nextCheck = rc.getNextCheckMillis(now);
			try {
				rollOver();
			}
			catch(IOException ioe) {
				LogLog.error("rollOver() failed.", ioe);
			}
		}
		super.subAppend(event);
	}

}

class SignerThread implements Runnable { // NOPMD this is not run in the ejb app
	private String urlstr;
	private String infile;
	private String outfile;
	public SignerThread(String urlstr, String infile, String outfile) {
		this.urlstr = urlstr;
		this.infile = infile;
		this.outfile = outfile;
	}
	public void run() {
		
		try {
			boolean base64 = true;
			TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();

			Random rand = new Random();
			int nonce = rand.nextInt();
			byte[] digestBytes = new byte[20];
			if (infile != null) {
				digestBytes = FileTools.readFiletoBuffer(infile);
			}
			MessageDigest dig = MessageDigest.getInstance(TSPAlgorithms.SHA1.getId(), BouncyCastleProvider.PROVIDER_NAME);
			dig.update(digestBytes);
			byte[] digest = dig.digest();
			TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA1, digest, BigInteger.valueOf(nonce));

			// create a singular HttpClient object
			HttpClient client = new HttpClient();

			//establish a connection within 5 seconds
			client.getHttpConnectionManager().getParams().setConnectionTimeout(5000);			
			PostMethod method = new PostMethod(urlstr);
			method.setParameter("http.socket.timeout", "5000");
			method.setRequestHeader("Content-Type", "application/timestamp-query");
			method.setRequestEntity(new InputStreamRequestEntity(new ByteArrayInputStream(timeStampRequest.getEncoded())));
			method.setContentChunked(true);
			InputStream input = null;
			ByteArrayOutputStream baos = null;
			byte[] replyBytes = null;
			try {
				client.executeMethod(method);
				if (method.getStatusCode() == HttpStatus.SC_OK) {
					replyBytes = method.getResponseBody();
				}
			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				method.releaseConnection();
				if (input != null) { 
					input.close(); 
				}
				if (baos != null) { 
					baos.close(); 
				}
			}   

			if ( (outfile != null) && (replyBytes != null) ) {
				// Store request
				byte[] outBytes;
				if (base64) {
					outBytes=Base64.encode(replyBytes);
				} else {
					outBytes = replyBytes;
				}
				FileOutputStream fos = null;
				try {
					fos = new FileOutputStream(outfile);
					fos.write(outBytes);					
				} finally {
					if (fos != null) {
						fos.close();
					}
				}
			}

			if (replyBytes != null) {
				try {
					TimeStampResponse timeStampResponse = new TimeStampResponse(replyBytes);
					timeStampResponse.validate(timeStampRequest);
				} catch (TSPValidationException e) {
					LogLog.error("TimeStampResponse validation failed.", e);
					e.printStackTrace();
				} catch (TSPException e) {
					LogLog.error("TimeStampResponse failed.", e);
					e.printStackTrace();
				}			
			} else {
				LogLog.error("No reply bytes received, is TSA down?");
				System.out.println("SigningDailyRollingFileAppender: No reply bytes received, is TSA down?");
			}			
		} catch (Exception e) {
			LogLog.error("Exception caught while signing log: ", e);
			e.printStackTrace();
		} 
		
	}
	
}

