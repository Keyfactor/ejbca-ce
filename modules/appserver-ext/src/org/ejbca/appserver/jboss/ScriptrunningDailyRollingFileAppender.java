package org.ejbca.appserver.jboss;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

import org.apache.log4j.FileAppender;
import org.apache.log4j.Layout;
import org.apache.log4j.helpers.LogLog;
import org.apache.log4j.spi.LoggingEvent;

/**
 * A shameless copy of DailyRollingFileAppender from log4j and merged (also shamelessly)
 * with DailyRollingFileAppender from jboss.
 * 
 * This was the only way I could find to implement the desired functionality.
 * 
 * @version $Id$
 */
public class ScriptrunningDailyRollingFileAppender extends FileAppender {

	// The code assumes that the following constants are in a increasing
	// sequence.
	static final int TOP_OF_TROUBLE=-1;
	static final int TOP_OF_MINUTE = 0;
	static final int TOP_OF_HOUR   = 1;
	static final int HALF_DAY      = 2;
	static final int TOP_OF_DAY    = 3;
	static final int TOP_OF_WEEK   = 4;
	static final int TOP_OF_MONTH  = 5;

	private Thread scriptThread; // NOPMD this is not run in the ejb app

	/**
	     The date pattern. By default, the pattern is set to
	     "'.'yyyy-MM-dd" meaning daily rollover.
	 */
	private String datePattern = "'.'yyyy-MM-dd";

	/** The script to run after rotating log */
	private String script;

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

	int checkPeriod = TOP_OF_TROUBLE;

	// The gmtTimeZone is used only in computeCheckPeriod() method.
	static final TimeZone gmtTimeZone = TimeZone.getTimeZone("GMT");


	/**
	     The default constructor does nothing. */
	public ScriptrunningDailyRollingFileAppender() {
	}

	/**
	    Instantiate a <code>DailyRollingFileAppender</code> and open the
	    file designated by <code>filename</code>. The opened filename will
	    become the ouput destination for this appender.

	 */
	public ScriptrunningDailyRollingFileAppender (Layout layout, String filename,
			String datePattern) throws IOException {
		super(layout, filename, true);
		this.datePattern = datePattern;
		activateOptions();
	}

	/** This is from org.jboss.logging.appender.DailyRollingFileAppender,
	 *  which will make the directory structure for the set log file. 
	 */
	@Override
	public void setFile(final String filename)
	{
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
		if (script == null) {
		    LogLog.error("Script option is not set for appender ["+name+"].");				
		}
	}

	void printPeriodicity(int type) {
		switch(type) {
		case TOP_OF_MINUTE:
			LogLog.debug("Appender ["+name+"] to be rolled every minute.");
			break;
		case TOP_OF_HOUR:
			LogLog.debug("Appender ["+name
					+"] to be rolled on top of every hour.");
			break;
		case HALF_DAY:
			LogLog.debug("Appender ["+name
					+"] to be rolled at midday and midnight.");
			break;
		case TOP_OF_DAY:
			LogLog.debug("Appender ["+name
					+"] to be rolled at midnight.");
			break;
		case TOP_OF_WEEK:
			LogLog.debug("Appender ["+name
					+"] to be rolled at start of week.");
			break;
		case TOP_OF_MONTH:
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
			for(int i = TOP_OF_MINUTE; i <= TOP_OF_MONTH; i++) {
				SimpleDateFormat simpleDateFormat = new SimpleDateFormat(datePattern);
				simpleDateFormat.setTimeZone(gmtTimeZone); // do all date formatting in GMT
				String r0 = simpleDateFormat.format(epoch);
				rollingCalendar.setType(i);
				Date next = new Date(rollingCalendar.getNextCheckMillis(epoch));
				String r1 =  simpleDateFormat.format(next);
				if(r0 != null && r1 != null && !r0.equals(r1)) {
					return i;
				}
			}
		}
		return TOP_OF_TROUBLE; // Deliberately head for trouble...
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
		if ( (script != null) && (script.length() > 0) ) {
				// Now call the script
				// Check first if an old instance of the thread is blocking
				if ( (scriptThread != null) && scriptThread.isAlive() ) {
					System.out.println("Stopping old hanging signerthread");
                    scriptThread.interrupt();
				}
                scriptThread = new Thread(new ScriptThread(script, scheduledFilename)); // NOPMD this is not run in the ejb app
                scriptThread.start();							
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

    public String getScript() {
        return script;
    }

    public void setScript(String script) {
        this.script = script;
    }

}

class ScriptThread implements Runnable { // NOPMD this is not run in the ejb app
	private String script;
	private String infile;
	public ScriptThread(String script, String infile) {
		this.script = script;
		this.infile = infile;
	}
	public void run() {
		
		try {
		    Runtime rt =Runtime.getRuntime();
		    String s = script +" "+infile;
            rt.exec(s);
            /*
            Process p = rt.exec(s);
            try {
                int e = p.exitValue(); 
                if (e != 0) {
                    LogLog.error("Script did not terminate with 0 return value.");                    
                    System.out.println("Script did not terminate with 0 return value.");                    
                }
            } catch (IllegalThreadStateException e) {
                LogLog.error("Script did not terminate within the timeout, 60 seconds.");
                System.out.println("Script did not terminate within the timeout, 60 seconds.");
                p.destroy();
            }
            */
		} catch (Exception e) {
			LogLog.error("Exception caught while running script: ", e);
			e.printStackTrace();
		} 
		
	}
	
}

