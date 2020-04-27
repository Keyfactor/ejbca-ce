package org.ejbca.ui.cli.clientToolBoxTest.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;

/**
 * <h1>
 * Storing of the system output.
 * </h1><p>
 * Storing what are sent to {@link System#err} and {@link System#out} in a time
 * interval. The interval is the time between a {@link SystemOutStorage#start()}
 * call and a {@link SystemOutStorage#getOutput()} call.
 * </p><p>
 * {@link #initiate()} must be called before any class using this utility is
 * created.
 * </p><p>
 * The output is retrieved by a the {@link #getOutput()} call.
 * </p>
 * @author lars
 *
 */
public class SystemOutStorage {

	/**
	 * Contains the output {@link #err} and {@link #out} from the last
	 * {@link SystemOutStorage#start()} to {@link SystemOutStorage#getOutput()}.
	 *
	 */
	public static class StdStrings {
		/**
		 * Contains everything sent to {@link System#err} in the time period.
		 */
		public final String err;
		/**
		 * Contains everything sent to {@link System#out} in the time period.
		 */
		public final String out;
		private static String getStringFromBAOS(ByteArrayOutputStream baos) throws IOException {
			if ( baos==null ) {
				return null;
			}
			baos.flush();
			final String value = baos.toString();
			baos.close();
			return value;
		}
		StdStrings(final ByteArrayOutputStream _err, final ByteArrayOutputStream _out) throws IOException {
			this.err = getStringFromBAOS(_err);
			this.out = getStringFromBAOS(_out);
		}
	}
	private ByteArrayOutputStream out;
	private ByteArrayOutputStream err;
	private abstract class MyOutputStream extends OutputStream {
		final PrintStream original;
		MyOutputStream( final PrintStream _original ) {
			this.original = _original;
		}
		abstract ByteArrayOutputStream getBAOS();
		@Override
		public void write(int b) throws IOException {
			this.original.write(b);
			if (getBAOS()==null) {
				return;
			}
			getBAOS().write(b);
		}
	}
	private class ErrorOutputStream extends MyOutputStream {
		ErrorOutputStream() {
			super(System.err);
		}
		@SuppressWarnings("synthetic-access")
		@Override
		ByteArrayOutputStream getBAOS() {
			return SystemOutStorage.this.err;
		}
	}
	private class StdoutOutputStream extends MyOutputStream {
		StdoutOutputStream() {
			super(System.out);
		}
		@SuppressWarnings("synthetic-access")
		@Override
		ByteArrayOutputStream getBAOS() {
			return SystemOutStorage.this.out;
		}
	}
	private SystemOutStorage() {
		this.out = null;
		this.err = null;
		System.setOut(new PrintStream(new StdoutOutputStream()));
		System.setErr(new PrintStream(new ErrorOutputStream()));
	}
	private static SystemOutStorage instance;
	/**
	 * Initiating of the redirection of output streams.
	 */
	public static void initiate() {
		if ( instance!=null ) {
			return;
		}
		instance = new SystemOutStorage();
	}
	/**
	 * Start to store system output.
	 * @throws InterruptedException
	 */
	public static void start() throws InterruptedException {
		instance.lStart();
	}
	/**
	 * Stop of storing System output.
	 * @return the output since {@link #start()}.
	 * @throws IOException
	 */
	public static StdStrings getOutput() throws IOException {
		return instance.lGetOutput();
	}
	
	private synchronized void lStart() throws InterruptedException {
		if ( this.out!=null || this.err!=null ) {
			wait();
		}
		this.out = new ByteArrayOutputStream();
		this.err = new ByteArrayOutputStream();
	}
	private synchronized StdStrings lGetOutput() throws IOException {
		final StdStrings result = new StdStrings(this.err, this.out);
		this.out = null;
		this.err = null;
		this.notifyAll();
		return result;
	}
}
