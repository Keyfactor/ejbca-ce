package org.ejbca.ui.cli.clientToolBoxTest.utils;

import java.io.IOException;
import java.io.InputStream;

/**
 * Redirects the {@link System#in} to a custom {@link InputStream}. The redirection
 * is activated by calling {@link #initiate()}.
 * {@link #setInput(String)} is used to set a byte array source. When reading
 * a byte from {@link System#in} the current position of this source is read and
 * the current position is incremented. When the last character has been read
 * the current position is set to 0.
 * @author lars
 *
 */
public class SystemInRedirect {

	private class StdinInputStream extends InputStream {
		private byte input[];
		private int pos;
		public StdinInputStream() {
		}
		@Override
		public int read() throws IOException {
			if ( this.input==null || this.input.length<1 ) {
				return '\n';
			}
			return this.input[this.pos++%this.input.length];
		}
		void setInput(final String s) {
			this.input = s.getBytes();
			this.pos = 0;
		}
	}
	final private StdinInputStream is;
	private SystemInRedirect() {
		this.is = new StdinInputStream();
		System.setIn(this.is);
	}
	private static SystemInRedirect instance;
	/**
	 * Initiates the redirection.
	 */
	public static void initiate() {
		if ( instance!=null ) {
			return;
		}
		instance = new SystemInRedirect();
	}
	/**
	 * Sets the input source. The current position of the source to 0.
	 * @param input The bytes of this string will be the new input source.
	 */
	public static void setInput(final String input) {
		instance.is.setInput(input);
	}
}
