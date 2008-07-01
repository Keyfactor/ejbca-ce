/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.util;

import java.util.ArrayList;

/**
 * Locking mechanism to avoid starvation. In Java there is no guarantee that threads will start in
 * the same order they blocked on a syncronized method.
 * 
 * Example usage:
 *   FifoLock fifoLock = new FifoLock();
 *   public void methodX() {
 *       fifoLock.lock();
 *       // Do stuff
 *       fifoLock.unlock();
 *   }
 * 
 * This code is inspired by a concurrency tutorial by Jakob Jenkov found at jenkov.com.
 */
public class FifoLock {
	boolean locked = false;
	Thread lockOwner = null;
	ArrayList fifoQueue = new ArrayList();	//<Sleeper>

	/**
	 * Acquire lock or block current thread. Locks are released in the same order as they were locked.
	 * When a thread is finished with it's work it must call unlock() to release the lock. 
	 */
	public void lock() throws InterruptedException {
		// Enqueue current thread
		Sleeper sleeper = new Sleeper();
		synchronized(this) {
			fifoQueue.add(sleeper);
		}
		while (true) {
			// Check if it's time to return to do some work
			synchronized(this) {
				if (!locked && fifoQueue.get(0) == sleeper) {
					locked = true;
					lockOwner = Thread.currentThread();
					fifoQueue.remove(sleeper);
					return;
				}
			}
			// Go back to sleep otherwise
			try {
				sleeper.sleep();
			} catch(InterruptedException e) {
				// Clean up before we re-throw the Exception
				synchronized(this) {
					fifoQueue.remove(sleeper);
				}
				throw e;
			}
		}
	}

	/**
	 * Releases the lock and gives the next locker in turn a chance to run.
	 */
	public synchronized void unlock() {
		if (this.lockOwner != Thread.currentThread()) {
			throw new IllegalMonitorStateException("Only current lock owner can unlock");
		}
		locked = false;
		if (fifoQueue.size() != 0) {
			((Sleeper) fifoQueue.get(0)).wakeup();
		} else {
			lockOwner = null; // No point in hogging this from the now GC
		}
	}

	/**
	 * Represents a waiting object in the FIFO.
	 */
	private class Sleeper {
		boolean woken = false;

		public synchronized void wakeup() {
			woken = true;
			notify();
		}

		public synchronized void sleep() throws InterruptedException {
			while (!woken) {
				wait();
			}
			woken = false;
		}
	}
}
