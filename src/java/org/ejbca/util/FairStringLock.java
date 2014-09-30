/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.log4j.Logger;

/**
 * Util for locking based on a String. This class can of course not do locking distributed over
 * several JVMs/EJBCA nodes. Currently not used by any classes in EJBCA.
 * 
 * Example usage:
 * 		String username = null;
 * 		boolean lockedByThisRequest = false;
 * 		...
 * 		try {
 * 			...
 * 			lockedByThisRequest = true;
 * 			FairStringLock.getInstance("SomeFairStringLock").lock(username);
 * 			...
 * 		} finally {
 * 			if (lockedByThisRequest) {
 * 				FairStringLock.getInstance("SomeFairStringLock").unlock(username);
 * 			}
 * 		}
 * 
 * @version $Id$
 */
public class FairStringLock {

	private static final Logger log = Logger.getLogger(FairStringLock.class);
			
	private static Map<String, FairStringLock> instanceMap = new HashMap<String, FairStringLock>();
	private static ReentrantLock instanceMapLock = new ReentrantLock(true);
	
	private final Map<String, ReentrantLock> lockMap = new HashMap<String, ReentrantLock>();
	private final ReentrantLock accessMapLock = new ReentrantLock(true);
	
	private final String instanceName;

	private FairStringLock(String instanceName) {
		this.instanceName = instanceName;
	}
	
	public static FairStringLock getInstance(String instanceName) {
		instanceMapLock.lock();
		FairStringLock instance = instanceMap.get(instanceName);
		if (instance == null) {
			instance = new FairStringLock(instanceName);
			instanceMap.put(instanceName, instance);
		}
		instanceMapLock.unlock();
		return instance;
	}
	
	public void lock(String lockName) {
		if (lockName == null) {
			return;
		}
		accessMapLock.lock();
		ReentrantLock reentrantLock = lockMap.get(lockName);
		if (reentrantLock == null) {
			reentrantLock = new ReentrantLock(true);
			lockMap.put(lockName, reentrantLock);
			reentrantLock.lock();
			accessMapLock.unlock();
		} else {
			accessMapLock.unlock();
			boolean gotProperLock = false;
			do {
				reentrantLock.lock();
				accessMapLock.lock();
				ReentrantLock storedReentrantLock = lockMap.get(lockName);
				if (reentrantLock.equals(storedReentrantLock)) {
					gotProperLock = true;
				} else {
					if (storedReentrantLock == null) {
						if (log.isDebugEnabled()) {
							log.debug("Instance \"" + instanceName + "\" had removed \"" + lockName + "\" while waiting for the lock.");
						}
						// So it was left for garbage collection.. write it back in the map
						lockMap.put(lockName, reentrantLock);
					} else {
						if (log.isDebugEnabled()) {
							log.debug("Instance \"" + instanceName + "\" had created a new \"" + lockName + "\" while a waiting for the lock.");
						}
						reentrantLock.unlock();
						reentrantLock = storedReentrantLock;
					}
				}
				accessMapLock.unlock();
			} while (!gotProperLock);
		}
	}
	
	public void unlock(String lockName) {
		if (lockName == null) {
			return;
		}
		accessMapLock.lock();
		ReentrantLock reentrantLock = lockMap.get(lockName);
		if (reentrantLock != null) {
			if (!reentrantLock.hasQueuedThreads()) {
				if (log.isDebugEnabled()) {
					log.debug("Instance \"" + instanceName + "\" removed reference \"" + lockName + "\".");
				}
				// No one is waiting for this lock so leave it for garbage collection
				lockMap.remove(lockName);
			}
			reentrantLock.unlock();
		} else {
			log.warn("Instance \"" + instanceName + "\" tried to unlock an non-existing entry \"" + lockName + "\"");
		}
		if (log.isDebugEnabled()) {
			log.debug("Unlocking. Instance \"" + instanceName + "\" is currently containing " + lockMap.keySet().size() + " references.");
		}
		accessMapLock.unlock();
	}
}
