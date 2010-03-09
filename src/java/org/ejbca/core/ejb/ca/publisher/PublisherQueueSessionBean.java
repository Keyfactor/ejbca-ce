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

package org.ejbca.core.ejb.ca.publisher;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.RemoveException;

import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileData;
import org.ejbca.util.JDBCUtil;


/**
 * Manages publisher queues which contains data to be republished, either because publishing failed or because publishing is done asynchonously. 
 *
 * @ejb.bean description="Session bean handling interface with publisher queue data"
 *   display-name="PublisherQueueSessionSB"
 *   name="PublisherQueueSession"
 *   jndi-name="PublisherQueueSession"
 *   local-jndi-name="PublisherQueueSessionLocal"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *
 * @ejb.transaction type="Required"
 *
 * @weblogic.enable-call-by-reference True
 *
 * @ejb.env-entry description="JDBC datasource to be used"
 * name="DataSource"
 * type="java.lang.String"
 * value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 * 
 * @ejb.ejb-external-ref description="The Publisher entity bean"
 *   view-type="local"
 *   ref-name="ejb/PublisherQueueDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.ca.publisher.PublisherQueueDataLocalHome"
 *   business="org.ejbca.core.ejb.ca.publisher.PublisherQueueDataLocal"
 *   link="PublisherQueueData"
 *
 * @ejb.home extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.ca.publisher.IPublisherQueueSessionLocalHome"
 *   remote-class="org.ejbca.core.ejb.ca.publisher.IPublisherQueueSessionHome"
 *
 * @ejb.interface extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.ca.publisher.IPublisherQueueSessionLocal"
 *   remote-class="org.ejbca.core.ejb.ca.publisher.IPublisherQueueSessionRemote"
 *
 * @author Tomas Gustavsson
 * @version $Id$
 */
public class PublisherQueueSessionBean extends BaseSessionBean {

    /**
     * The local home interface of publisher entity bean.
     */
    private PublisherQueueDataLocalHome queuehome = null;

    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        queuehome = (PublisherQueueDataLocalHome) getLocator().getLocalHome(PublisherQueueDataLocalHome.COMP_NAME);
    }


    /**
     * Adds an entry to the publisher queue.
	 *
	 * @param publisherId the publisher that this should be published to
	 * @param publishType the type of entry it is, {@link PublisherQueueData#PUBLISH_TYPE_CERT} or CRL
     * @throws CreateException if the entry can not be created
     *
     * @ejb.interface-method view-type="both"
     */
    public void addQueueData(int publisherId, int publishType, String fingerprint, PublisherQueueVolatileData queueData, int publishStatus) throws CreateException {
    	if (log.isTraceEnabled()) {
            log.trace(">addQueueData(publisherId: " + publisherId + ")");
    	}
    	queuehome.create(publisherId, publishType, fingerprint, queueData, publishStatus);
        trace("<addQueueData()");
    } // addEntry

    /**
     * Removes an entry from the publisher queue.
	 *
     *
     * @ejb.interface-method view-type="both"
     */
    public void removeQueueData(String pk) {
    	if (log.isTraceEnabled()) {
            log.trace(">removeQueueData(pk: " + pk + ")");
    	}
    	try {
			queuehome.remove(pk);
		} catch (EJBException e) {
			log.info(e);
		} catch (RemoveException e) {
			log.info(e);
		}
        trace("<removeQueueData()");
    } // addEntry

    /**
     * Finds all entries with status PublisherQueueData.STATUS_PENDING for a specific publisherId.
	 *
	 * @return Collection of PublisherQueueData, never null
	 * 
     * @ejb.interface-method view-type="both"
     */
    public Collection getPendingEntriesForPublisher(int publisherId) {
    	if (log.isTraceEnabled()) {
            log.trace(">getPendingEntriesForPublisher(publisherId: " + publisherId + ")");
    	}
    	Collection datas = null;
    	Collection ret = new ArrayList();
		try {
			datas = queuehome.findDataByPublisherIdAndStatus(publisherId, PublisherQueueData.STATUS_PENDING);
		} catch (FinderException e) {
			log.debug("No publisher queue entries found for publisher "+publisherId);
		}
		if (datas != null) {
	    	Iterator iter = datas.iterator();
	    	while (iter.hasNext()) {
	    		PublisherQueueDataLocal d = (PublisherQueueDataLocal)iter.next();
	    		PublisherQueueData pqd = new PublisherQueueData(d.getPk(), new Date(d.getTimeCreated()), new Date(d.getLastUpdate()), d.getPublishStatus(), d.getTryCounter(), d.getPublishType(), d.getFingerprint(), d.getPublisherId(), d.getPublisherQueueVolatileData());
	    		ret.add(pqd);
	    	}			
		}
        trace("<getPendingEntriesForPublisher()");
    	return ret;
    } // getPendingEntriesForPublisher

    /**
     * Gets the number of pending entries for a publisher.
     * @param publisherId The publisher to count the number of pending entries for.
     * @return The number of pending entries.
     * 
     * @ejb.interface-method view-type="both"
     */
    public int getPendingEntriesCountForPublisher(int publisherId) {
    	return getPendingEntriesCountForPublisherInIntervals(publisherId, new int[]{0}, new int[]{-1})[0];
    } // getPendingEntriesCountForPublisher
    
    /**
     * Gets an array with the number of new pending entries for a publisher in each intervals specified by 
     * <i>lowerBounds</i> and <i>upperBounds</i>. 
     * 
     * The interval is defined as from lowerBounds[i] to upperBounds[i] and the unit is seconds from now. 
     * A negative value results in no boundary.
     * 
     * @param publisherId The publisher to count the number of pending entries for.
     * @return Array with the number of pending entries corresponding to each element in <i>interval</i>.
     * 
     * @ejb.interface-method view-type="both"
     */
    public int[] getPendingEntriesCountForPublisherInIntervals(int publisherId, int[] lowerBounds, int[] upperBounds) {
    	if (log.isTraceEnabled()) {
            log.trace(">getPendingEntriesCountForPublisherInIntervals(publisherId: " + publisherId + ", lower:" + Arrays.toString(lowerBounds) + ", upper:" + Arrays.toString(upperBounds) +  ")");
    	}
    	if(lowerBounds.length != upperBounds.length) {
    		throw new IllegalArgumentException("lowerBounds and upperBounds must have equal length");
    	}
    	
    	int[] result = new int[lowerBounds.length];
    	Connection con = null;
    	PreparedStatement ps = null;
    	ResultSet rs = null;
    	
    	try {
	    	con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
	    	StringBuilder sql = new StringBuilder();
	    	long now = new Date().getTime();
	    	
	    	for(int i = 0; i < lowerBounds.length; i++) {
	    		sql.append("select count(*) from PublisherQueueData where publisherId=");
	    		sql.append(publisherId);
	    		sql.append(" and publishStatus=");
	    		sql.append(PublisherQueueData.STATUS_PENDING);
	    		if(lowerBounds[i] > 0) {
		    		sql.append(" and timeCreated < ");
		    		sql.append(now - 1000 * lowerBounds[i]);
	    		}
	    		if(upperBounds[i] > 0) {
		    		sql.append(" and timeCreated > ");
		    		sql.append(now - 1000 * upperBounds[i]);
	    		}
	    		if(i < lowerBounds.length-1) {
	    			sql.append(" union all ");
	    		}
	    	}
	    	if (log.isDebugEnabled()) {
	    		log.debug("Executing SQL: "+sql.toString());    			
			}
	    	ps = con.prepareStatement(sql.toString());
			
			rs = ps.executeQuery();
			for(int i = 0; i < lowerBounds.length && rs.next(); i++) {
				result[i] = rs.getInt(1);
			}
    	} catch(SQLException e) {
    		throw new EJBException(e);
    	} finally {
    		JDBCUtil.close(con, ps, rs);
    	}
    	trace("<getPendingEntriesCountForPublisherInIntervals()");
    	return result;
    } // getPendingEntriesCountForPublisher
    
    /**
     * Finds all entries with status PublisherQueueData.STATUS_PENDING for a specific publisherId.
	 *
	 * @param orderBy order by clause for the SQL to the database, for example "order by timeCreated desc".
	 * 
	 * @return Collection of PublisherQueueData, never null
	 * 
     * @ejb.interface-method view-type="both"
     */
    public Collection getPendingEntriesForPublisherWithLimit(int publisherId, int limit, int timeout, String orderBy) {
    	if (log.isTraceEnabled()) {
            log.trace(">getPendingEntriesForPublisherWithLimit(publisherId: " + publisherId + ")");
    	}
    	Collection ret = new ArrayList();
    	Connection con = null;
    	PreparedStatement ps = null;
    	ResultSet result = null;
    	try {
    		// This should only list a few thousand certificates at a time, in case there
    		// are really many entries.
    		con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
    		String sql = "select pk, timeCreated, lastUpdate, tryCounter, publishType, fingerprint from PublisherQueueData where publisherId=? and publishStatus=?";
    		if (orderBy != null) {
    			sql += " "+orderBy;
    		}
    		if (log.isDebugEnabled()) {
        		log.debug("Executing SQL: "+sql);    			
    		}
    		ps = con.prepareStatement(sql);
    		ps.setInt(1, publisherId);
    		ps.setInt(2, PublisherQueueData.STATUS_PENDING);
    		ps.setFetchSize(limit);
    		ps.setMaxRows(limit);
    		try {
    			ps.setQueryTimeout(timeout);
    		} catch (Exception e) {
    			// ignore, in postgresql 8.4 (jdbc4 driver v701) trying this throws an exception telling you that it's not implemented yet in the driver.
        		if (log.isDebugEnabled()) {
            		log.debug("Error setting query timeout, I guess this is postgresql 8? In this case it is expected. "+e.getMessage());    			
        		}
    		}
    		result = ps.executeQuery();
    		while (result.next()) {
    			String pk = result.getString(1);
    			Date timeCreated = new Date(result.getLong(2));
    			Date lastUpdate = new Date(result.getLong(3));
    			int tryCounter = result.getInt(4);
    			int publishType = result.getInt(5);
    			String fingerprint = result.getString(6);
	    		PublisherQueueData pqd = new PublisherQueueData(pk, timeCreated, lastUpdate, PublisherQueueData.STATUS_PENDING, tryCounter, publishType, fingerprint, publisherId, null);
	    		try {
					PublisherQueueDataLocal dl = queuehome.findByPrimaryKey(pk);
					PublisherQueueVolatileData vol = dl.getPublisherQueueVolatileData();
					pqd.setVolatileData(vol);
					ret.add(pqd); // We finally have an object to return...
					if (log.isDebugEnabled()) {
						log.debug("Return pending record with pk "+pk+", and timeCreated "+timeCreated);
					}
				} catch (FinderException e) {
					log.debug("All of a sudden entry with primaryKey vanished: "+pk);
				}
    		}
    	} catch (SQLException e) {
    		throw new EJBException(e);
    	} finally {
    		JDBCUtil.close(con, ps, result);
    	}
        trace("<getPendingEntriesForPublisherWithLimit()");
    	return ret;
    } // getPendingEntriesForPublisherWithLimit

    /**
     * Finds all entries for a specific fingerprint.
	 *
	 * @return Collection of PublisherQueueData, never null
	 * 
     * @ejb.interface-method view-type="both"
     */
    public Collection getEntriesByFingerprint(String fingerprint) {
    	if (log.isTraceEnabled()) {
            log.trace(">getEntriesByFingerprint(fingerprint: " + fingerprint + ")");
    	}
    	Collection datas = null;
    	Collection ret = new ArrayList();
		try {
			datas = queuehome.findDataByFingerprint(fingerprint);
		} catch (FinderException e) {
			log.debug("No publisher queue entries found for fingerprint "+fingerprint);
		}
		if (datas != null) {
	    	Iterator iter = datas.iterator();
	    	while (iter.hasNext()) {
	    		PublisherQueueDataLocal d = (PublisherQueueDataLocal)iter.next();
	    		PublisherQueueData pqd = new PublisherQueueData(d.getPk(), new Date(d.getTimeCreated()), new Date(d.getLastUpdate()), d.getPublishStatus(), d.getTryCounter(), d.getPublishType(), d.getFingerprint(), d.getPublisherId(), d.getPublisherQueueVolatileData());
	    		ret.add(pqd);
	    	}			
		}
        trace("<getEntriesByFingerprint()");
    	return ret;
    } // getEntriesByFingerprint

    
    /** Updates a record with new status
     * 
     * @param pk primary key of data entry
     * @param status status from PublisherQueueData.STATUS_SUCCESS etc, or -1 to not update status
     * @param tryCounter an updated try counter, or -1 to not update counter
     * 
     * @ejb.interface-method view-type="both"
     */
    public void updateData(String pk, int status, int tryCounter) {
    	if (log.isTraceEnabled()) {
            log.trace(">updateData(pk: " + pk + ", status: "+status+")");
    	}
    	try {
    		PublisherQueueDataLocal data = queuehome.findByPrimaryKey(pk);
    		if (status > 0) {
        		data.setPublishStatus(status);    			
    		}
    		data.setLastUpdate(new Date().getTime());
    		if (tryCounter > -1) {
    			data.setTryCounter(tryCounter);
    		}
		} catch (FinderException e) {
			log.debug("Trying to set status on nonexisting data, pk: "+pk);
		}
        trace("<updateData()");
    }

} // LocalPublisherSessionBean
