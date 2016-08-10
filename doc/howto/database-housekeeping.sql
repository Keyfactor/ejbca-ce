--
-- This housekeeping script should not be run as an SQL script.
-- This file shows the principle of what should be considered for housekeeping.
-- SQL scripts should be made in cooperation with a good DBA for your database.
--
-- During long term operation of EJBCA your database will grow. This is due to several factors:
-- 1. The number of certificates you have issued (they are stored in the database).
-- 2. The number of end entities you have registered (they are stored in the database).
-- 3. The number of CRLs you have issued (they are stored in the database).
-- 4. If you have audit logging to database enabled (this is stored in the database).
--
-- So how large does your database get?
-- As you see your size may vary quite a lot depending on your usage pattern. If you have 
-- database knowledge you can analyze the sizes of your database tables and tune your database 
-- for your specific patterns.
-- As a simple rule of thumb you can calculate between 16-32KiB/issued certificate. 
-- Don't take it as a guarantee though, since you use can may be completely off the charts.
-- 
-- Here we will show how you can do some basic housekeeping of the three tables storing the
-- information mentioned above. 
-- NOTE: housekeeping is done on your own responsibility, you must know your use cases and determine
-- if deleting anything from the database is suitable. 
-- Always try on a test database before doing anything in production.
--
--
-- Clean old CRLs from database
--
select distinct issuerDN from CRLData;
-- Select the first issuerDN from the returned list.
select max(CRLNumber) from CRLData where issuerDN='CN=ManagementCA,O=EJBCA Sample,C=SE';
select count(*) from CRLData where issuerDN='CN=ManagementCA,O=EJBCA Sample,C=SE';
-- Should be a large number if you have issued many CRLs.
delete from CRLData where issuerDN='CN=ManagementCA,O=EJBCA Sample,C=SE' and crlNumber < 17;
-- Where 17 is the 'max(CRLnumber).
select count(*) from CRLData where issuerDN='CN=ManagementCA,O=EJBCA Sample,C=SE';
-- Should be 1
-- 
-- Repeat for all issuerDN.

-- 
-- Clean old expired certificates from database, if a CRL job is being run so certificate status is set to archived on expired certificates
--
delete from CertificateData where status=60;

--
-- Clean old expired certificates from database
--
-- Get the current date (or an older date) in seconds format
-- > date +%s
-- 1394628796
-- Then 1394628796000 (times 1000) is the date in milliseconds format
-- list all certificates that have expired.
select fingerprint,username,expireDate from CertificateData where expireDate<1394628796000;
-- delete all certificates that have expired.
delete from CertificateData where expireDate<1394628796000;

-- Delete from UserData and CertReqHistoryData where there is a username that does not have any certificates anymore
-- Warning these questions must be modified by DBA, they can not be executed as they are if you have a very large database.
-- It may take a very long time, make a test run in a test database first.
delete from UserData where UserData.username not in (select CertificateData.username from CertificateData);
delete from CertReqHistoryData where CertReqHistoryData.username not in (select CertificateData.username from CertificateData);

--
-- Clean old log data
--
-- AuditRecordData will contain a very large amount of rows if you have audit logging to database enabled and have been running for a long time.
-- Get the date for some time ago (14th january 2008, or any older date) in seconds format
-- >  date --date "01/14/2008 12:48:00" +%s
-- 1200343680
-- Then 1200343680000 is the date in milliseconds format
-- List the total number of rows
select count(*) from AuditRecordData;
-- List the number of rows before this date
select count(*) from AuditRecordData where timeStamp<1200343680000;
-- Delete the old log rows
-- Instead of deleting the rows you probably should move them to another partition/database, export them, or similar to keep the audit records. 
-- This depends on your policy, check it!
delete from AuditRecordData where timeStamp<1200343680000;
