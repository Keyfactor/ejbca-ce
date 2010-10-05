-- Add rowVersion column to all tables
-- PublisherQueueData was a late add-on so we need to check if the column was created during appserver start-up
ALTER TABLE PublisherQueueData ADD rowVersion NUMBER(10) DEFAULT 0 NOT NULL;
