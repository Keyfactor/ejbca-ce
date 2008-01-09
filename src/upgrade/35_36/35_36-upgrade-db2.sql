# Format of column changed, no information was stored here earlier though
alter table EJBCA.CRLData add column deltaCRLIndicator BIGINT NOT NULL WITH DEFAULT -1:

