
# Format of column changed, no information was stored here earlier though
alter table CRLData add deltaCRLIndicator NUMBER(10) default -1;

ALTER TABLE AdminEntityData ADD cAId NUMBER(10) DEFAULT 0;
