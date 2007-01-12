
# Format of column changed, no information was stored here earlier though
alter table CAData add updateTime NUMBER(19) NOT NULL default 0;
