
# Format of column changed, no information was stored here earlier though
alter table CAData add updateTime INT8 NOT NULL DEFAULT 0;
