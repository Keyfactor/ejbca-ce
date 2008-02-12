
# Format of column changed, no information was stored here earlier though
alter table CAData add updateTime bigint NOT NULL DEFAULT 0;

