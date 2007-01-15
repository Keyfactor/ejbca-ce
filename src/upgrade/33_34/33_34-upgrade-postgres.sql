
# Format of column changed, no information was stored here earlier though
alter table CAData add updateTime INT8;
update cadata set updateTime = 0;
alter table cadata alter column updateTime set not null;
alter table cadata alter column updateTime set default 0;
