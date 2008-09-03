alter table AdminEntityData add cAId INT;
update AdminEntityData set cAId = 0;
alter table AdminEntityData alter column cAId set not null;
alter table AdminEntityData alter column cAId set default 0;

