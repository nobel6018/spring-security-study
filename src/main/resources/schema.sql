create table authority
(
    id      bigint generated by default as identity,
    name    varchar(255),
    user_id bigint,
    primary key (id)
)

create table users if not exists
(
    id        bigint generated by default as identity,
    algorithm varchar(255) not null,
    password  varchar(255) not null,
    username  varchar(255) not null,
    primary key (id)
)

alter table if exists authority add constraint FKka37hl6mopj61rfbe97si18p8 foreign key (user_id) references users