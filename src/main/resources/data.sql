INSERT INTO users(id, username, password, algorithm)
values(1, 'leedo', '$2a$12$BrJpth02UoFS8dS2v47GE.2ya5rl5q4AS07OTDAbwyn1F/ZGQK4wW', 'BCRYPT');

INSERT INTO authority(id, name, user_id) values (1, 'READ', 1);
INSERT INTO authority(id, name, user_id) values (2, 'WRITE', 1);