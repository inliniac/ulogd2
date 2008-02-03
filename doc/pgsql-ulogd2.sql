-- vi: et ai ts=2
-- 
-- Warning: postgresql >= 8.2 is required for the 'DROP .. IF EXISTS'
-- Warning: this script DESTROYS EVERYTHING !
-- 
-- NOTE : - we could / should use types cidr / inet / macaddr for IP ? (see http://www.postgresql.org/docs/8.2/static/datatype-net-types.html)
--        - ON UPDATE is not supported ?
--        - type 'integer' is used (we have to check for overflows ..)
--        - type 'datetime' has been replaced by 'timestamp'
--        - deleting from table ulog2_ct will delete entries from ct_tuple

DROP TABLE IF EXISTS _format;
CREATE TABLE _format (
  version integer
) WITH (OIDS=FALSE);

INSERT INTO _format (version) VALUES (3);

-- this table could be used to know which user-defined tables are linked
-- to ulog
DROP TABLE IF EXISTS _extensions;
CREATE TABLE _extensions (
  ext_id serial PRIMARY KEY UNIQUE NOT NULL,
  ext_name varchar(64) NOT NULL,
  table_name varchar(64) NOT NULL,
  join_name varchar(64) NOT NULL
) WITH (OIDS=FALSE);

DROP TABLE IF EXISTS mac CASCADE;
DROP TABLE IF EXISTS tcp CASCADE;
DROP TABLE IF EXISTS udp CASCADE;
DROP TABLE IF EXISTS icmp CASCADE;
DROP TABLE IF EXISTS nufw CASCADE;
DROP TABLE IF EXISTS ulog2_ct CASCADE;
DROP TABLE IF EXISTS ct_tuple CASCADE;
DROP TABLE IF EXISTS ct_l4 CASCADE;
DROP TABLE IF EXISTS ct_icmp CASCADE;
DROP TABLE IF EXISTS ulog2 CASCADE;


DROP SEQUENCE IF EXISTS ulog2__id_seq;
CREATE SEQUENCE ulog2__id_seq;
CREATE TABLE ulog2 (
  _id bigint PRIMARY KEY UNIQUE NOT NULL DEFAULT nextval('ulog2__id_seq'),
  oob_time_sec integer default NULL,
  oob_time_usec integer default NULL,
  oob_prefix varchar(32) default NULL,
  oob_mark integer default NULL,
  oob_in varchar(32) default NULL,
  oob_out varchar(32) default NULL,
  ip_saddr inet default NULL,
  ip_daddr inet default NULL,
  ip_protocol smallint default NULL,
  ip_tos smallint default NULL,
  ip_ttl smallint default NULL,
  ip_totlen smallint default NULL,
  ip_ihl smallint default NULL,
  ip_csum smallint default NULL,
  ip_id smallint default NULL,
  ip_fragoff smallint default NULL,
  timestamp timestamp NOT NULL default 'now'
) WITH (OIDS=FALSE);

CREATE INDEX ulog2_timestamp ON ulog2(timestamp);
CREATE INDEX ulog2_ip_saddr ON ulog2(ip_saddr);
CREATE INDEX ulog2_ip_daddr ON ulog2(ip_daddr);

CREATE TABLE mac (
  _mac_id bigint PRIMARY KEY UNIQUE NOT NULL,
  mac_saddr macaddr default NULL,
  mac_daddr macaddr default NULL,
  mac_protocol smallint default NULL
) WITH (OIDS=FALSE);

CREATE INDEX mac_saddr ON mac(mac_saddr);
CREATE INDEX mac_daddr ON mac(mac_daddr);

CREATE TABLE tcp (
  _tcp_id bigint PRIMARY KEY UNIQUE NOT NULL,
  tcp_sport integer default NULL,
  tcp_dport integer default NULL,
  tcp_seq integer default NULL,
  tcp_ackseq integer default NULL,
  tcp_window smallint default NULL,
  tcp_urg smallint default NULL,
  tcp_urgp smallint  default NULL,
  tcp_ack smallint default NULL,
  tcp_psh smallint default NULL,
  tcp_rst smallint default NULL,
  tcp_syn smallint default NULL,
  tcp_fin smallint default NULL
) WITH (OIDS=FALSE);

CREATE INDEX tcp_sport ON tcp(tcp_sport);
CREATE INDEX tcp_dport ON tcp(tcp_dport);

ALTER TABLE tcp ADD CONSTRAINT tcp_sport_ok CHECK(tcp_sport >= 0 AND tcp_sport <= 65536);
ALTER TABLE tcp ADD CONSTRAINT tcp_dport_ok CHECK(tcp_dport >= 0 AND tcp_dport <= 65536);

CREATE TABLE udp (
  _udp_id bigint PRIMARY KEY UNIQUE NOT NULL,
  udp_sport integer default NULL,
  udp_dport integer default NULL,
  udp_len smallint default NULL
) WITH (OIDS=FALSE);

CREATE INDEX udp_sport ON udp(udp_sport);
CREATE INDEX udp_dport ON udp(udp_dport);

ALTER TABLE udp ADD CONSTRAINT udp_sport_ok CHECK(udp_sport >= 0 AND udp_sport <= 65536);
ALTER TABLE udp ADD CONSTRAINT udp_dport_ok CHECK(udp_dport >= 0 AND udp_dport <= 65536);

CREATE TABLE icmp (
  _icmp_id bigint PRIMARY KEY UNIQUE NOT NULL,
  icmp_type smallint default NULL,
  icmp_code smallint default NULL,
  icmp_echoid smallint default NULL,
  icmp_echoseq smallint default NULL,
  icmp_gateway integer default NULL,
  icmp_fragmtu smallint  default NULL
) WITH (OIDS=FALSE);

-- 
-- VIEWS
-- 

CREATE OR REPLACE VIEW view_tcp AS
        SELECT * FROM ulog2 INNER JOIN tcp ON ulog2._id = tcp._tcp_id;

CREATE OR REPLACE VIEW view_udp AS
        SELECT * FROM ulog2 INNER JOIN udp ON ulog2._id = udp._udp_id;

CREATE OR REPLACE VIEW view_icmp AS
        SELECT * FROM ulog2 INNER JOIN icmp ON ulog2._id = icmp._icmp_id;

-- shortcuts
CREATE OR REPLACE VIEW view_tcp_quad AS
        SELECT ulog2._id,ulog2.ip_saddr,tcp.tcp_sport,ulog2.ip_daddr,tcp.tcp_dport FROM ulog2 INNER JOIN tcp ON ulog2._id = tcp._tcp_id;

CREATE OR REPLACE VIEW view_udp_quad AS
        SELECT ulog2._id,ulog2.ip_saddr,udp.udp_sport,ulog2.ip_daddr,udp.udp_dport FROM ulog2 INNER JOIN udp ON ulog2._id = udp._udp_id;

-- 
-- conntrack
-- 
-- orig_id is linked to ulog2.id and is the packet before conntrack (and NAT, for ex)
-- reply_id is linked to ulog2.id and is the packet after conntrack (and NAT, for ex)
CREATE TABLE ulog2_ct (
  _ct_id serial PRIMARY KEY UNIQUE NOT NULL,
  orig_id integer default NULL,
  reply_id integer default NULL,
  state smallint default NULL,
  start_timestamp timestamp default NULL,
  end_timestamp timestamp default NULL
) WITH (OIDS=FALSE);

CREATE TABLE ct_tuple (
  _tuple_id bigint PRIMARY KEY UNIQUE NOT NULL,
  ip_saddr inet default NULL,
  ip_daddr inet default NULL,
  ip_protocol smallint default NULL,
  packets bigint default 0,
  bytes bigint default 0
) WITH (OIDS=FALSE);

CREATE INDEX ct_tuple_ip_saddr ON ct_tuple(ip_saddr);
CREATE INDEX ct_tuple_ip_daddr ON ct_tuple(ip_daddr);

CREATE TABLE ct_l4 (
  _l4_id bigint PRIMARY KEY UNIQUE NOT NULL,
  l4_sport integer default NULL,
  l4_dport integer default NULL
) WITH (OIDS=FALSE);

CREATE INDEX ct_l4_l4_sport ON ct_l4(l4_sport);
CREATE INDEX ct_l4_l4_dport ON ct_l4(l4_dport);

CREATE TABLE ct_icmp (
  _icmp_id bigint PRIMARY KEY UNIQUE NOT NULL,
  icmp_type smallint default NULL,
  icmp_code smallint default NULL
) WITH (OIDS=FALSE);


ALTER TABLE ulog2_ct ADD CONSTRAINT ulog2_orig_id_fk   FOREIGN KEY (orig_id)   REFERENCES ct_tuple(_tuple_id) ON DELETE CASCADE;
ALTER TABLE ulog2_ct ADD CONSTRAINT ulog2_reply_id_fk  FOREIGN KEY (reply_id)  REFERENCES ct_tuple(_tuple_id) ON DELETE CASCADE;

-- 
-- Helper table
-- 

DROP TABLE IF EXISTS ip_proto;
CREATE TABLE ip_proto (
  _proto_id serial PRIMARY KEY UNIQUE NOT NULL,
  proto_name varchar(16) default NULL,
  proto_desc varchar(255) default NULL
) WITH (OIDS=FALSE);

-- see files /etc/protocols
-- or /usr/share/nmap/nmap-protocols
INSERT INTO ip_proto (_proto_id,proto_name,proto_desc) VALUES
        (0,'ip','internet protocol, pseudo protocol number'),
        (1,'icmp','internet control message protocol'),
        (2,'igmp','Internet Group Management'),
        (3,'ggp','gateway-gateway protocol'),
        (4,'ipencap',E'IP encapsulated in IP (officially \'IP\')'),
        (5,'st','ST datagram mode'),
        (6,'tcp','transmission control protocol'),
        (17,'udp','user datagram protocol'),
        (41,'ipv6','Internet Protocol, version 6'),
        (58,'ipv6-icmp','ICMP for IPv6');

-- 
-- NuFW specific
-- 

DROP TABLE IF EXISTS nufw;
CREATE TABLE nufw (
  _nufw_id bigint PRIMARY KEY UNIQUE NOT NULL,
  username varchar(30) default NULL,
  user_id smallint default NULL,
  client_os varchar(100) default NULL,
  client_app varchar(256) default NULL
) WITH (OIDS=FALSE);

CREATE INDEX nufw_user_id ON nufw(user_id);

ALTER TABLE nufw ADD CONSTRAINT nufw_id_fk FOREIGN KEY (_nufw_id) REFERENCES ulog2(_id);

CREATE OR REPLACE VIEW view_nufw AS
        SELECT * FROM ulog2 INNER JOIN nufw ON ulog2._id = nufw._nufw_id;

INSERT INTO _extensions (ext_name,table_name,join_name) VALUES
        ('nufw','nufw','_nufw_id');


-- 
-- Procedures
-- 

CREATE OR REPLACE FUNCTION ULOG2_DROP_FOREIGN_KEYS()
RETURNS void AS $$
  ALTER TABLE icmp DROP CONSTRAINT icmp_id_fk;
  ALTER TABLE udp  DROP CONSTRAINT udp_id_fk;
  ALTER TABLE tcp  DROP CONSTRAINT tcp_id_fk;
$$ LANGUAGE SQL SECURITY INVOKER;


CREATE OR REPLACE FUNCTION ULOG2_ADD_FOREIGN_KEYS()
RETURNS void AS $$
  ALTER TABLE tcp  ADD CONSTRAINT tcp_id_fk  FOREIGN KEY (_tcp_id)  REFERENCES ulog2(_id);
  ALTER TABLE udp  ADD CONSTRAINT udp_id_fk  FOREIGN KEY (_udp_id)  REFERENCES ulog2(_id);
  ALTER TABLE icmp ADD CONSTRAINT icmp_id_fk FOREIGN KEY (_icmp_id) REFERENCES ulog2(_id);
$$ LANGUAGE SQL SECURITY INVOKER;


CREATE OR REPLACE FUNCTION DELETE_PACKET(
                IN _packet_id bigint
        )
RETURNS void AS $$
  -- remember : table with most constraints first
  DELETE FROM icmp  WHERE icmp._icmp_id = $1;
  DELETE FROM tcp   WHERE tcp._tcp_id   = $1;
  DELETE FROM udp   WHERE udp._udp_id   = $1;
  DELETE FROM ulog2 WHERE ulog2._id     = $1;
$$ LANGUAGE SQL SECURITY INVOKER;

-- this function requires plpgsql
-- su -c "createlang plpgsql ulog2" postgres
-- CREATE OR REPLACE FUNCTION DELETE_CUSTOM_ONE(
--                 tname varchar(64),
--                 tjoin varchar(64),
--                 _id bigint
--         )
-- RETURNS void AS $$
-- DECLARE
--   query TEXT;
-- BEGIN
--   query := 'DELETE FROM ' || $1 || ' WHERE ' || $1 || '.' || $2 || ' = $1';
--   PREPARE delete_stmt (bigint) AS query;
--   EXECUTE delete_stmt(_id);
--   DEALLOCATE PREPARE delete_stmt;
-- END
-- $$ LANGUAGE plpgsql SECURITY INVOKER;

CREATE OR REPLACE FUNCTION DELETE_CT_TUPLE(
                IN _packet_id bigint
        )
RETURNS void AS $$
  -- remember : table with most constraints first
  DELETE FROM ct_icmp  WHERE ct_icmp._icmp_id   = $1;
  DELETE FROM ct_l4    WHERE ct_l4._l4_id       = $1;
  DELETE FROM ct_tuple WHERE ct_tuple._tuple_id = $1;
$$ LANGUAGE SQL SECURITY INVOKER;




CREATE OR REPLACE FUNCTION COMPRESS_TABLES()
RETURNS void AS $$
  -- look for packets in table _tcp and not in table ulog2
  DELETE FROM tcp WHERE _tcp_id NOT IN (SELECT _id FROM ulog2);
  -- XXX note: could be rewritten (need to see what is more efficient) as:
  -- DELETE FROM tcp WHERE _tcp_id IN (SELECT tcp._tcp_id FROM tcp LEFT OUTER JOIN ulog2  ON (tcp._tcp_id = ulog2._id) WHERE ulog2._id IS NULL);
  DELETE FROM mac WHERE _mac_id NOT IN (SELECT _id FROM ulog2);
  DELETE FROM udp WHERE _udp_id NOT IN (SELECT _id FROM ulog2);
  DELETE FROM icmp WHERE _icmp_id NOT IN (SELECT _id FROM ulog2);
  -- look for packets in table ulog2 with proto tcp (or ipv6 ?) and not in table tcp
  DELETE FROM ulog2 WHERE ulog2.ip_protocol = '6' AND _id NOT IN (SELECT _tcp_id FROM tcp);
  DELETE FROM ulog2 WHERE ulog2.ip_protocol = '17' AND _id NOT IN (SELECT _udp_id FROM udp);
  DELETE FROM ulog2 WHERE ulog2.ip_protocol = '2' AND _id NOT IN (SELECT _icmp_id FROM icmp);
$$ LANGUAGE SQL SECURITY INVOKER;



-- ERROR:  VACUUM cannot be executed from a function
-- CREATE OR REPLACE FUNCTION ANALYZE_TABLES()
-- RETURNS void AS $$
--   VACUUM ANALYZE ulog2;
--   VACUUM ANALYZE mac;
--   VACUUM ANALYZE tcp;
--   VACUUM ANALYZE udp;
--   VACUUM ANALYZE icmp;
--   VACUUM ANALYZE ulog2_ct;
-- $$ LANGUAGE SQL SECURITY INVOKER;






-- Add foreign keys to tables
SELECT ULOG2_ADD_FOREIGN_KEYS();

-- 
-- Test section
-- 

-- pas besoin de faire une transaction, LAST_INSERT_ID est par connexion (donc pas de race condition, mais par contre il faut pas
-- faire d'insertions multiples)
BEGIN;
INSERT INTO ulog2 (ip_saddr,ip_daddr,ip_protocol) VALUES ('127.0.0.1','127.0.0.1',6);
INSERT INTO tcp (_tcp_id,tcp_sport,tcp_dport) VALUES (currval('ulog2__id_seq'),46546,80);
COMMIT;

BEGIN;
INSERT INTO ulog2 (ip_saddr,ip_daddr,ip_protocol) VALUES ('127.0.0.2','127.0.0.2',2);
INSERT INTO icmp (_icmp_id) VALUES (currval('ulog2__id_seq'));
COMMIT;

-- INSERT INTO ulog2_ct (orig_id,reply_id) VALUES (@tcp_packet1,@tcp_packet2);

INSERT INTO ulog2 (ip_saddr,ip_daddr,ip_protocol) VALUES ('127.0.0.1','127.0.0.1',0);
INSERT INTO nufw (_nufw_id,user_id,username) VALUES (currval('ulog2__id_seq'),1000,'toto');

INSERT INTO ulog2 (ip_saddr,ip_daddr,ip_protocol) VALUES ('127.0.0.1','127.0.0.1',0);

