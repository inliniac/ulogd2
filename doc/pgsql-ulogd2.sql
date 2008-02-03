-- vi: et ai ts=2
-- 
-- Warning: postgresql >= 8.2 is required for the 'DROP .. IF EXISTS'
-- Warning: this script DESTROYS EVERYTHING !
-- 
-- NOTE : - we could / should use types cidr / inet / macaddr for IP ? (see http://www.postgresql.org/docs/8.2/static/datatype-net-types.html)
--        - ON UPDATE is not supported ?
--        - type 'integer' is used (we have to check for overflows ..)
--        - type 'datetime' has been replaced by 'timestamp'

DROP TABLE IF EXISTS _format;
CREATE TABLE _format (
  version integer
) WITH (OIDS=FALSE);

INSERT INTO _format (version) VALUES (4);

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
  ip_saddr_str inet default NULL,
  ip_daddr_str inet default NULL,
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
CREATE INDEX ulog2_ip_saddr ON ulog2(ip_saddr_str);
CREATE INDEX ulog2_ip_daddr ON ulog2(ip_daddr_str);

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

-- complete view
CREATE OR REPLACE VIEW ulog AS
        SELECT * FROM ulog2 INNER JOIN tcp ON ulog2._id = tcp._tcp_id INNER JOIN udp ON ulog2._id = udp._udp_id
                INNER JOIN icmp ON ulog2._id = icmp._icmp_id INNER JOIN mac ON ulog2._id = mac._mac_id;

-- shortcuts
CREATE OR REPLACE VIEW view_tcp_quad AS
        SELECT ulog2._id,ulog2.ip_saddr_str,tcp.tcp_sport,ulog2.ip_daddr_str,tcp.tcp_dport FROM ulog2 INNER JOIN tcp ON ulog2._id = tcp._tcp_id;

CREATE OR REPLACE VIEW view_udp_quad AS
        SELECT ulog2._id,ulog2.ip_saddr_str,udp.udp_sport,ulog2.ip_daddr_str,udp.udp_dport FROM ulog2 INNER JOIN udp ON ulog2._id = udp._udp_id;

-- 
-- conntrack
-- 
DROP SEQUENCE IF EXISTS ulog2_ct__ct_id_seq;
CREATE SEQUENCE ulog2_ct__ct_id_seq;
CREATE TABLE ulog2_ct (
  _ct_id bigint PRIMARY KEY UNIQUE NOT NULL DEFAULT nextval('ulog2_ct__ct_id_seq'),
  orig_ip_saddr_str inet default NULL,
  orig_ip_daddr_str inet default NULL,
  orig_ip_protocol smallint default NULL,
  orig_l4_sport integer default NULL,
  orig_l4_dport integer default NULL,
  orig_bytes bigint default 0,
  orig_packets bigint default 0,
  reply_ip_saddr_str inet default NULL,
  reply_ip_daddr_str inet default NULL,
  reply_ip_protocol smallint default NULL,
  reply_l4_sport integer default NULL,
  reply_l4_dport integer default NULL,
  reply_bytes bigint default 0,
  reply_packets bigint default 0,
  icmp_code smallint default NULL,
  icmp_type smallint default NULL,
  ct_mark bigint default 0,
  flow_start_sec integer default 0,
  flow_start_usec integer default 0,
  flow_end_sec integer default 0,
  flow_end_usec integer default 0,
  state smallint default 0
) WITH (OIDS=FALSE);

CREATE INDEX ulog2_ct_orig_ip_saddr ON ulog2_ct(orig_ip_saddr_str);
CREATE INDEX ulog2_ct_orig_ip_daddr ON ulog2_ct(orig_ip_daddr_str);
CREATE INDEX ulog2_ct_reply_ip_saddr ON ulog2_ct(reply_ip_saddr_str);
CREATE INDEX ulog2_ct_reply_ip_daddr ON ulog2_ct(reply_ip_daddr_str);
CREATE INDEX ulog2_ct_orig_l4_sport ON ulog2_ct(orig_l4_sport);
CREATE INDEX ulog2_ct_orig_l4_dport ON ulog2_ct(orig_l4_dport);
CREATE INDEX ulog2_ct_reply_l4_sport ON ulog2_ct(reply_l4_sport);
CREATE INDEX ulog2_ct_reply_l4_dport ON ulog2_ct(reply_l4_dport);
CREATE INDEX ulog2_ct_state ON ulog2_ct(state);

ALTER TABLE ulog2_ct ADD CONSTRAINT orig_l4_sport CHECK(orig_l4_sport >= 0 AND orig_l4_sport <= 65536);
ALTER TABLE ulog2_ct ADD CONSTRAINT orig_l4_dport CHECK(orig_l4_dport >= 0 AND orig_l4_dport <= 65536);
ALTER TABLE ulog2_ct ADD CONSTRAINT reply_l4_sport CHECK(reply_l4_sport >= 0 AND reply_l4_sport <= 65536);
ALTER TABLE ulog2_ct ADD CONSTRAINT reply_l4_dport CHECK(reply_l4_dport >= 0 AND reply_l4_dport <= 65536);

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


CREATE OR REPLACE FUNCTION INSERT_IP_PACKET(
                IN oob_time_sec integer,
                IN oob_time_usec integer,
                IN oob_prefix varchar(32),
                IN oob_mark integer,
                IN oob_in varchar(32),
                IN oob_out varchar(32),
                IN ip_saddr_str inet,
                IN ip_daddr_str inet,
                IN ip_protocol smallint
        )
RETURNS bigint AS $$
        INSERT INTO ulog2 (oob_time_sec,oob_time_usec,oob_prefix,oob_mark,
                        oob_in,oob_out,ip_saddr_str,ip_daddr_str,ip_protocol)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9);
        SELECT currval('ulog2__id_seq');
$$ LANGUAGE SQL SECURITY INVOKER;


CREATE OR REPLACE FUNCTION INSERT_IP_PACKET_FULL(
                IN oob_time_sec integer,
                IN oob_time_usec integer,
                IN oob_prefix varchar(32),
                IN oob_mark integer,
                IN oob_in varchar(32),
                IN oob_out varchar(32),
                IN ip_saddr_str inet,
                IN ip_daddr_str inet,
                IN ip_protocol smallint,
                IN ip_tos smallint,
                IN ip_ttl smallint,
                IN ip_totlen smallint,
                IN ip_ihl smallint,
                IN ip_csum smallint,
                IN ip_id smallint,
                IN ip_fragoff smallint
        )
RETURNS bigint AS $$
        INSERT INTO ulog2 (oob_time_sec,oob_time_usec,oob_prefix,oob_mark,
                        oob_in,oob_out,ip_saddr_str,ip_daddr_str,ip_protocol,
                        ip_tos,ip_ttl,ip_totlen,ip_ihl,ip_csum,ip_id,ip_fragoff)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16);
        SELECT currval('ulog2__id_seq');
$$ LANGUAGE SQL SECURITY INVOKER;

CREATE OR REPLACE FUNCTION INSERT_TCP_FULL(
                IN tcp_id bigint,
                IN tcp_sport integer,
                IN tcp_dport integer,
                IN tcp_seq integer,
                IN tcp_ackseq integer,
                IN tcp_window smallint,
                IN tcp_urg smallint,
                IN tcp_urgp smallint ,
                IN tcp_ack smallint,
                IN tcp_psh smallint,
                IN tcp_rst smallint,
                IN tcp_syn smallint,
                IN tcp_fin smallint
        )
RETURNS bigint AS $$
        INSERT INTO tcp (_tcp_id,tcp_sport,tcp_dport,tcp_seq,tcp_ackseq,tcp_window,tcp_urg,
                        tcp_urgp,tcp_ack,tcp_psh,tcp_rst,tcp_syn,tcp_fin)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13);
        SELECT currval('ulog2__id_seq');
$$ LANGUAGE SQL SECURITY INVOKER;

CREATE OR REPLACE FUNCTION INSERT_UDP(
                IN tcp_id bigint,
                IN tcp_sport integer,
                IN tcp_dport integer,
                IN tcp_len smallint
        )
RETURNS bigint AS $$
        INSERT INTO udp (_udp_id,udp_sport,udp_dport,udp_len)
                VALUES ($1,$2,$3,$4);
        SELECT currval('ulog2__id_seq');
$$ LANGUAGE SQL SECURITY INVOKER;

CREATE OR REPLACE FUNCTION INSERT_ICMP(
                IN icmp_id bigint,
                IN icmp_type smallint,
                IN icmp_code smallint,
                IN icmp_echoid smallint,
                IN icmp_echoseq smallint,
                IN icmp_gateway integer,
                IN icmp_fragmtu smallint 
        )
RETURNS bigint AS $$
        INSERT INTO icmp (_icmp_id,icmp_type,icmp_code,icmp_echoid,icmp_echoseq,icmp_gateway,icmp_fragmtu)
                VALUES ($1,$2,$3,$4,$5,$6,$7);
        SELECT currval('ulog2__id_seq');
$$ LANGUAGE SQL SECURITY INVOKER;

CREATE OR REPLACE FUNCTION INSERT_MAC(
                IN tcp_id bigint,
                IN udp_sport integer,
                IN udp_dport integer,
                IN udp_len smallint
        )
RETURNS bigint AS $$
        INSERT INTO udp (_udp_id,udp_sport,udp_dport,udp_len)
                VALUES ($1,$2,$3,$4);
        SELECT currval('ulog2__id_seq');
$$ LANGUAGE SQL SECURITY INVOKER;

-- this function requires plpgsql
-- su -c "createlang plpgsql ulog2" postgres
CREATE OR REPLACE FUNCTION INSERT_PACKET_FULL(
                IN oob_time_sec integer,
                IN oob_time_usec integer,
                IN oob_prefix varchar(32),
                IN oob_mark integer,
                IN oob_in varchar(32),
                IN oob_out varchar(32),
                IN ip_saddr_str inet,
                IN ip_daddr_str inet,
                IN ip_protocol smallint,
                IN ip_tos smallint,
                IN ip_ttl smallint,
                IN ip_totlen smallint,
                IN ip_ihl smallint,
                IN ip_csum smallint,
                IN ip_id smallint,
                IN ip_fragoff smallint,
                IN tcp_sport integer,
                IN tcp_dport integer,
                IN tcp_seq integer,
                IN tcp_ackseq integer,
                IN tcp_window smallint,
                IN tcp_urg smallint,
                IN tcp_urgp smallint ,
                IN tcp_ack smallint,
                IN tcp_psh smallint,
                IN tcp_rst smallint,
                IN tcp_syn smallint,
                IN tcp_fin smallint,
                IN udp_sport integer,
                IN udp_dport integer,
                IN udp_len smallint,
                IN icmp_type smallint,
                IN icmp_code smallint,
                IN icmp_echoid smallint,
                IN icmp_echoseq smallint,
                IN icmp_gateway integer,
                IN icmp_fragmtu smallint 
        )
RETURNS bigint AS $$
DECLARE
        _id bigint;
BEGIN
        _id := INSERT_IP_PACKET_FULL($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ;
        IF (ip_protocol = 6) THEN
                SELECT INSERT_TCP_FULL(_id,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28);
        ELSIF (ip_protocol = 17) THEN
                SELECT INSERT_UDP(_id,$29,$30,$31,$32);
        ELSIF (ip_protocol = 1) THEN
                SELECT INSERT_ICMP(_id,$33,$34,$35,$36,$37,$38);
        END IF;
        RETURN _id;
END
$$ LANGUAGE plpgsql SECURITY INVOKER;




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

CREATE OR REPLACE FUNCTION DELETE_CT_FLOW(
                IN _ct_packet_id bigint
        )
RETURNS void AS $$
  -- remember : table with most constraints first
  DELETE FROM ulog2_ct WHERE ulog2_ct._ct_id = $1;
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

-- Pierre Chifflier <chifflier AT inl DOT fr>
