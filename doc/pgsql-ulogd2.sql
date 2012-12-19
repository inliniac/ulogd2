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

INSERT INTO _format (version) VALUES (6);

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
DROP TABLE IF EXISTS hwhdr CASCADE;
DROP TABLE IF EXISTS tcp CASCADE;
DROP TABLE IF EXISTS udp CASCADE;
DROP TABLE IF EXISTS sctp CASCADE;
DROP TABLE IF EXISTS icmp CASCADE;
DROP TABLE IF EXISTS icmpv6 CASCADE;
DROP TABLE IF EXISTS nufw CASCADE;
DROP TABLE IF EXISTS nfacct CASCADE;
DROP TABLE IF EXISTS ulog2_ct CASCADE;
DROP TABLE IF EXISTS ulog2 CASCADE;


DROP SEQUENCE IF EXISTS ulog2__id_seq;
CREATE SEQUENCE ulog2__id_seq;
CREATE TABLE ulog2 (
  _id bigint PRIMARY KEY UNIQUE NOT NULL DEFAULT nextval('ulog2__id_seq'),
  oob_time_sec integer default NULL,
  oob_time_usec integer default NULL,
  oob_hook smallint default NULL,
  oob_prefix varchar(32) default NULL,
  oob_mark integer default NULL,
  oob_in varchar(32) default NULL,
  oob_out varchar(32) default NULL,
  oob_family smallint default NULL,
  ip_saddr_str inet default NULL,
  ip_daddr_str inet default NULL,
  ip_protocol smallint default NULL,
  ip_tos smallint default NULL,
  ip_ttl smallint default NULL,
  ip_totlen smallint default NULL,
  ip_ihl smallint default NULL,
  ip_csum integer default NULL,
  ip_id integer default NULL,
  ip_fragoff smallint default NULL,
  ip6_payloadlen bigint default NULL,
  ip6_priority smallint default NULL,
  ip6_hoplimit smallint default NULL,
  ip6_flowlabel bigint default NULL,
  ip6_fragoff integer default NULL,
  ip6_fragid bigint default NULL,
  label smallint default NULL,
  mac_id bigint default NULL,
  timestamp timestamp NOT NULL default now()
) WITH (OIDS=FALSE);

CREATE INDEX ulog2_oob_family ON ulog2(oob_family);
CREATE INDEX ulog2_ip_saddr ON ulog2(ip_saddr_str);
CREATE INDEX ulog2_ip_daddr ON ulog2(ip_daddr_str);
CREATE INDEX ulog2_timestamp ON ulog2(timestamp);

DROP SEQUENCE IF EXISTS mac__id_seq;
CREATE SEQUENCE mac__id_seq;
CREATE TABLE mac (
  _mac_id bigint PRIMARY KEY UNIQUE NOT NULL DEFAULT nextval('mac__id_seq'),
  mac_saddr macaddr NOT NULL,
  mac_daddr macaddr default NULL,
  mac_protocol integer default NULL
) WITH (OIDS=FALSE);

CREATE INDEX mac_saddr ON mac(mac_saddr);
CREATE INDEX mac_daddr ON mac(mac_daddr);
CREATE UNIQUE INDEX unique_mac ON mac(mac_saddr,mac_daddr,mac_protocol);

CREATE TABLE hwhdr (
  _hw_id bigint PRIMARY KEY UNIQUE NOT NULL,
  raw_type integer default NULL,
  raw_header varchar(256) default NULL
) WITH (OIDS=FALSE);

CREATE INDEX raw_type ON hwhdr(raw_type);
CREATE INDEX raw_header ON hwhdr(raw_header);

CREATE TABLE tcp (
  _tcp_id bigint PRIMARY KEY UNIQUE NOT NULL,
  tcp_sport integer default NULL,
  tcp_dport integer default NULL,
  tcp_seq bigint default NULL,
  tcp_ackseq bigint default NULL,
  tcp_window integer default NULL,
  tcp_urg boolean default NULL,
  tcp_urgp integer  default NULL,
  tcp_ack boolean default NULL,
  tcp_psh boolean default NULL,
  tcp_rst boolean default NULL,
  tcp_syn boolean default NULL,
  tcp_fin boolean default NULL
) WITH (OIDS=FALSE);

CREATE INDEX tcp_sport ON tcp(tcp_sport);
CREATE INDEX tcp_dport ON tcp(tcp_dport);

CREATE TABLE udp (
  _udp_id bigint PRIMARY KEY UNIQUE NOT NULL,
  udp_sport integer default NULL,
  udp_dport integer default NULL,
  udp_len smallint default NULL
) WITH (OIDS=FALSE);

CREATE INDEX udp_sport ON udp(udp_sport);
CREATE INDEX udp_dport ON udp(udp_dport);

CREATE TABLE sctp (
  _sctp_id bigint PRIMARY KEY UNIQUE NOT NULL,
  sctp_sport integer default NULL,
  sctp_dport integer default NULL,
  sctp_csum smallint default NULL
) WITH (OIDS=FALSE);

CREATE INDEX sctp_sport ON sctp(sctp_sport);
CREATE INDEX sctp_dport ON sctp(sctp_dport);

CREATE TABLE icmp (
  _icmp_id bigint PRIMARY KEY UNIQUE NOT NULL,
  icmp_type smallint default NULL,
  icmp_code smallint default NULL,
  icmp_echoid integer default NULL,
  icmp_echoseq integer default NULL,
  icmp_gateway integer default NULL,
  icmp_fragmtu smallint  default NULL
) WITH (OIDS=FALSE);

CREATE TABLE icmpv6 (
  _icmpv6_id bigint PRIMARY KEY UNIQUE NOT NULL,
  icmpv6_type smallint default NULL,
  icmpv6_code smallint default NULL,
  icmpv6_echoid integer default NULL,
  icmpv6_echoseq integer default NULL,
  icmpv6_csum integer default NULL
) WITH (OIDS=FALSE);

CREATE TABLE nfacct (
  sum_name varchar(128),
  sum_pkts integer default 0,
  sum_bytes integer default 0,
  oob_time_sec integer default NULL,
  oob_time_usec integer default NULL
) WITH (OIDS=FALSE);

CREATE UNIQUE INDEX unique_acct ON nfacct(sum_name, oob_time_sec, oob_time_usec);

-- 
-- VIEWS
-- 

CREATE OR REPLACE VIEW view_tcp AS
        SELECT * FROM ulog2 INNER JOIN tcp ON ulog2._id = tcp._tcp_id;

CREATE OR REPLACE VIEW view_udp AS
        SELECT * FROM ulog2 INNER JOIN udp ON ulog2._id = udp._udp_id;

CREATE OR REPLACE VIEW view_icmp AS
        SELECT * FROM ulog2 INNER JOIN icmp ON ulog2._id = icmp._icmp_id;

CREATE OR REPLACE VIEW view_icmpv6 AS
        SELECT * FROM ulog2 INNER JOIN icmpv6 ON ulog2._id = icmpv6._icmpv6_id;

-- complete view
CREATE OR REPLACE VIEW ulog AS
        SELECT _id,
        oob_time_sec,
        oob_time_usec,
        oob_hook,
        oob_prefix,
        oob_mark,
        oob_in,
        oob_out,
        oob_family,
        ip_saddr_str,
        ip_daddr_str,
        ip_protocol,
        ip_tos,
        ip_ttl,
        ip_totlen,
        ip_ihl,
        ip_csum,
        ip_id,
        ip_fragoff,
        ip6_payloadlen,
        ip6_priority,
        ip6_hoplimit,
        ip6_flowlabel,
        ip6_fragoff,
        ip6_fragid,
        tcp_sport,
        tcp_dport,
        tcp_seq,
        tcp_ackseq,
        tcp_window,
        tcp_urg,
        tcp_urgp,
        tcp_ack,
        tcp_psh,
        tcp_rst,
        tcp_syn,
        tcp_fin,
        udp_sport,
        udp_dport,
        udp_len,
        icmp_type,
        icmp_code,
        icmp_echoid,
        icmp_echoseq,
        icmp_gateway,
        icmp_fragmtu,
        icmpv6_type,
        icmpv6_code,
        icmpv6_echoid,
        icmpv6_echoseq,
        icmpv6_csum,
        raw_type,
        raw_header AS mac_str,
        mac_saddr AS mac_saddr_str,
        mac_daddr AS mac_daddr_str,
        mac_protocol AS oob_protocol,
        label AS raw_label,
        sctp_sport,
        sctp_dport,
        sctp_csum
        FROM ulog2 LEFT JOIN tcp ON ulog2._id = tcp._tcp_id LEFT JOIN udp ON ulog2._id = udp._udp_id
                LEFT JOIN sctp ON ulog2._id = sctp._sctp_id
                LEFT JOIN icmp ON ulog2._id = icmp._icmp_id
                LEFT JOIN mac ON ulog2.mac_id = mac._mac_id
                LEFT JOIN hwhdr ON ulog2._id = hwhdr._hw_id
                LEFT JOIN icmpv6 ON ulog2._id = icmpv6._icmpv6_id;

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
  oob_family smallint default NULL,
  orig_ip_saddr_str inet default NULL,
  orig_ip_daddr_str inet default NULL,
  orig_ip_protocol smallint default NULL,
  orig_l4_sport integer default NULL,
  orig_l4_dport integer default NULL,
  orig_raw_pktlen bigint default 0,
  orig_raw_pktcount bigint default 0,
  reply_ip_saddr_str inet default NULL,
  reply_ip_daddr_str inet default NULL,
  reply_ip_protocol smallint default NULL,
  reply_l4_sport integer default NULL,
  reply_l4_dport integer default NULL,
  reply_raw_pktlen bigint default 0,
  reply_raw_pktcount bigint default 0,
  icmp_code smallint default NULL,
  icmp_type smallint default NULL,
  ct_mark bigint default 0,
  flow_start_sec bigint default 0,
  flow_start_usec bigint default 0,
  flow_end_sec bigint default 0,
  flow_end_usec bigint default 0,
  ct_event smallint default 0
) WITH (OIDS=FALSE);

CREATE INDEX ulog2_ct_oob_family ON ulog2_ct(oob_family);
CREATE INDEX ulog2_ct_orig_ip_saddr ON ulog2_ct(orig_ip_saddr_str);
CREATE INDEX ulog2_ct_orig_ip_daddr ON ulog2_ct(orig_ip_daddr_str);
CREATE INDEX ulog2_ct_reply_ip_saddr ON ulog2_ct(reply_ip_saddr_str);
CREATE INDEX ulog2_ct_reply_ip_daddr ON ulog2_ct(reply_ip_daddr_str);
CREATE INDEX ulog2_ct_orig_l4_sport ON ulog2_ct(orig_l4_sport);
CREATE INDEX ulog2_ct_orig_l4_dport ON ulog2_ct(orig_l4_dport);
CREATE INDEX ulog2_ct_reply_l4_sport ON ulog2_ct(reply_l4_sport);
CREATE INDEX ulog2_ct_reply_l4_dport ON ulog2_ct(reply_l4_dport);
CREATE INDEX ulog2_ct_event ON ulog2_ct(ct_event);

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
        (132,'sctp','Stream Control Transmission Protocol'),
        (58,'ipv6-icmp','ICMP for IPv6');

-- 
-- NuFW specific
-- 

DROP TABLE IF EXISTS nufw;
CREATE TABLE nufw (
  _nufw_id bigint PRIMARY KEY UNIQUE NOT NULL,
  username varchar(30) default NULL,
  user_id integer default NULL,
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
  ALTER TABLE ulog2 DROP CONSTRAINT mac_id_fk;
  ALTER TABLE icmpv6 DROP CONSTRAINT icmpv6_id_fk;
  ALTER TABLE icmp DROP CONSTRAINT icmp_id_fk;
  ALTER TABLE udp  DROP CONSTRAINT udp_id_fk;
  ALTER TABLE tcp  DROP CONSTRAINT tcp_id_fk;
$$ LANGUAGE SQL SECURITY INVOKER;


CREATE OR REPLACE FUNCTION ULOG2_ADD_FOREIGN_KEYS()
RETURNS void AS $$
  ALTER TABLE tcp  ADD CONSTRAINT tcp_id_fk  FOREIGN KEY (_tcp_id)  REFERENCES ulog2(_id);
  ALTER TABLE udp  ADD CONSTRAINT udp_id_fk  FOREIGN KEY (_udp_id)  REFERENCES ulog2(_id);
  ALTER TABLE sctp  ADD CONSTRAINT sctp_id_fk  FOREIGN KEY (_sctp_id)  REFERENCES ulog2(_id);
  ALTER TABLE icmp ADD CONSTRAINT icmp_id_fk FOREIGN KEY (_icmp_id) REFERENCES ulog2(_id);
  ALTER TABLE icmpv6 ADD CONSTRAINT icmpv6_id_fk FOREIGN KEY (_icmpv6_id) REFERENCES ulog2(_id);
  ALTER TABLE ulog2 ADD CONSTRAINT mac_id_fk FOREIGN KEY (mac_id) REFERENCES mac(_mac_id);
$$ LANGUAGE SQL SECURITY INVOKER;


CREATE OR REPLACE FUNCTION INSERT_IP_PACKET(
                IN oob_time_sec integer,
                IN oob_time_usec integer,
                IN oob_prefix varchar(32),
                IN oob_mark integer,
                IN oob_in varchar(32),
                IN oob_out varchar(32),
                IN oob_family integer,
                IN ip_saddr_str inet,
                IN ip_daddr_str inet,
                IN ip_protocol integer
        )
RETURNS bigint AS $$
        INSERT INTO ulog2 (oob_time_sec,oob_time_usec,oob_prefix,oob_mark,
                        oob_in,oob_out,oob_family,ip_saddr_str,ip_daddr_str,ip_protocol)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,10);
        SELECT currval('ulog2__id_seq');
$$ LANGUAGE SQL SECURITY INVOKER;


CREATE OR REPLACE FUNCTION INSERT_IP_PACKET_FULL(
                IN oob_time_sec integer,
                IN oob_time_usec integer,
                IN oob_hook integer,
                IN oob_prefix varchar(32),
                IN oob_mark integer,
                IN oob_in varchar(32),
                IN oob_out varchar(32),
                IN oob_family integer,
                IN ip_saddr_str inet,
                IN ip_daddr_str inet,
                IN ip_protocol integer,
                IN ip_tos integer,
                IN ip_ttl integer,
                IN ip_totlen integer,
                IN ip_ihl integer,
                IN ip_csum integer,
                IN ip_id integer,
                IN ip_fragoff integer,
                IN ip6_payloadlen integer,
                IN ip6_priority integer,
                IN ip6_hoplimit integer,
                IN ip6_flowlabel bigint,
                IN ip6_fragoff integer,
                IN ip6_fragid bigint,
                IN label integer
        )
RETURNS bigint AS $$
        INSERT INTO ulog2 (oob_time_sec,oob_time_usec,oob_hook,oob_prefix,oob_mark,
                        oob_in,oob_out,oob_family,ip_saddr_str,ip_daddr_str,ip_protocol,
                        ip_tos,ip_ttl,ip_totlen,ip_ihl,ip_csum,ip_id,ip_fragoff,
                        ip6_payloadlen,ip6_priority,ip6_hoplimit,ip6_flowlabel,
                        ip6_fragoff,ip6_fragid,label)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25);
        SELECT currval('ulog2__id_seq');
$$ LANGUAGE SQL SECURITY INVOKER;

CREATE OR REPLACE FUNCTION INSERT_TCP_FULL(
                IN tcp_id bigint,
                IN tcp_sport integer,
                IN tcp_dport integer,
                IN tcp_seq bigint,
                IN tcp_ackseq bigint,
                IN tcp_window integer,
                IN tcp_urg boolean,
                IN tcp_urgp integer ,
                IN tcp_ack boolean,
                IN tcp_psh boolean,
                IN tcp_rst boolean,
                IN tcp_syn boolean,
                IN tcp_fin boolean
        )
RETURNS bigint AS $$
        INSERT INTO tcp (_tcp_id,tcp_sport,tcp_dport,tcp_seq,tcp_ackseq,tcp_window,tcp_urg,
                        tcp_urgp,tcp_ack,tcp_psh,tcp_rst,tcp_syn,tcp_fin)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13);
        SELECT currval('ulog2__id_seq');
$$ LANGUAGE SQL SECURITY INVOKER;

CREATE OR REPLACE FUNCTION INSERT_UDP(
                IN udp_id bigint,
                IN udp_sport integer,
                IN udp_dport integer,
                IN udp_len integer
        )
RETURNS bigint AS $$
        INSERT INTO udp (_udp_id,udp_sport,udp_dport,udp_len)
                VALUES ($1,$2,$3,$4);
        SELECT currval('ulog2__id_seq');
$$ LANGUAGE SQL SECURITY INVOKER;

CREATE OR REPLACE FUNCTION INSERT_SCTP(
                IN sctp_id bigint,
                IN sctp_sport integer,
                IN sctp_dport integer,
                IN sctp_csum integer
        )
RETURNS bigint AS $$
        INSERT INTO sctp (_sctp_id,sctp_sport,sctp_dport,sctp_csum)
                VALUES ($1,$2,$3,$4);
        SELECT currval('ulog2__id_seq');
$$ LANGUAGE SQL SECURITY INVOKER;

CREATE OR REPLACE FUNCTION INSERT_ICMP(
                IN icmp_id bigint,
                IN icmp_type integer,
                IN icmp_code integer,
                IN icmp_echoid integer,
                IN icmp_echoseq integer,
                IN icmp_gateway integer,
                IN icmp_fragmtu integer 
        )
RETURNS bigint AS $$
        INSERT INTO icmp (_icmp_id,icmp_type,icmp_code,icmp_echoid,icmp_echoseq,icmp_gateway,icmp_fragmtu)
                VALUES ($1,$2,$3,$4,$5,$6,$7);
        SELECT currval('ulog2__id_seq');
$$ LANGUAGE SQL SECURITY INVOKER;

CREATE OR REPLACE FUNCTION INSERT_ICMPV6(
                IN icmpv6_id bigint,
                IN icmpv6_type integer,
                IN icmpv6_code integer,
                IN icmpv6_echoid integer,
                IN icmpv6_echoseq integer,
                IN icmpv6_csum integer
        )
RETURNS bigint AS $$
        INSERT INTO icmpv6 (_icmpv6_id,icmpv6_type,icmpv6_code,icmpv6_echoid,icmpv6_echoseq,icmpv6_csum)
                VALUES ($1,$2,$3,$4,$5,$6);
        SELECT currval('ulog2__id_seq');
$$ LANGUAGE SQL SECURITY INVOKER;

CREATE OR REPLACE FUNCTION INSERT_HARDWARE_HEADER(
                IN hw_id bigint,
                IN hw_type integer,
                IN hw_addr varchar(256)
        )
RETURNS bigint AS $$
        INSERT INTO hwhdr (_hw_id,raw_type,raw_header)
                VALUES ($1,$2,$3);
        SELECT currval('ulog2__id_seq');
$$ LANGUAGE SQL SECURITY INVOKER;

CREATE OR REPLACE FUNCTION INSERT_OR_SELECT_MAC(
                IN in_mac_saddr macaddr,
                IN in_mac_daddr macaddr,
                IN in_mac_protocol integer
        )
RETURNS bigint AS $$
DECLARE
        _id bigint;
BEGIN
        IF $2 IS NULL THEN
                SELECT INTO _id _mac_id FROM mac WHERE mac_saddr = $1 AND mac_daddr IS NULL AND mac_protocol = $3;
        ELSE
                SELECT INTO _id _mac_id FROM mac WHERE mac_saddr = $1 AND mac_daddr = $2 AND mac_protocol = $3;
        END IF;
        IF NOT FOUND THEN
                INSERT INTO mac (mac_saddr,mac_daddr,mac_protocol) VALUES ($1,$2,$3) RETURNING _mac_id INTO _id;
                RETURN _id;
        END IF;
        RETURN _id;
END
$$ LANGUAGE plpgsql SECURITY INVOKER;

-- this function requires plpgsql
-- su -c "createlang plpgsql ulog2" postgres
CREATE OR REPLACE FUNCTION INSERT_PACKET_FULL(
                IN oob_time_sec integer,
                IN oob_time_usec integer,
                IN oob_hook integer,
                IN oob_prefix varchar(32),
                IN oob_mark integer,
                IN oob_in varchar(32),
                IN oob_out varchar(32),
                IN oob_family integer,
                IN ip_saddr_str inet,
                IN ip_daddr_str inet,
                IN ip_protocol integer,
                IN ip_tos integer,
                IN ip_ttl integer,
                IN ip_totlen integer,
                IN ip_ihl integer,
                IN ip_csum integer,
                IN ip_id integer,
                IN ip_fragoff integer,
                IN ip6_payloadlen integer,
                IN ip6_priority integer,
                IN ip6_hoplimit integer,
                IN ip6_flowlabel bigint,
                IN ip6_fragoff integer,
                IN ip6_fragid bigint,
                IN tcp_sport integer,
                IN tcp_dport integer,
                IN tcp_seq bigint,
                IN tcp_ackseq bigint,
                IN tcp_window integer,
                IN tcp_urg boolean,
                IN tcp_urgp integer ,
                IN tcp_ack boolean,
                IN tcp_psh boolean,
                IN tcp_rst boolean,
                IN tcp_syn boolean,
                IN tcp_fin boolean,
                IN udp_sport integer,
                IN udp_dport integer,
                IN udp_len integer,
                IN icmp_type integer,
                IN icmp_code integer,
                IN icmp_echoid integer,
                IN icmp_echoseq integer,
                IN icmp_gateway integer,
                IN icmp_fragmtu integer,
                IN icmpv6_type integer,
                IN icmpv6_code integer,
                IN icmpv6_echoid integer,
                IN icmpv6_echoseq integer,
                IN icmpv6_csum integer,
                IN raw_type integer,
                IN raw_header varchar(256),
                IN mac_saddr varchar(32),
                IN mac_daddr varchar(32),
                IN mac_protocol integer,
                IN label integer,
                IN sctp_sport integer,
                IN sctp_dport integer,
                IN sctp_csum integer
        )
RETURNS bigint AS $$
DECLARE
        t_id bigint;
        t_mac_id bigint;
BEGIN
        t_id := INSERT_IP_PACKET_FULL($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$56);
        IF (ip_protocol = 6) THEN
                PERFORM INSERT_TCP_FULL(t_id,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36);
        ELSIF (ip_protocol = 17) THEN
                PERFORM INSERT_UDP(t_id,$37,$38,$39);
        ELSIF (ip_protocol = 132) THEN
                PERFORM INSERT_SCTP(t_id,$57,$58,$59);
        ELSIF (ip_protocol = 1) THEN
                PERFORM INSERT_ICMP(t_id,$40,$41,$42,$43,$44,$45);
        ELSIF (ip_protocol = 58) THEN
                PERFORM INSERT_ICMPV6(t_id,$46,$47,$48,$49,$50);
        END IF;
        IF (raw_type = 1) THEN
                t_mac_id = INSERT_OR_SELECT_MAC($53::macaddr,$54::macaddr,$55);
                UPDATE ulog2 SET mac_id = t_mac_id WHERE _id = t_id;
        ELSE
                PERFORM INSERT_HARDWARE_HEADER(t_id,$51,$52);
        END IF;
        RETURN t_id;
END
$$ LANGUAGE plpgsql SECURITY INVOKER;




CREATE OR REPLACE FUNCTION INSERT_CT(
                IN _oob_family integer,
                IN _orig_ip_saddr inet,
                IN _orig_ip_daddr inet,
                IN _orig_ip_protocol integer,
                IN _orig_l4_sport integer,
                IN _orig_l4_dport integer,
                IN _orig_raw_pktlen bigint,
                IN _orig_raw_pktcount bigint,
                IN _reply_ip_saddr inet,
                IN _reply_ip_daddr inet,
                IN _reply_ip_protocol integer,
                IN _reply_l4_sport integer,
                IN _reply_l4_dport integer,
                IN _reply_raw_pktlen bigint,
                IN _reply_raw_pktcount bigint,
                IN _icmp_code integer,
                IN _icmp_type integer,
                IN _ct_mark bigint,
                IN _flow_start_sec bigint,
                IN _flow_start_usec bigint,
                IN _flow_end_sec bigint,
                IN _flow_end_usec bigint,
                IN _ct_event integer
        )
RETURNS bigint AS $$
        INSERT INTO ulog2_ct (oob_family, orig_ip_saddr_str, orig_ip_daddr_str, orig_ip_protocol,
                        orig_l4_sport, orig_l4_dport, orig_raw_pktlen, orig_raw_pktcount,
                        reply_ip_saddr_str, reply_ip_daddr_str, reply_ip_protocol,
                        reply_l4_sport, reply_l4_dport, reply_raw_pktlen, reply_raw_pktcount,
                        icmp_code, icmp_type, ct_mark, 
                        flow_start_sec, flow_start_usec,
                        flow_end_sec, flow_end_usec, ct_event)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23);
        SELECT currval('ulog2_ct__ct_id_seq');
$$ LANGUAGE SQL SECURITY INVOKER;

CREATE OR REPLACE FUNCTION INSERT_OR_REPLACE_CT(
                IN _oob_family integer,
                IN _orig_ip_saddr inet,
                IN _orig_ip_daddr inet,
                IN _orig_ip_protocol integer,
                IN _orig_l4_sport integer,
                IN _orig_l4_dport integer,
                IN _orig_raw_pktlen bigint,
                IN _orig_raw_pktcount bigint,
                IN _reply_ip_saddr inet,
                IN _reply_ip_daddr inet,
                IN _reply_ip_protocol integer,
                IN _reply_l4_sport integer,
                IN _reply_l4_dport integer,
                IN _reply_raw_pktlen bigint,
                IN _reply_raw_pktcount bigint,
                IN _icmp_code integer,
                IN _icmp_type integer,
                IN _ct_mark bigint,
                IN _flow_start_sec bigint,
                IN _flow_start_usec bigint,
                IN _flow_end_sec bigint,
                IN _flow_end_usec bigint,
                IN _ct_event integer
        )
RETURNS bigint AS $$
DECLARE
        _id bigint;
BEGIN
        IF (_ct_event = 4) THEN
          if (_orig_ip_protocol = 1) THEN
            UPDATE ulog2_ct SET (orig_raw_pktlen, orig_raw_pktcount,
                reply_raw_pktlen, reply_raw_pktcount,
                ct_mark, flow_end_sec, flow_end_usec, ct_event)
                = ($7,$8,$14,$15,$18,$21,$22,$23)
            WHERE oob_family=$1 AND orig_ip_saddr_str = $2
                AND orig_ip_daddr_str = $3 AND orig_ip_protocol = $4
                AND reply_ip_saddr_str = $9 AND reply_ip_daddr_str = $10
                AND reply_ip_protocol = $11
                AND icmp_code = $16 AND icmp_type = $17 
                AND ct_event < 4;
          ELSE
            UPDATE ulog2_ct SET (orig_raw_pktlen, orig_raw_pktcount,
                reply_raw_pktlen, reply_raw_pktcount,
                ct_mark, flow_end_sec, flow_end_usec, ct_event)
                = ($7,$8,$14,$15,$18,$21,$22,$23)
            WHERE oob_family=$1 AND orig_ip_saddr_str = $2
                AND orig_ip_daddr_str = $3 AND orig_ip_protocol = $4
                AND orig_l4_sport = $5 AND orig_l4_dport = $6
                AND reply_ip_saddr_str = $9 AND reply_ip_daddr_str = $10
                AND reply_ip_protocol = $11 AND reply_l4_sport = $12
                AND reply_l4_dport = $13 
                AND ct_event < 4;
          END IF;
        ELSE
          _id := INSERT_CT($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23);
        END IF;
        RETURN _id;
END
$$ LANGUAGE plpgsql SECURITY INVOKER;


CREATE OR REPLACE FUNCTION INSERT_NFACCT(
                IN sum_name varchar(128),
                IN sum_pkts integer,
                IN sum_bytes integer,
                IN oob_time_sec integer,
                IN oob_time_usec integer
        )
RETURNS void AS $$
        INSERT INTO nfacct (sum_name,sum_pkts,sum_bytes,oob_time_sec,oob_time_usec)
                VALUES ($1,$2,$3,$4,$5);
$$ LANGUAGE SQL SECURITY INVOKER;


CREATE OR REPLACE FUNCTION DELETE_PACKET(
                IN _packet_id bigint
        )
RETURNS void AS $$
  -- remember : table with most constraints first
  DELETE FROM icmp  WHERE icmp._icmp_id = $1;
  DELETE FROM tcp   WHERE tcp._tcp_id   = $1;
  DELETE FROM udp   WHERE udp._udp_id   = $1;
  DELETE FROM sctp   WHERE sctp._sctp_id   = $1;
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
  DELETE FROM sctp WHERE _sctp_id NOT IN (SELECT _id FROM ulog2);
  DELETE FROM icmp WHERE _icmp_id NOT IN (SELECT _id FROM ulog2);
  -- look for packets in table ulog2 with proto tcp (or ipv6 ?) and not in table tcp
  DELETE FROM ulog2 WHERE ulog2.ip_protocol = '6' AND _id NOT IN (SELECT _tcp_id FROM tcp);
  DELETE FROM ulog2 WHERE ulog2.ip_protocol = '17' AND _id NOT IN (SELECT _udp_id FROM udp);
  DELETE FROM ulog2 WHERE ulog2.ip_protocol = '132' AND _id NOT IN (SELECT _sctp_id FROM sctp);
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
