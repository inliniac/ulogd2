-- vi: et ai ts=2
--
-- Warning: postgresql >= 8.2 is required for the 'DROP .. IF EXISTS'
-- Warning: this script DESTROYS EVERYTHING !
--

DROP TABLE IF EXISTS _format;
CREATE TABLE _format (
  version integer
) WITH (OIDS=FALSE);

INSERT INTO _format (version) VALUES (1);

-- this table could be used to know which user-defined tables are linked
-- to ulog
DROP TABLE IF EXISTS _extensions;
CREATE TABLE _extensions (
  ext_id serial PRIMARY KEY UNIQUE NOT NULL,
  ext_name varchar(64) NOT NULL,
  table_name varchar(64) NOT NULL,
  join_name varchar(64) NOT NULL
) WITH (OIDS=FALSE);

DROP TABLE IF EXISTS nufw CASCADE;
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
  raw_label smallint default NULL,
  -- timestamp timestamp NOT NULL default 'now',
  mac_saddr_str macaddr default NULL,
  mac_daddr_str macaddr default NULL,
  oob_protocol integer default NULL,
  raw_type integer default NULL,
  mac_str varchar(256) default NULL,
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
  tcp_fin boolean default NULL,
  udp_sport integer default NULL,
  udp_dport integer default NULL,
  udp_len smallint default NULL,
  sctp_sport integer default NULL,
  sctp_dport integer default NULL,
  sctp_csum smallint default NULL,
  icmp_type smallint default NULL,
  icmp_code smallint default NULL,
  icmp_echoid integer default NULL,
  icmp_echoseq integer default NULL,
  icmp_gateway integer default NULL,
  icmp_fragmtu smallint  default NULL,
  icmpv6_type smallint default NULL,
  icmpv6_code smallint default NULL,
  icmpv6_echoid integer default NULL,
  icmpv6_echoseq integer default NULL,
  icmpv6_csum integer default NULL
) WITH (OIDS=FALSE);

CREATE INDEX ulog2_oob_family ON ulog2(oob_family);
CREATE INDEX ulog2_ip_saddr ON ulog2(ip_saddr_str);
CREATE INDEX ulog2_ip_daddr ON ulog2(ip_daddr_str);
-- CREATE INDEX ulog2_timestamp ON ulog2(timestamp);

CREATE INDEX mac_saddr ON ulog2(mac_saddr_str);
CREATE INDEX mac_daddr ON ulog2(mac_daddr_str);

CREATE INDEX tcp_sport ON ulog2(tcp_sport);
CREATE INDEX tcp_dport ON ulog2(tcp_dport);

CREATE INDEX udp_sport ON ulog2(udp_sport);
CREATE INDEX udp_dport ON ulog2(udp_dport);

CREATE INDEX sctp_sport ON ulog2(sctp_sport);
CREATE INDEX sctp_dport ON ulog2(sctp_dport);

--
-- VIEWS
--

CREATE OR REPLACE VIEW view_tcp AS
        SELECT * FROM ulog2 WHERE ulog2.ip_protocol = 6;

CREATE OR REPLACE VIEW view_udp AS
        SELECT * FROM ulog2 WHERE ulog2.ip_protocol = 17;

CREATE OR REPLACE VIEW view_icmp AS
        SELECT * FROM ulog2 WHERE ulog2.ip_protocol = 1;

CREATE OR REPLACE VIEW view_icmpv6 AS
        SELECT * FROM ulog2 WHERE ulog2.ip_protocol = 58;

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
        mac_str,
        mac_saddr_str,
        mac_daddr_str,
        oob_protocol,
        raw_label,
        sctp_sport,
        sctp_dport,
        sctp_csum
        FROM ulog2;

-- shortcuts
CREATE OR REPLACE VIEW view_tcp_quad AS
        SELECT _id,ip_saddr_str,tcp_sport,ip_daddr_str,tcp_dport FROM ulog2 WHERE ulog2.ip_protocol = 6;

CREATE OR REPLACE VIEW view_udp_quad AS
        SELECT _id,ip_saddr_str,udp_sport,ip_daddr_str,udp_dport FROM ulog2 WHERE ulog2.ip_protocol = 17;

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




CREATE OR REPLACE FUNCTION DELETE_PACKET(
                IN _packet_id bigint
        )
RETURNS void AS $$
  DELETE FROM ulog2 WHERE ulog2._id     = $1;
$$ LANGUAGE SQL SECURITY INVOKER;


CREATE OR REPLACE FUNCTION DELETE_CT_FLOW(
                IN _ct_packet_id bigint
        )
RETURNS void AS $$
  DELETE FROM ulog2_ct WHERE ulog2_ct._ct_id = $1;
$$ LANGUAGE SQL SECURITY INVOKER;





-- Pierre Chifflier <chifflier AT inl DOT fr>
