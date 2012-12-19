
DROP TABLE IF EXISTS `_format`;
CREATE TABLE `_format` (
  `version` int(4) NOT NULL
) ENGINE=INNODB;

INSERT INTO _format (version) VALUES (1);

-- this table could be used to know which user-defined tables are linked
-- to ulog
DROP TABLE IF EXISTS `_extensions`;
CREATE TABLE `_extensions` (
  `ext_id` int(8) unsigned NOT NULL auto_increment,
  `ext_name` varchar(64) NOT NULL,
  `table_name` varchar(64) NOT NULL,
  `join_name` varchar(64) NOT NULL,
  UNIQUE KEY `ext_id` (`ext_id`)
) ENGINE=INNODB;

DROP TABLE IF EXISTS `ulog2_ct`;
DROP TABLE IF EXISTS `state_t`;
DROP TABLE IF EXISTS `nufw`;
DROP TABLE IF EXISTS `ulog2`;

CREATE TABLE `ulog2` (
  `_id` bigint unsigned NOT NULL auto_increment,
  `oob_time_sec` int(10) unsigned default NULL,
  `oob_time_usec` int(10) unsigned default NULL,
  `oob_hook` tinyint(3) unsigned default NULL,
  `oob_prefix` varchar(32) default NULL,
  `oob_mark` int(10) unsigned default NULL,
  `oob_in` varchar(32) default NULL,
  `oob_out` varchar(32) default NULL,
  `oob_family` tinyint(3) unsigned default NULL,
  `ip_saddr_bin` binary(16) default NULL,
  `ip_daddr_bin` binary(16) default NULL,
  `ip_protocol` tinyint(3) unsigned default NULL,
  `ip_tos` tinyint(3) unsigned default NULL,
  `ip_ttl` tinyint(3) unsigned default NULL,
  `ip_totlen` smallint(5) unsigned default NULL,
  `ip_ihl` tinyint(3) unsigned default NULL,
  `ip_csum` smallint(5) unsigned default NULL,
  `ip_id` smallint(5) unsigned default NULL,
  `ip_fragoff` smallint(5) unsigned default NULL,
  `ip6_payloadlen` smallint(5) unsigned default NULL,
  `ip6_priority` tinyint(3) unsigned default NULL,
  `ip6_hoplimit` tinyint(3) unsigned default NULL,
  `ip6_flowlabel` int(10) default NULL,
  `ip6_fragoff` smallint(5) default NULL,
  `ip6_fragid` int(10) unsigned default NULL,
  `raw_label` tinyint(3) unsigned default NULL,
  `mac_saddr_str` varchar(32) default NULL,
  `mac_daddr_str` varchar(32) default NULL,
  `oob_protocol` smallint(5) default NULL,
  `raw_type` int(10) unsigned default NULL,
  `mac_str` varchar(255) default NULL,
  `tcp_sport` int(5) unsigned default NULL,
  `tcp_dport` int(5) unsigned default NULL,
  `tcp_seq` int(10) unsigned default NULL,
  `tcp_ackseq` int(10) unsigned default NULL,
  `tcp_window` int(5) unsigned default NULL,
  `tcp_urg` tinyint(4) default NULL,
  `tcp_urgp` int(5) unsigned default NULL,
  `tcp_ack` tinyint(4) default NULL,
  `tcp_psh` tinyint(4) default NULL,
  `tcp_rst` tinyint(4) default NULL,
  `tcp_syn` tinyint(4) default NULL,
  `tcp_fin` tinyint(4) default NULL,
  `udp_sport` int(5) unsigned default NULL,
  `udp_dport` int(5) unsigned default NULL,
  `udp_len` int(5) unsigned default NULL,
  `sctp_sport` int(5) unsigned default NULL,
  `sctp_dport` int(5) unsigned default NULL,
  `sctp_csum` int(5) unsigned default NULL,
  `icmp_type` tinyint(3) unsigned default NULL,
  `icmp_code` tinyint(3) unsigned default NULL,
  `icmp_echoid` smallint(5) unsigned default NULL,
  `icmp_echoseq` smallint(5) unsigned default NULL,
  `icmp_gateway` int(10) unsigned default NULL,
  `icmp_fragmtu` smallint(5) unsigned default NULL,
  `icmpv6_type` tinyint(3) unsigned default NULL,
  `icmpv6_code` tinyint(3) unsigned default NULL,
  `icmpv6_echoid` smallint(5) unsigned default NULL,
  `icmpv6_echoseq` smallint(5) unsigned default NULL,
  `icmpv6_csum` int(10) unsigned default NULL,
  UNIQUE KEY `key_id` (`_id`)
) ENGINE=INNODB COMMENT='Table for IP packets';

ALTER TABLE ulog2 ADD KEY `oob_family` (`oob_family`);
ALTER TABLE ulog2 ADD KEY `ip_saddr` (`ip_saddr_bin`);
ALTER TABLE ulog2 ADD KEY `ip_daddr` (`ip_daddr_bin`);
-- This index does not seem very useful:
-- ALTER TABLE ulog2 ADD KEY `oob_time_sec` (`oob_time_sec`);

ALTER TABLE ulog2 ADD KEY `mac_saddr` (`mac_saddr_str`);
ALTER TABLE ulog2 ADD KEY `mac_daddr` (`mac_daddr_str`);

ALTER TABLE ulog2 ADD KEY `raw_type` (`raw_type`);
ALTER TABLE ulog2 ADD KEY `raw_header` (`mac_str`);

ALTER TABLE ulog2 ADD KEY `tcp_sport` (`tcp_sport`);
ALTER TABLE ulog2 ADD KEY `tcp_dport` (`tcp_dport`);

ALTER TABLE ulog2 ADD KEY `udp_sport` (`udp_sport`);
ALTER TABLE ulog2 ADD KEY `udp_dport` (`udp_dport`);

ALTER TABLE ulog2 ADD KEY `sctp_sport` (`sctp_sport`);
ALTER TABLE ulog2 ADD KEY `sctp_dport` (`sctp_dport`);



-- views

DROP VIEW IF EXISTS `view_tcp`;
CREATE SQL SECURITY INVOKER VIEW `view_tcp` AS
        SELECT * FROM ulog2 WHERE ulog2.ip_protocol = 6;

DROP VIEW IF EXISTS `view_udp`;
CREATE SQL SECURITY INVOKER VIEW `view_udp` AS
        SELECT * FROM ulog2 WHERE ulog2.ip_protocol = 17;

DROP VIEW IF EXISTS `view_icmp`;
CREATE SQL SECURITY INVOKER VIEW `view_icmp` AS
        SELECT * FROM ulog2 WHERE ulog2.ip_protocol = 1;

DROP VIEW IF EXISTS `view_icmpv6`;
CREATE SQL SECURITY INVOKER VIEW `view_icmpv6` AS
        SELECT * FROM ulog2 WHERE ulog2.ip_protocol = 58;

-- ulog view
DROP VIEW IF EXISTS `ulog`;
-- CREATE SQL SECURITY INVOKER VIEW `ulog` AS
--         SELECT * FROM ulog2 INNER JOIN tcp ON ulog2._id = tcp._tcp_id INNER JOIN udp ON ulog2._id = udp._udp_id
-- 		 INNER JOIN icmp ON ulog2._id = icmp._icmp_id INNER JOIN mac ON ulog2._id = mac._mac_id;
CREATE SQL SECURITY INVOKER VIEW `ulog` AS
        SELECT _id,
        oob_time_sec,
        oob_time_usec,
        oob_hook,
        oob_prefix,
        oob_mark,
        oob_in,
        oob_out,
        oob_family,
        ip_saddr_bin,
        ip_daddr_bin,
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
DROP FUNCTION IF EXISTS BIN_TO_IPV6;
delimiter $$
CREATE FUNCTION BIN_TO_IPV6(
		_in binary(16)
                ) RETURNS varchar(64)
SQL SECURITY INVOKER
DETERMINISTIC
COMMENT 'Convert binary ip to printable string'
BEGIN
	-- IPv4 address in IPv6 form
	IF HEX(SUBSTRING(_in, 1, 12)) = '00000000000000000000FFFF' THEN
		RETURN CONCAT(
			'::ffff:',
			ASCII(SUBSTRING(_in, 13, 1)), '.',
			ASCII(SUBSTRING(_in, 14, 1)), '.',
			ASCII(SUBSTRING(_in, 15, 1)), '.',
			ASCII(SUBSTRING(_in, 16, 1))
		);
	END IF;
	-- return the full IPv6 form
	RETURN LOWER(CONCAT(
		HEX(SUBSTRING(_in,  1, 2)), ':',
		HEX(SUBSTRING(_in,  3, 2)), ':',
		HEX(SUBSTRING(_in,  5, 2)), ':',
		HEX(SUBSTRING(_in,  7, 2)), ':',
		HEX(SUBSTRING(_in,  9, 2)), ':',
		HEX(SUBSTRING(_in, 11, 2)), ':',
		HEX(SUBSTRING(_in, 13, 2)), ':',
		HEX(SUBSTRING(_in, 15, 2))
	));
END
$$
delimiter ;


DROP VIEW IF EXISTS `view_tcp_quad`;
CREATE SQL SECURITY INVOKER VIEW `view_tcp_quad` AS
	SELECT _id,BIN_TO_IPV6(ip_saddr_bin) AS ip_saddr_str,tcp_sport,BIN_TO_IPV6(ip_daddr_bin) AS ip_daddr_str,tcp_dport FROM ulog2 WHERE ulog2.ip_protocol = 6;

DROP VIEW IF EXISTS `view_udp_quad`;
CREATE SQL SECURITY INVOKER VIEW `view_udp_quad` AS
	SELECT _id,BIN_TO_IPV6(ip_saddr_bin) AS ip_saddr_str,udp_sport,BIN_TO_IPV6(ip_daddr_bin) AS ip_daddr_str,udp_dport FROM ulog2 WHERE ulog2.ip_protocol = 17;



-- conntrack

CREATE TABLE `ulog2_ct` (
  `_ct_id` bigint unsigned NOT NULL auto_increment,
  `oob_family` tinyint(3) unsigned default NULL,
  `orig_ip_saddr` binary(16) default NULL,
  `orig_ip_daddr` binary(16) default NULL,
  `orig_ip_protocol` tinyint(3) unsigned default NULL,
  `orig_l4_sport` int(5) default NULL,
  `orig_l4_dport` int(5) default NULL,
  `orig_bytes` bigint default 0,
  `orig_packets` bigint default 0,
  `reply_ip_saddr` binary(16) default NULL,
  `reply_ip_daddr` binary(16) default NULL,
  `reply_ip_protocol` tinyint(3) unsigned default NULL,
  `reply_l4_sport` int(5) default NULL,
  `reply_l4_dport` int(5) default NULL,
  `reply_bytes` bigint default 0,
  `reply_packets` bigint default 0,
  `icmp_code` tinyint(3) default NULL,
  `icmp_type` tinyint(3) default NULL,
  `ct_mark` bigint default 0,
  `flow_start_sec` int(10) default 0,
  `flow_start_usec` int(10) default 0,
  `flow_end_sec` int(10) default 0,
  `flow_end_usec` int(10) default 0,
  `state` tinyint(3) unsigned default 0,
  
  UNIQUE KEY `_ct_id` (`_ct_id`)
) ENGINE=INNODB;

ALTER TABLE ulog2_ct ADD KEY `index_ct_id` (`_ct_id`);
ALTER TABLE ulog2_ct ADD KEY `oob_family` (`oob_family`);
ALTER TABLE ulog2_ct ADD KEY `orig_ip_saddr` (`orig_ip_saddr`);
ALTER TABLE ulog2_ct ADD KEY `orig_ip_daddr` (`orig_ip_daddr`);
ALTER TABLE ulog2_ct ADD KEY `orig_ip_protocol` (`orig_ip_protocol`);
ALTER TABLE ulog2_ct ADD KEY `orig_l4_dport` (`orig_l4_dport`);
ALTER TABLE ulog2_ct ADD KEY `orig_l4_sport` (`orig_l4_sport`);
ALTER TABLE ulog2_ct ADD KEY `reply_ip_saddr` (`reply_ip_saddr`);
ALTER TABLE ulog2_ct ADD KEY `reply_ip_daddr` (`reply_ip_daddr`);
ALTER TABLE ulog2_ct ADD KEY `reply_ip_protocol` (`reply_ip_protocol`);
ALTER TABLE ulog2_ct ADD KEY `reply_l4_dport` (`reply_l4_dport`);
ALTER TABLE ulog2_ct ADD KEY `reply_l4_sport` (`reply_l4_sport`);
ALTER TABLE ulog2_ct ADD KEY `state` (`state`);
ALTER TABLE ulog2_ct ADD KEY `orig_tuple` (`orig_ip_saddr`, `orig_ip_daddr`, `orig_ip_protocol`,
					   `orig_l4_sport`, `orig_l4_dport`);
ALTER TABLE ulog2_ct ADD KEY `reply_tuple` (`reply_ip_saddr`, `reply_ip_daddr`, `reply_ip_protocol`,
					   `reply_l4_sport`, `reply_l4_dport`);

DROP VIEW IF EXISTS `conntrack`;
CREATE SQL SECURITY INVOKER VIEW `conntrack` AS
	SELECT _ct_id,
	       oob_family,
	       orig_ip_saddr AS orig_ip_saddr_bin,
	       orig_ip_daddr AS orig_ip_daddr_bin,
	       orig_ip_protocol,
	       orig_l4_sport,
	       orig_l4_dport,
	       orig_bytes AS orig_raw_pktlen,
	       orig_packets AS orig_raw_pktcount,
	       reply_ip_saddr AS reply_ip_saddr_bin,
	       reply_ip_daddr AS reply_ip_daddr_bin,
	       reply_ip_protocol,
	       reply_l4_sport,
	       reply_l4_dport,
	       reply_bytes AS reply_raw_pktlen,
	       reply_packets AS reply_raw_pktcount,
	       icmp_code,
	       icmp_type,
	       ct_mark,
	       flow_start_sec,
	       flow_start_usec,
	       flow_end_sec,
	       flow_end_usec FROM ulog2_ct WHERE state != 0;

-- Helper table
DROP TABLE IF EXISTS `ip_proto`;
CREATE TABLE `ip_proto` (
  `_proto_id` int(10) unsigned NOT NULL,
  `proto_name` varchar(16) default NULL,
  `proto_desc` varchar(255) default NULL
) ENGINE=INNODB;

ALTER TABLE ip_proto ADD UNIQUE KEY `_proto_id` (`_proto_id`);

-- see files /etc/protocols
-- or /usr/share/nmap/nmap-protocols
INSERT INTO ip_proto (_proto_id,proto_name,proto_desc) VALUES
        (0,'ip','internet protocol, pseudo protocol number'),
        (1,'icmp','internet control message protocol'),
        (2,'igmp','Internet Group Management'),
        (3,'ggp','gateway-gateway protocol'),
        (4,'ipencap','IP encapsulated in IP (officially \'IP\')'),
        (5,'st','ST datagram mode'),
        (6,'tcp','transmission control protocol'),
        (17,'udp','user datagram protocol'),
        (41,'ipv6','Internet Protocol, version 6'),
        (58,'ipv6-icmp','ICMP for IPv6');

-- State
CREATE TABLE `state_t` (
  `_state_id` bigint unsigned NOT NULL,
  state tinyint(3) unsigned
) ENGINE=INNODB;

ALTER TABLE state_t ADD UNIQUE KEY `_state_id` (`_state_id`);
ALTER TABLE state_t ADD KEY `index_state_id` (`_state_id`);
ALTER TABLE state_t ADD KEY `state` (`state`);
ALTER TABLE state_t ADD FOREIGN KEY (_state_id) REFERENCES ulog2 (_id);

INSERT INTO _extensions (ext_name,table_name,join_name) VALUES
        ('state','state_t','_state_id');

-- NuFW specific

DROP TABLE IF EXISTS `nufw`;
CREATE TABLE `nufw` (
  `_nufw_id` bigint unsigned NOT NULL,
  `username` varchar(30) default NULL,
  `user_id` smallint(5) unsigned default NULL,
  `client_os` varchar(100) default NULL,
  `client_app` varchar(256) default NULL
) ENGINE=INNODB;

ALTER TABLE nufw ADD UNIQUE KEY `_nufw_id` (`_nufw_id`);
ALTER TABLE nufw ADD KEY `index_nufw_id` (`_nufw_id`);
ALTER TABLE nufw ADD KEY `user_id` (`user_id`);
ALTER TABLE nufw ADD FOREIGN KEY (_nufw_id) REFERENCES ulog2 (_id);

DROP VIEW IF EXISTS `view_nufw`;
CREATE SQL SECURITY INVOKER VIEW `view_nufw` AS
        SELECT * FROM ulog2 INNER JOIN nufw ON ulog2._id = nufw._nufw_id;

INSERT INTO _extensions (ext_name,table_name,join_name) VALUES
        ('nufw','nufw','_nufw_id');

-- nufw view (nulog)
DROP VIEW IF EXISTS `nulog`;
CREATE SQL SECURITY INVOKER VIEW `nulog` AS
       SELECT * FROM ulog2 
		LEFT JOIN nufw ON ulog2._id = nufw._nufw_id LEFT JOIN state_t ON ulog2._id = state_t._state_id;



-- Procedures


delimiter $$
DROP PROCEDURE IF EXISTS PACKET_ADD_NUFW;
CREATE PROCEDURE PACKET_ADD_NUFW(
		IN `id` int(10) unsigned,
		IN `username` varchar(30),
		IN `user_id` int(10) unsigned,
		IN `client_os` varchar(100),
		IN `client_app` varchar(256),
		IN `socket` smallint(5)
		)
BEGIN
	INSERT INTO nufw (_nufw_id, username, user_id, client_os, client_app, socket) VALUES
	(id, username, user_id, client_os, client_app, socket);
END
$$

delimiter $$
DROP FUNCTION IF EXISTS INSERT_CT;
CREATE FUNCTION INSERT_CT(
		`_oob_family` bigint,
		`_orig_ip_saddr` binary(16),
		`_orig_ip_daddr` binary(16),
		`_orig_ip_protocol` tinyint(3) unsigned,
		`_orig_l4_sport` int(5),
		`_orig_l4_dport` int(5),
		`_orig_bytes` bigint,
		`_orig_packets` bigint,
		`_reply_ip_saddr` binary(16),
		`_reply_ip_daddr` binary(16),
		`_reply_ip_protocol` tinyint(3) unsigned,
		`_reply_l4_sport` int(5),
		`_reply_l4_dport` int(5),
		`_reply_bytes` bigint,
		`_reply_packets` bigint,
		`_icmp_code` tinyint(3),
		`_icmp_type` tinyint(3),
		`_ct_mark` bigint,
		`_flow_start_sec` int(10),
		`_flow_start_usec` int(10),
		`_flow_end_sec` int(10),
		`_flow_end_usec` int(10)
		) RETURNS bigint unsigned
READS SQL DATA
BEGIN
	INSERT INTO ulog2_ct (oob_family, orig_ip_saddr, orig_ip_daddr, orig_ip_protocol,
		orig_l4_sport, orig_l4_dport, orig_bytes, orig_packets,
		reply_ip_saddr, reply_ip_daddr, reply_ip_protocol,
		reply_l4_sport, reply_l4_dport, reply_bytes, reply_packets,
		icmp_code, icmp_type, ct_mark, 
		flow_start_sec, flow_start_usec,
		flow_end_sec, flow_end_usec)
 	VALUES (_oob_family, _orig_ip_saddr, _orig_ip_daddr, _orig_ip_protocol,
		_orig_l4_sport, _orig_l4_dport, _orig_bytes, _orig_packets,
		_reply_ip_saddr, _reply_ip_daddr, _reply_ip_protocol,
		_reply_l4_sport, _reply_l4_dport, _reply_bytes, _reply_packets,
		_icmp_code, _icmp_type, _ct_mark,
		_flow_start_sec, _flow_start_usec,
		_flow_end_sec, _flow_end_usec);
	RETURN LAST_INSERT_ID();
END
$$

delimiter ;

-- suppressing packets
-- better use trigger ?
--   -> a trigger needs super-user access
--   -> triggers on delete does not affect drop tables
DROP PROCEDURE IF EXISTS DELETE_PACKET;
delimiter $$
CREATE PROCEDURE DELETE_PACKET(
		IN _packet_id bigint unsigned
                )
SQL SECURITY INVOKER
COMMENT 'Delete a packet (from ulog tables only)'
BEGIN
        DELETE FROM ulog2 WHERE ulog2._id = _packet_id;
END
$$
delimiter ;


-- suppressing tuples
DROP PROCEDURE IF EXISTS DELETE_CT_FLOW;
delimiter $$
CREATE PROCEDURE DELETE_CT_FLOW(
		IN _ct_packet_id bigint unsigned
                )
SQL SECURITY INVOKER
COMMENT 'Delete a packet from the conntrack tables'
BEGIN
        DELETE FROM ulog2_ct WHERE ulog2_ct._ct_id = _ct_packet_id;
END
$$
delimiter ;


-- Pierre Chifflier <chifflier AT inl DOT fr>

