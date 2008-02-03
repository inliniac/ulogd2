-- general notes:
--  - tables are split using the protocol
--  - keys are created outside the table, when possible
--  - foreign keys (constraints) are added using ULOG2_ADD_FOREIGN_KEYS()
--  - some procedures for maintainance are provided (suppressing entries, compressing tables, running ~VACUUM)
--  - security is set to INVOKER, which means the permissions of the connected client are used. To create an abstraction layer, DEFINER could be used (with precautions on DELETE ..)


-- (most constraint) ulog2_ct >> tcp,udp,icmp >> ulog2 (least constraint)


DROP TABLE IF EXISTS `_format`;
CREATE TABLE `_format` (
  `version` int(4) NOT NULL
) ENGINE=INNODB;

INSERT INTO _format (version) VALUES (3);

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

DROP TABLE IF EXISTS `mac`;
DROP TABLE IF EXISTS `tcp`;
DROP TABLE IF EXISTS `udp`;
DROP TABLE IF EXISTS `icmp`;
DROP TABLE IF EXISTS `nufw`;
DROP TABLE IF EXISTS `ulog2_ct`;
DROP TABLE IF EXISTS `ct_tuple`;
DROP TABLE IF EXISTS `ct_l4`;
DROP TABLE IF EXISTS `ct_icmp`;
DROP TABLE IF EXISTS `ulog2`;

CREATE TABLE `ulog2` (
  `_id` bigint unsigned NOT NULL auto_increment,
  `oob_time_sec` int(10) unsigned default NULL,
  `oob_time_usec` int(10) unsigned default NULL,
  `oob_prefix` varchar(32) default NULL,
  `oob_mark` int(10) unsigned default NULL,
  `oob_in` varchar(32) default NULL,
  `oob_out` varchar(32) default NULL,
  `ip_saddr` binary(16) default NULL,
  `ip_daddr` binary(16) default NULL,
  `ip_protocol` tinyint(3) unsigned default NULL,
  `ip_tos` tinyint(3) unsigned default NULL,
  `ip_ttl` tinyint(3) unsigned default NULL,
  `ip_totlen` smallint(5) unsigned default NULL,
  `ip_ihl` tinyint(3) unsigned default NULL,
  `ip_csum` smallint(5) unsigned default NULL,
  `ip_id` smallint(5) unsigned default NULL,
  `ip_fragoff` smallint(5) unsigned default NULL,
  `timestamp` timestamp NOT NULL default CURRENT_TIMESTAMP on update CURRENT_TIMESTAMP,
  UNIQUE KEY `key_id` (`_id`)
) ENGINE=INNODB COMMENT='Table for IP packets';

ALTER TABLE ulog2 ADD KEY `index_id` (`_id`);
ALTER TABLE ulog2 ADD KEY `timestamp` (`timestamp`);
ALTER TABLE ulog2 ADD KEY `ip_saddr` (`ip_saddr`);
ALTER TABLE ulog2 ADD KEY `ip_daddr` (`ip_daddr`);
-- This index does not seem very useful:
-- ALTER TABLE ulog2 ADD KEY `oob_time_sec` (`oob_time_sec`);

CREATE TABLE `mac` (
  `_mac_id` bigint unsigned NOT NULL,
  `mac_saddr` binary(12) default NULL,
  `mac_daddr` binary(12) default NULL,
  `mac_protocol` smallint(5) default NULL
) ENGINE=INNODB;

ALTER TABLE mac ADD UNIQUE KEY `_mac_id` (`_mac_id`);
ALTER TABLE mac ADD KEY `mac_saddr` (`mac_saddr`);
ALTER TABLE mac ADD KEY `mac_daddr` (`mac_daddr`);
ALTER TABLE mac ADD KEY `index_mac_id` (`_mac_id`);

CREATE TABLE `tcp` (
  `_tcp_id` bigint unsigned NOT NULL,
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
  `tcp_fin` tinyint(4) default NULL
) ENGINE=INNODB;

ALTER TABLE tcp ADD UNIQUE KEY `_tcp_id` (`_tcp_id`);
ALTER TABLE tcp ADD KEY `index_tcp_id` (`_tcp_id`);
ALTER TABLE tcp ADD KEY `tcp_sport` (`tcp_sport`);
ALTER TABLE tcp ADD KEY `tcp_dport` (`tcp_dport`);


CREATE TABLE `udp` (
  `_udp_id` bigint unsigned NOT NULL,
  `udp_sport` int(5) unsigned default NULL,
  `udp_dport` int(5) unsigned default NULL,
  `udp_len` int(5) unsigned default NULL
) ENGINE=INNODB;

ALTER TABLE udp ADD UNIQUE KEY `_udp_id` (`_udp_id`);
ALTER TABLE udp ADD KEY `index_udp_id` (`_udp_id`);
ALTER TABLE udp ADD KEY `udp_sport` (`udp_sport`);
ALTER TABLE udp ADD KEY `udp_dport` (`udp_dport`);

CREATE TABLE `icmp` (
  `_icmp_id` bigint unsigned NOT NULL,
  `icmp_type` tinyint(3) unsigned default NULL,
  `icmp_code` tinyint(3) unsigned default NULL,
  `icmp_echoid` smallint(5) unsigned default NULL,
  `icmp_echoseq` smallint(5) unsigned default NULL,
  `icmp_gateway` int(10) unsigned default NULL,
  `icmp_fragmtu` smallint(5) unsigned default NULL
) ENGINE=INNODB;

ALTER TABLE icmp ADD UNIQUE KEY `key_icmp_id` (`_icmp_id`);
ALTER TABLE icmp ADD KEY `index_icmp_id` (`_icmp_id`);


-- views

DROP VIEW IF EXISTS `view_tcp`;
CREATE SQL SECURITY INVOKER VIEW `view_tcp` AS
        SELECT * FROM ulog2 INNER JOIN tcp ON ulog2._id = tcp._tcp_id;

-- alternate form:
--  select * from ulog2 where ulog2._id in (select tcp._tcp_id from tcp where tcp._tcp_id is not null);

DROP VIEW IF EXISTS `view_udp`;
CREATE SQL SECURITY INVOKER VIEW `view_udp` AS
        SELECT * FROM ulog2 INNER JOIN udp ON ulog2._id = udp._udp_id;

DROP VIEW IF EXISTS `view_icmp`;
CREATE SQL SECURITY INVOKER VIEW `view_icmp` AS
        SELECT * FROM ulog2 INNER JOIN icmp ON ulog2._id = icmp._icmp_id;

-- ulog view
DROP VIEW IF EXISTS `ulog`;
CREATE SQL SECURITY INVOKER VIEW `ulog` AS
        SELECT * FROM ulog2 INNER JOIN tcp ON ulog2._id = tcp._tcp_id INNER JOIN udp ON ulog2._id = udp._udp_id
		 INNER JOIN icmp ON ulog2._id = icmp._icmp_id INNER JOIN mac ON ulog2._id = mac._mac_id;

-- shortcuts
DROP VIEW IF EXISTS `view_tcp_quad`;
CREATE SQL SECURITY INVOKER VIEW `view_tcp_quad` AS
        SELECT ulog2._id,ulog2.ip_saddr,tcp.tcp_sport,ulog2.ip_daddr,tcp.tcp_dport FROM ulog2 INNER JOIN tcp ON ulog2._id = tcp._tcp_id;

DROP VIEW IF EXISTS `view_udp_quad`;
CREATE SQL SECURITY INVOKER VIEW `view_udp_quad` AS
        SELECT ulog2._id,ulog2.ip_saddr,udp.udp_sport,ulog2.ip_daddr,udp.udp_dport FROM ulog2 INNER JOIN udp ON ulog2._id = udp._udp_id;



-- conntrack

CREATE TABLE `ulog2_ct` (
  `_ct_id` bigint unsigned NOT NULL auto_increment,
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
	       orig_ip_saddr,
	       orig_ip_daddr,
	       orig_ip_protocol,
	       orig_l4_sport,
	       orig_l4_dport,
	       orig_bytes AS orig_raw_pktlen,
	       orig_packets AS orig_raw_pktcount,
	       reply_ip_saddr,
	       reply_ip_daddr,
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

-- Procedures

DROP PROCEDURE IF EXISTS ULOG2_DROP_FOREIGN_KEYS;
delimiter $$
CREATE PROCEDURE ULOG2_DROP_FOREIGN_KEYS(
                )
SQL SECURITY INVOKER
COMMENT 'Drop constraints for ulog2 tables'
BEGIN
        -- remember : table with most constraints first
        ALTER TABLE icmp DROP FOREIGN KEY _icmp_id; 
        ALTER TABLE udp DROP FOREIGN KEY _udp_id; 
        ALTER TABLE tcp DROP FOREIGN KEY _tcp_id; 
END
$$
delimiter ;

DROP PROCEDURE IF EXISTS ULOG2_ADD_FOREIGN_KEYS;
delimiter $$
CREATE PROCEDURE ULOG2_ADD_FOREIGN_KEYS(
                )
SQL SECURITY INVOKER
COMMENT 'Add constraints for ulog2 tables'
BEGIN
        -- remember : table with least constraints first
        ALTER TABLE tcp ADD CONSTRAINT _tcp_id FOREIGN KEY (_tcp_id) REFERENCES ulog2 (_id);
        ALTER TABLE udp ADD CONSTRAINT _udp_id FOREIGN KEY (_udp_id) REFERENCES ulog2 (_id);
        ALTER TABLE icmp ADD CONSTRAINT _icmp_id FOREIGN KEY (_icmp_id) REFERENCES ulog2 (_id);
END
$$
delimiter ;

delimiter $$
DROP FUNCTION IF EXISTS INSERT_IP_PACKET;
CREATE FUNCTION INSERT_IP_PACKET(
		_oob_time_sec int(10) unsigned,
		_oob_time_usec int(10) unsigned,
		_oob_prefix varchar(32),
		_oob_mark int(10) unsigned,
		_oob_in varchar(32),
		_oob_out varchar(32),
		_ip_saddr int(16),
		_ip_daddr int(16),
		_ip_protocol tinyint(3) unsigned
		) RETURNS bigint unsigned
SQL SECURITY INVOKER
NOT DETERMINISTIC
READS SQL DATA
BEGIN
	INSERT INTO ulog2 (oob_time_sec, oob_time_usec, oob_prefix, oob_mark, oob_in, oob_out,
			   ip_saddr, ip_daddr, ip_protocol) VALUES 
		(_oob_time_sec, _oob_time_usec, _oob_prefix, _oob_mark, _oob_in, _oob_out,
		 _ip_saddr, _ip_daddr, _ip_protocol);
	RETURN LAST_INSERT_ID();
END
$$

delimiter $$
DROP FUNCTION IF EXISTS INSERT_IP_PACKET_FULL;
CREATE FUNCTION INSERT_IP_PACKET_FULL(
		_oob_time_sec int(10) unsigned,
		_oob_time_usec int(10) unsigned,
		_oob_prefix varchar(32),
		_oob_mark int(10) unsigned,
		_oob_in varchar(32),
		_oob_out varchar(32),
		_ip_saddr int(16),
		_ip_daddr int(16),
		_ip_protocol tinyint(3) unsigned,
	  	_ip_tos tinyint(3) unsigned,
	  	_ip_ttl tinyint(3) unsigned,
	  	_ip_totlen smallint(5) unsigned,
	  	_ip_ihl tinyint(3) unsigned,
	  	_ip_csum smallint(5) unsigned,
	  	_ip_id smallint(5) unsigned,
	  	_ip_fragoff smallint(5) unsigned
		) RETURNS int(10) unsigned
SQL SECURITY INVOKER
NOT DETERMINISTIC
READS SQL DATA
BEGIN
	INSERT INTO ulog2 (oob_time_sec, oob_time_usec, oob_prefix, oob_mark, oob_in, oob_out,
			   ip_saddr, ip_daddr, ip_protocol, ip_tos, ip_ttl, ip_totlen, ip_ihl,
		 	   ip_csum, ip_id, ip_fragoff ) VALUES 
		(_oob_time_sec, _oob_time_usec, _oob_prefix, _oob_mark, _oob_in, _oob_out,
		 _ip_saddr, _ip_daddr, _ip_protocol, _ip_tos, _ip_ttl, _ip_totlen, _ip_ihl,
		 _ip_csum, _ip_id, _ip_fragoff);
	RETURN LAST_INSERT_ID();
END
$$


delimiter $$
DROP PROCEDURE IF EXISTS PACKET_ADD_TCP_FULL;
CREATE PROCEDURE PACKET_ADD_TCP_FULL(
		IN `id` int(10) unsigned,
		IN `_sport` smallint(5) unsigned,
		IN `_dport` smallint(5) unsigned,
		IN `_seq` int(10) unsigned,
		IN `_ackseq` int(10) unsigned,
		IN `_window` smallint(5) unsigned,
		IN `_urg` tinyint(4),
		IN `_urgp` smallint(5) unsigned,
		IN `_ack` tinyint(4),
		IN `_psh` tinyint(4),
		IN `_rst` tinyint(4),
		IN `_syn` tinyint(4),
		IN `_fin` tinyint(4)
		)
BEGIN
	INSERT INTO tcp (_tcp_id, tcp_sport, tcp_dport, tcp_seq, tcp_ackseq, tcp_window, tcp_urg, tcp_urgp, tcp_ack, tcp_psh, tcp_rst, tcp_syn, tcp_fin) VALUES
	(id, _sport, _dport, _seq, _ackseq, _window, _urg, _urgp, _ack, _psh, _rst, _syn, _fin);
END
$$

delimiter $$
DROP PROCEDURE IF EXISTS PACKET_ADD_TCP;
CREATE PROCEDURE PACKET_ADD_TCP(
		IN `id` int(10) unsigned,
		IN `_sport` smallint(5) unsigned,
		IN `_dport` smallint(5) unsigned
		)
BEGIN
	INSERT INTO tcp (_tcp_id, tcp_sport, tcp_dport) VALUES (id, _sport, _dport);
END
$$

delimiter $$
DROP PROCEDURE IF EXISTS PACKET_ADD_UDP;
CREATE PROCEDURE PACKET_ADD_UDP(
		IN `id` int(10) unsigned,
		IN `_sport` smallint(5) unsigned,
		IN `_dport` smallint(5) unsigned,
		IN `_len` smallint(5) unsigned
		)
BEGIN
	INSERT INTO udp (_udp_id, udp_sport, udp_dport, udp_len) VALUES
	(id, _sport, _dport, _len);
END
$$

delimiter $$
DROP PROCEDURE IF EXISTS PACKET_ADD_ICMP;
CREATE PROCEDURE PACKET_ADD_ICMP(
		IN `id` int(10) unsigned,
		IN `_icmp_type` tinyint(3) unsigned,
		IN `_icmp_code` tinyint(3) unsigned,
		IN `_icmp_echoid` smallint(5) unsigned,
		IN `_icmp_echoseq` smallint(5) unsigned,
		IN `_icmp_gateway` int(10) unsigned,
		IN `_icmp_fragmtu` smallint(5) unsigned
		)
BEGIN
	INSERT INTO icmp (_icmp_id, icmp_type, icmp_code, icmp_echoid, icmp_echoseq, 
			  icmp_gateway, icmp_fragmtu) VALUES
			 (id, _icmp_type, _icmp_code, _icmp_echoid, _icmp_echoseq, 
			  _icmp_gateway, _icmp_fragmtu);

END
$$


delimiter $$
DROP PROCEDURE IF EXISTS PACKET_ADD_MAC;
CREATE PROCEDURE PACKET_ADD_MAC(
		IN `id` int(10) unsigned,
		IN `_saddr` binary(12),
		IN `_daddr` binary(12),
		IN `_protocol` smallint(5)
		)
BEGIN
	INSERT INTO mac (_mac_id, mac_saddr, mac_daddr, mac_protocol) VALUES
	(id, _saddr, _daddr, _protocol);
END
$$

delimiter $$
DROP PROCEDURE IF EXISTS INSERT_PACKET_FULL;
CREATE PROCEDURE INSERT_PACKET_FULL(
		IN `_oob_time_sec` int(10) unsigned,
		IN `_oob_time_usec` int(10) unsigned,
		IN `_oob_prefix` varchar(32),
		IN `_oob_mark` int(10) unsigned,
		IN `_oob_in` varchar(32),
		IN `_oob_out` varchar(32),
		IN `_ip_saddr` int(16),
		IN `_ip_daddr` int(16),
		IN `_ip_protocol` tinyint(3) unsigned,
	  	IN `_ip_tos` tinyint(3) unsigned,
	  	IN `_ip_ttl` tinyint(3) unsigned,
	  	IN `_ip_totlen` smallint(5) unsigned,
	  	IN `_ip_ihl` tinyint(3) unsigned,
	  	IN `_ip_csum` smallint(5) unsigned,
	  	IN `_ip_id` smallint(5) unsigned,
	  	IN `_ip_fragoff` smallint(5) unsigned,
		IN `tcp_sport` smallint(5) unsigned,
		IN `tcp_dport` smallint(5) unsigned,
		IN `tcp_seq` int(10) unsigned,
		IN `tcp_ackseq` int(10) unsigned,
		IN `tcp_window` smallint(5) unsigned,
		IN `tcp_urg` tinyint(4),
		IN `tcp_urgp` smallint(5) unsigned,
		IN `tcp_ack` tinyint(4),
		IN `tcp_psh` tinyint(4),
		IN `tcp_rst` tinyint(4),
		IN `tcp_syn` tinyint(4),
		IN `tcp_fin` tinyint(4),
		IN `udp_sport` smallint(5) unsigned,
		IN `udp_dport` smallint(5) unsigned,
		IN `udp_len` smallint(5) unsigned,
		IN `icmp_type` tinyint(3) unsigned,
		IN `icmp_code` tinyint(3) unsigned,
		IN `icmp_echoid` smallint(5) unsigned,
		IN `icmp_echoseq` smallint(5) unsigned,
		IN `icmp_gateway` int(10) unsigned,
		IN `icmp_fragmtu` smallint(5) unsigned
--		IN `mac_saddr` binary(12),
--		IN `mac_daddr` binary(12),
--		IN `mac_protocol` smallint(5)
		)
BEGIN
	SET @lastid = INSERT_IP_PACKET_FULL(_oob_time_sec, _oob_time_usec, _oob_prefix,
					   _oob_mark, _oob_in, _oob_out, _ip_saddr, 
					   _ip_daddr, _ip_protocol, _ip_tos, _ip_ttl,
					   _ip_totlen, _ip_ihl, _ip_csum, _ip_id,
					   _ip_fragoff);
	IF _ip_protocol = 6 THEN
		CALL PACKET_ADD_TCP_FULL(@lastid, tcp_sport, tcp_dport, tcp_seq, tcp_ackseq,
					 tcp_window, tcp_urg, tcp_urgp, tcp_ack, tcp_psh,
					 tcp_rst, tcp_syn, tcp_fin);
	ELSEIF _ip_protocol = 17 THEN
		CALL PACKET_ADD_UDP(@lastid, udp_sport, udp_dport, udp_len);
	ELSEIF _ip_protocol = 1 THEN
		CALL PACKET_ADD_ICMP(@lastid, icmp_type, icmp_code, icmp_echoid, icmp_echoseq, 
				     icmp_gateway, icmp_fragmtu);
	END IF;
--	IF mac_protocol IS NOT NULL THEN
--		CALL PACKET_ADD_MAC(@lastid, mac_saddr, mac_daddr, mac_protocol);
--	END IF;
END
$$


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
DROP PROCEDURE IF EXISTS INSERT_CT;
CREATE PROCEDURE INSERT_CT(
		IN `_orig_ip_saddr` binary(16),
		IN `_orig_ip_daddr` binary(16),
		IN `_orig_ip_protocol` tinyint(3) unsigned,
		IN `_orig_l4_sport` int(5),
		IN `_orig_l4_dport` int(5),
		IN `_orig_bytes` bigint,
		IN `_orig_packets` bigint,
		IN `_reply_ip_saddr` binary(16),
		IN `_reply_ip_daddr` binary(16),
		IN `_reply_ip_protocol` tinyint(3) unsigned,
		IN `_reply_l4_sport` int(5),
		IN `_reply_l4_dport` int(5),
		IN `_reply_bytes` bigint,
		IN `_reply_packets` bigint,
		IN `_icmp_code` tinyint(3),
		IN `_icmp_type` tinyint(3),
		IN `_ct_mark` bigint,
		IN `_flow_start_sec` int(10),
		IN `_flow_start_usec` int(10),
		IN `_flow_end_sec` int(10),
		IN `_flow_end_usec` int(10)
		)
BEGIN
	INSERT INTO ulog2_ct (orig_ip_saddr, orig_ip_daddr, orig_ip_protocol,
		orig_l4_sport, orig_l4_dport, orig_bytes, orig_packets,
		reply_ip_saddr, reply_ip_daddr, reply_ip_protocol,
		reply_l4_sport, reply_l4_dport, reply_bytes, reply_packets,
		icmp_code, icmp_type, ct_mark, 
		flow_start_sec, flow_start_usec,
		flow_end_sec, flow_end_usec)
 	VALUES (_orig_ip_saddr, _orig_ip_daddr, _orig_ip_protocol,
		_orig_l4_sport, _orig_l4_dport, _orig_bytes, _orig_packets,
		_reply_ip_saddr, _reply_ip_daddr, _reply_ip_protocol,
		_reply_l4_sport, _reply_l4_dport, _reply_bytes, _reply_packets,
		_icmp_code, _icmp_type, _ct_mark,
		_flow_start_sec, _flow_start_usec,
		_flow_end_sec, _flow_end_usec);

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
        -- remember : table with most constraints first
        DELETE FROM icmp  WHERE icmp._icmp_id = _packet_id;
        DELETE FROM tcp   WHERE tcp._tcp_id = _packet_id;
        DELETE FROM udp   WHERE udp._udp_id = _packet_id;
        DELETE FROM ulog2 WHERE ulog2._id = _packet_id;
END
$$
delimiter ;

DROP PROCEDURE IF EXISTS DELETE_CUSTOM_ONE;
delimiter $$
-- XXX be careful with SQL injections !!
CREATE PROCEDURE DELETE_CUSTOM_ONE(
		IN tname varchar(64),
		IN tjoin varchar(64),
                IN _id bigint
                )
SQL SECURITY INVOKER
COMMENT 'Delete packet in a custom table (specified at runtime) using a prepared query'
BEGIN
        SET @l_sql = CONCAT('DELETE FROM ',@tname,' WHERE ',@tname,'.',@tfield,' = ',_id);
        PREPARE delete_stmt FROM @l_sql;
        EXECUTE delete_stmt;
        DEALLOCATE PREPARE delete_stmt;
END
$$
delimiter ;

DROP PROCEDURE IF EXISTS DELETE_PACKET_FULL;
delimiter $$
CREATE PROCEDURE DELETE_PACKET_FULL(
		IN _packet_id bigint unsigned
                )
SQL SECURITY INVOKER
COMMENT 'Delete packet in all tables (including extensions)'
BEGIN
        DECLARE tname varchar(64);
        DECLARE tjoin varchar(64);
        DECLARE l_last INT DEFAULT 0;

        DECLARE ext_csr CURSOR FOR
                SELECT table_name,join_name FROM _extensions;

        DECLARE CONTINUE HANDLER FOR NOT FOUND SET l_last=1;

        OPEN ext_csr;
        ext_loop:LOOP
                FETCH ext_csr INTO tname,tjoin;
                IF l_last THEN
                        LEAVE ext_loop;
                END IF;
                CALL DELETE_CUSTOM_ONE(tname,tjoin,_packet_id);
        END LOOP ext_loop;
        CLOSE ext_csr;

        CALL DELETE_PACKET(_packet_id);
END
$$
delimiter ;

-- suppressing tuples
DROP PROCEDURE IF EXISTS DELETE_CT_TUPLE;
delimiter $$
CREATE PROCEDURE DELETE_CT_TUPLE(
		IN _packet_id bigint unsigned
                )
SQL SECURITY INVOKER
COMMENT 'Delete a tuple from conntrack'
BEGIN
        -- remember : table with most constraints first
        DELETE FROM ct_icmp  WHERE ct_icmp._icmp_id = _packet_id;
        DELETE FROM ct_l4   WHERE ct_l4._l4_id = _packet_id;
        DELETE FROM ct_tuple WHERE ct_tuple._tuple_id = _packet_id;
END
$$

delimiter ;


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

-- DROP TRIGGER IF EXISTS _trigger_delete;
-- delimiter $$
-- CREATE TRIGGER _trigger_delete BEFORE DELETE ON ulog2
-- FOR EACH ROW
-- BEGIN
-- 	DELETE FROM icmp  WHERE icmp._icmp_id = _packet_id;
--      DELETE FROM tcp   WHERE tcp._tcp_id = _packet_id;
--      DELETE FROM udp   WHERE udp._udp_id = _packet_id;
-- END
-- $$
-- delimiter ;


-- Tables compression

DROP PROCEDURE IF EXISTS COMPRESS_TABLES;
delimiter $$
CREATE PROCEDURE COMPRESS_TABLES(
                )
SQL SECURITY INVOKER
COMMENT 'Try to remove dead entries and call OPTIMIZE for each table'
BEGIN
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
        -- finally, call optimize to reclaim unused space and defragment the data file
        OPTIMIZE TABLE ulog2, mac, tcp, udp, icmp, ulog2_ct;
END
$$
delimiter ;

DROP PROCEDURE IF EXISTS ANALYZE_TABLES;
delimiter $$
CREATE PROCEDURE ANALYZE_TABLES(
                )
SQL SECURITY INVOKER
COMMENT 'ANALYZE all ulog2 tables'
BEGIN
        ANALYZE TABLE ulog2, mac, tcp, udp, icmp, ulog2_ct;
END
$$
delimiter ;

-- Add foreign keys to tables
CALL ULOG2_ADD_FOREIGN_KEYS();

