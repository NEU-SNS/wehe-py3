--
-- This query searches the M-Lab traceroute dataset for Y-shaped topologies.
--
-- Y-shaped topologies consists of a path pair that
--   starts at two M-Lab servers which belong to two different ASes
--   and merge exactly once before reaching the client (preferably inside the edge network).
--
-- Input:
--      - measurement-lab.wehe.replayInfo1
--      - measurement-lab.wehe.scamper1
--      - measurement-lab.wehe_raw.hopannotation2
-- Output:
--      - json files with name format: ytopologies-<subnetPrefix>-000000000000.json
--

--
-- Helper Variables
--
DECLARE period INT64 DEFAULT 7;
DECLARE end_date DATE DEFAULT CURRENT_DATE()-1;
DECLARE start_date DATE DEFAULT DATE_SUB(end_date, INTERVAL period-1 DAY);
DECLARE subnets ARRAY<STRING>;
DECLARE bucket_uri STRING DEFAULT CONCAT("gs://archive-measurement-lab/wehe/ytopologies/", CURRENT_DATE(), "/");

--
-- Helper Functions
--
# Checks if a given string addr string is: (1) valid IP and (2) public IP.
CREATE TEMP FUNCTION isValidPublicIP(addr STRING) AS (
    CASE WHEN REGEXP_CONTAINS(addr, r'\.') AND NOT REGEXP_CONTAINS(addr, r'\:') THEN
        NOT (NET.IP_TO_STRING((NET.SAFE_IP_FROM_STRING(addr) & NET.IP_NET_MASK(4, 8))) = '10.0.0.0'
          OR NET.IP_TO_STRING((NET.SAFE_IP_FROM_STRING(addr) & NET.IP_NET_MASK(4, 12))) = '172.16.0.0'
          OR NET.IP_TO_STRING((NET.SAFE_IP_FROM_STRING(addr) & NET.IP_NET_MASK(4, 16))) = '192.168.0.0')
    ELSE
        NOT (NET.IP_TO_STRING((NET.SAFE_IP_FROM_STRING(addr) & NET.IP_NET_MASK(16, 7))) = 'fc00::'
          OR NET.IP_TO_STRING((NET.SAFE_IP_FROM_STRING(addr) & NET.IP_NET_MASK(16, 7))) = 'fd00::')
    END
);

# Hash function for an IP address
CREATE TEMP FUNCTION HashAddr(addr STRING) RETURNS INT64 AS (
  CASE WHEN REGEXP_CONTAINS(addr, r'\.') THEN
    array(
      SELECT SUM(IFNULL(SAFE_CAST(x as INT64), 0) * prime)
      FROM unnest(SPLIT(addr, '.')) as x with offset
      join unnest([2, 3, 5, 7]) prime with offset
      using(offset))[OFFSET(0)]
  WHEN REGEXP_CONTAINS(addr, r'\:') THEN
    array(
      SELECT SUM(IFNULL(SAFE_CAST(CONCAT('0x',x) as INT64), 0) * prime)
      FROM unnest(SPLIT(addr, ':')) as x with offset
      join unnest([2, 3, 5, 7, 11, 13, 17, 19]) prime with offset
      using(offset))[OFFSET(0)]
  ELSE
    NULL
  END
);

# Takes the "nodes" record from the scamper traceroute plus the flowid
# and constructs the single path array of hops for that flow id.
CREATE TEMP FUNCTION FindPath(nodes ANY TYPE, flow_id INT64) AS (
  array (
    SELECT STRUCT(
      offset, hop_id, hop_addr, next_addrs, next_hop,
      NOT EXISTS(SELECT true FROM UNNEST(next_addrs) as item WHERE item = next_hop) as is_next_missing)
    FROM (
      SELECT
        offset,
        nodes.hop_id,
        nodes.addr as hop_addr,
        array(
          SELECT links.addr
          FROM UNNEST(nodes.links) as links_arr, UNNEST(links_arr.Links) as links, UNNEST(links.probes) as probes
          WHERE (probes.replyc != 0) AND (probes.flowid = flow_id)
        ) as next_addrs,
        LEAD(nodes.addr) OVER (ORDER BY offset) as next_hop
      FROM unnest(nodes) as nodes WITH OFFSET as `offset`
)));

# Tranforms the next_addr in the last hop to a hop STRUCT.
CREATE TEMP FUNCTION NextAddrToHop(last_hop ANY TYPE) AS (
  STRUCT(
    last_hop.offset+1 as offset,
    CONCAT(
      SPLIT(last_hop.hop_id, '_')[0],
      '_', SPLIT(last_hop.hop_id, '_')[1],
      '_', last_hop.next_addrs[OFFSET(0)]) as hop_id,
    last_hop.next_addrs[OFFSET(0)] as hop_addr,
    ARRAY<STRING>[] as next_addrs, '' as next_hop,
    true as is_next_missing)
);

# Given a single path array of hops, this function:
#   (1) check if the last hop has a next_addrs field and append as a new hop
#   (2) discard a hop if the hop_addr is an invalid or private IP
CREATE TEMP FUNCTION PostProcessSinglePathTraceroute(hops ANY TYPE) AS (
  array(
    SELECT STRUCT(
      hop.offset, hop.hop_id, hop.hop_addr,
      ARRAY_TO_STRING(hop.next_addrs, ','), hop.next_hop, hop.is_next_missing)
    FROM (
      SELECT * FROM unnest(hops)
      UNION ALL
      SELECT * FROM unnest(IF (
          (ARRAY_LENGTH(hops) <> 0) AND (ARRAY_LENGTH(hops[OFFSET(ARRAY_LENGTH(hops)-1)].next_addrs) <> 0),
          [NextAddrToHop(hops[offset(ARRAY_LENGTH(hops)-1)])], []))
    ) as hop
    WHERE isValidPublicIP(hop.hop_addr)
));

# Given two single path tracesoutes:
# searches for common hops (addr or CIDR) inside the destination's network.
CREATE TEMP FUNCTION FindCommonHopsInside(hops1 ANY TYPE, hops2 ANY TYPE, edgeASN INT64) AS (
  array(
    SELECT STRUCT(
      array(SELECT DISTINCT hops1.hop_addr
        FROM unnest(hops1) as hops1, unnest(hops2) as hops2
        WHERE hops1.hop_addr = hops2.hop_addr AND hops1.hop_ASN = edgeASN) as common_addrs,
      array(SELECT DISTINCT hops1.hop_cidr
        FROM unnest(hops1) as hops1, unnest(hops2) as hops2
        WHERE hops1.hop_cidr = hops2.hop_cidr AND hops1.hop_ASN = edgeASN) as common_cidrs
    ) as common_hops
));

# The priorty of a path-pair is determined by the existance of
# physical intersection inside the edge network (i.e., client's network).
# This function returns the following priorities:
#   1: if they have physical router with same ip in common - highest priority
#   2: if the two paths pass through the same cidr
#   3: if there is no evidence of intersection inside the edge AS - lowest priority
CREATE TEMP FUNCTION AssignInnetworkPriortiy (common_innetwork_hops ANY TYPE) AS (
  CASE WHEN ARRAY_LENGTH(common_innetwork_hops.common_addrs) <> 0 THEN 1
  WHEN ARRAY_LENGTH(common_innetwork_hops.common_cidrs) <> 0 THEN 2
  ELSE 3
  END
);

# Returns the sequence of ASes traversed by the single path traceroute
# from the M-Lab server to the edge network.
CREATE TEMP FUNCTION GetASNsOrdered(hops ANY TYPE, edgeASN INT64) AS (
  array(
    SELECT STRUCT(ROW_NUMBER() OVER() as offset, hop_ASN, hop_ASName)
    FROM (
      SELECT MAX(hops.offset) as max_offset, hops.hop_ASN as hop_ASN, hops.hop_ASName as hop_ASName
      FROM unnest(ARRAY_REVERSE(hops)) as hops
      WHERE hops.hop_ASN <> edgeASN
      GROUP BY hops.hop_ASN, hops.hop_ASName
    ) as ases
    ORDER BY ases.max_offset
));

# Find the common ASes (other than the edge AS) between two single path traceroutes.
CREATE TEMP FUNCTION FindCommonASesOutside(hops1 ANY TYPE, hops2 ANY TYPE, edgeASN INT64) AS (
  array(
    SELECT STRUCT(ases1.hop_ASN, ases1.hop_ASName, ases1.offset as offset1, ases2.offset as offset2)
    FROM unnest(GetASNsOrdered(hops1, edgeASN)) as ases1, unnest(GetASNsOrdered(hops2, edgeASN)) as ases2
    WHERE ases1.hop_ASN = ases2.hop_ASN
));

# Checks if the common ASes between two single path traceroutes are consecutive and end at the edge network;
# with this property, the path-pair forms a Y-shaped topology.
CREATE TEMP FUNCTION AreOutSideAsesSEQ(ases ANY TYPE) AS (
  IF (
    ARRAY_LENGTH(ases) = 0,
    true,
    array(
      SELECT LOGICAL_AND(are_offsets_equal) AND LOGICAL_AND(are_offsets_consec)
      FROM (
        SELECT
          (ases.offset1 = ases.offset2) as are_offsets_equal,
          (ases.offset1 = IFNULL(LAG(ases.offset1) OVER(ORDER BY ases.offset1), 0) + 1) as are_offsets_consec
        FROM unnest(ases) as ases)
    )[OFFSET(0)]
));

CREATE TEMP FUNCTION ParseServerStructJSON(input STRING)
RETURNS STRUCT<IP STRING, ASN INT64, ASName STRING, CIDR STRING, mlab_site STRING>
LANGUAGE js AS """
  return JSON.parse(input);
""";

CREATE TEMP FUNCTION ParseClientStructJSON(input STRING)
RETURNS STRUCT<IP STRING, ASN INT64, ASName STRING, CIDR STRING>
LANGUAGE js AS """
  return JSON.parse(input);
""";

--
-- The Query
--

# Find the users subnets (destination) from wehe replay info records.
SET subnets = ARRAY(
  SELECT DISTINCT(client.Network.CIDR)
  FROM `measurement-lab.wehe.scamper1`
  WHERE (date BETWEEN start_date AND end_date)
    AND (raw.Tracelb.dst IN (
      SELECT DISTINCT raw.clientIP
      FROM `measurement-lab.wehe.replayInfo1`
      WHERE (date BETWEEN start_date AND end_date)))
    AND (client.Network.CIDR is not NULL)
);

# annotations: a temporary table that contains the hop annotations from wehe and ndt data.
# Hop annotations are mapped to hops according to the IP address and the date the hop (traceroute) was recorded.
CREATE TEMP TABLE annotations AS (
  SELECT SPLIT(ha2.id, '_')[0] as date_str, SPLIT(ha2.id, '_')[2] as addr, ARRAY_AGG(ha2 LIMIT 1)[ORDINAL(1)].*
  FROM (
      SELECT *
      FROM `measurement-lab.wehe_raw.hopannotation2` as ha2_wehe
      WHERE (date BETWEEN start_date AND end_date) AND ha2_wehe.raw.Annotations.Network.Missing is NULL
      -- UNION ALL
      -- SELECT *
      -- FROM `measurement-lab.ndt_raw.hopannotation2` as ha2_ndt
      -- WHERE (date BETWEEN start_date AND end_date) AND ha2_ndt.raw.Annotations.Network.Missing is NULL
    ) as ha2
  GROUP BY date_str, addr
);

# traceroute: a temporary table filled with the single path traceroutes extracted from scamper
CREATE OR REPLACE TEMP TABLE traceroute (
  date DATE, id STRING, flow_id INT64,
  server STRUCT<IP STRING, ASN INT64, ASName STRING, CIDR STRING, mlab_site STRING>,
  client STRUCT<IP STRING, ASN INT64, ASName STRING, CIDR STRING>,
  tr ARRAY<STRUCT<offset INT64, hop_id STRING, hop_addr STRING, next_addrs STRING, next_hop STRING, is_next_missing BOOL>>
);

CREATE TEMP TABLE scamper1 AS (
  SELECT *
  FROM `measurement-lab.wehe.scamper1`
  WHERE (date BETWEEN start_date AND end_date) AND (client.Network.CIDR is not NULL) AND (client.Network.CIDR IN UNNEST(subnets))
);

# Convert scamper traceroute format to single path
FOR flow_id in (SELECT * FROM unnest([1, 2, 3, 4, 5, 6]) val)
DO
  INSERT INTO traceroute
    SELECT ARRAY_AGG(spt LIMIT 1)[OFFSET(0)].*
    FROM (
      SELECT
        date, id, flow_id.val,
        STRUCT(raw.Tracelb.src, server.Network.ASNumber, server.Network.ASName, server.Network.CIDR, server.Site) as server,
        STRUCT(raw.Tracelb.dst, client.Network.ASNumber, client.Network.ASName, client.Network.CIDR) as client,
        PostProcessSinglePathTraceroute(FindPath(raw.Tracelb.nodes, flow_id.val)) as tr
      FROM scamper1) as spt
    GROUP BY FARM_FINGERPRINT(CONCAT(spt.server.CIDR, spt.client.CIDR, TO_JSON_STRING(spt.tr)));
END FOR;

--
-- Apply topology finder algorithm for each user's CIDR
--

# the schema of the final table produced by this query
CREATE OR REPLACE TEMP TABLE topologies_table (
  subnet STRING,
  ASN INT64,
  ASName STRING,
  topos ARRAY<STRUCT<
    servers STRUCT<s1 STRUCT<IP STRING, ASN INT64, ASName STRING, CIDR STRING, mlab_site STRING>, s2 STRUCT<IP STRING, ASN INT64, ASName STRING, CIDR STRING, mlab_site STRING>>,
    traceroutes STRUCT<
      s1_hops ARRAY<STRUCT<offset INT64, hop_id STRING, hop_addr STRING, hop_ASN INT64, hop_ASName STRING, hop_CIDR STRING, missing_network BOOL, next_addrs STRING, is_next_missing BOOL>>,
      s2_hops ARRAY<STRUCT<offset INT64, hop_id STRING, hop_addr STRING, hop_ASN INT64, hop_ASName STRING, hop_CIDR STRING, missing_network BOOL, next_addrs STRING, is_next_missing BOOL>>>,
    common_innetwrok_hops STRUCT<common_addrs ARRAY<STRING>, common_cidrs ARRAY<STRING>>,
    common_outside_ases ARRAY<STRUCT<hop_ASN INT64, hop_ASName STRING, offset1 INT64, offset INT64>>
  >>
);

FOR subnet in (SELECT * FROM unnest(subnets) subnet)
DO
  CREATE OR REPLACE TEMP TABLE topologies AS (
    # remove duplicates from table traceroute
    WITH single_path_traceroute AS (
      SELECT ARRAY_AGG(spt LIMIT 1)[ORDINAL(1)].*
      FROM (
        SELECT * FROM traceroute WHERE client.CIDR = subnet.subnet
      ) as spt
      GROUP BY FARM_FINGERPRINT(CONCAT(spt.server.CIDR, spt.client.CIDR, TO_JSON_STRING(array(SELECT hop_addr FROM spt.tr))))),

    # Annotate the hops with the ASNumber and ASName from the annotations temporary table
    annotated_traceroute AS (
      SELECT date, id, flow_id, ParseServerStructJSON(server) as server, ParseClientStructJSON(client) as client, hops
      FROM (
        SELECT
          spt.date, spt.id, spt.flow_id,
          TO_JSON_STRING(spt.server) as server, TO_JSON_STRING(spt.client) as client,
          ARRAY_AGG(STRUCT(
            hops.offset, hops.hop_id, hops.hop_addr,
            IFNULL(ha2.raw.Annotations.Network.ASNumber, -HashAddr(hops.hop_addr)) as hop_ASN,
            ha2.raw.Annotations.Network.ASName as hop_ASName,
            IFNULL(ha2.raw.Annotations.Network.CIDR, hops.hop_addr) as hop_CIDR,
            (ha2.raw.Annotations.Network.ASNumber IS NULL) as missing_network,
            hops.next_addrs as next_addrs, hops.is_next_missing
          ) ORDER BY hops.offset) as hops
        FROM single_path_traceroute as spt, UNNEST(spt.tr) as hops
        LEFT JOIN annotations as ha2 ON ((ha2.date_str = SPLIT(hops.hop_id, '_')[0]) AND (ha2.addr = SPLIT(hops.hop_id, '_')[2]))
        WHERE hops.hop_addr != spt.client.IP
        GROUP BY 1, 2, 3, 4, 5)),


    # Step1 of the agorithm: create server pairs by self joining the annotated_traceroute table. Then:
    #   1. find the common hops (IPs and/or ciders) inside the edge ISP
    #   2. find if there exist common ASes between the path pair other than the edge ISP
    step1 AS (
      SELECT
        right_tr.client as client,
        STRUCT(right_tr.server as s1, left_tr.server as s2) as servers,
        STRUCT(right_tr.hops as s1_hops, left_tr.hops as s2_hops) as traceroutes,
        FindCommonHopsInside(right_tr.hops, left_tr.hops, right_tr.client.ASN)[offset(0)] as common_innetwrok_hops,
        FindCommonASesOutside(right_tr.hops, left_tr.hops, right_tr.client.ASN) as common_outside_ases,
      FROM annotated_traceroute as right_tr
      CROSS JOIN annotated_traceroute as left_tr
      WHERE right_tr.server.ASN < left_tr.server.ASN),

    # Step2 of the agorithm:
    # discard server pairs that do not form Y-shaped topology (see function AreOutSideAsesSEQ)
    # and asign two priority numbers for each server pair:
    #   1. innetwork_priority:  this priority depends on the physical intersection of the path-pair
    #                           inside the edge AS (see function AssignInnetworkPriortiy)
    #   2. outnetwork_priority: this priority depends on the number of upstream ASes the path-pair
    #                           have in common (0 is the highest priorty)
    step2 AS (
      SELECT
        *,
        AssignInnetworkPriortiy(common_innetwrok_hops) as innetwork_priority,
        ARRAY_LENGTH(common_outside_ases) as outnetwork_priority
      FROM step1
      WHERE AreOutSideAsesSEQ(common_outside_ases)
      ORDER BY innetwork_priority, outnetwork_priority),

    # step3 of the agorithm: select the best candidate path-pairs for localization
    # this selection favors:
    #   (1) server pairs that phyiscally intersect inside the edge AS
    #   (2) server pairs that have no upstream ASes in common
    step3 AS (
      SELECT client, servers, traceroutes, common_innetwrok_hops, common_outside_ases
      FROM (
        SELECT *
        FROM step2
        CROSS JOIN (
          SELECT MIN(innetwork_priority) as min_innetwork_priority, MIN(outnetwork_priority) as min_outnetwork_priority
          FROM step2
          GROUP BY ALL)
        WHERE outnetwork_priority = min_outnetwork_priority)
      WHERE innetwork_priority = min_innetwork_priority
    )

    SELECT ARRAY_AGG(step3 LIMIT 1)[ORDINAL(1)].*
    FROM step3
    GROUP BY FARM_FINGERPRINT(TO_JSON_STRING(step3))
  );

  IF (SELECT count(1) FROM topologies) != 0
  THEN
    EXPORT DATA OPTIONS(
      uri=CONCAT(bucket_uri, 'ytopologies-', SPLIT(subnet.subnet, '/')[0], '-', SPLIT(subnet.subnet, '/')[1] , '-*.json'),
      format='JSON',
      overwrite=true)
    AS (
      SELECT
        client.CIDR as subnet, client.ASN as ASN, client.ASName as ASName,
        ARRAY_AGG(STRUCT(servers, traceroutes, common_innetwrok_hops, common_outside_ases)) as topos
      FROM topologies
      GROUP BY client.CIDR, client.ASN, client.ASName);
  END IF;
END FOR;