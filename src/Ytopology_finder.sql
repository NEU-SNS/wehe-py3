--
-- This query aims to find Y-shaped topologies in the Wehe traceroute
-- data collected by M-Lab.
--
-- Y-shaped topologies consists of two M-Lab servers and one Wehe client.
-- The paths from the M-Lab servers to the client merge inside the client
-- edge ISP but not outside.
--
-- Input:
--      - measurement-lab.wehe.scamper1
--      - measurement-lab.wehe_raw.hopannotation2
-- Output:
--      - measurement-lab.wehe.y_topologies
--

--
-- Helper Variables
--
DECLARE period INT64 DEFAULT 7;
DECLARE end_date DATE DEFAULT CURRENT_DATE();
DECLARE start_date DATE DEFAULT DATE_SUB(CURRENT_DATE(), INTERVAL period-1 DAY);
DECLARE users ARRAY<STRING>;

--
-- Helper Functions
--
CREATE TEMP FUNCTION FindPath(exp_nodes ANY TYPE)
AS ( array(
  SELECT STRUCT(offset, hop_id, hop_addr, next_addrs, next_hop, NOT EXISTS(SELECT true FROM UNNEST(next_addrs) AS item WHERE item = next_hop) as is_next_missing)
  FROM (
    SELECT
      offset,
      nodes.hop_id,
      nodes.addr as hop_addr,
      array(
        SELECT links.addr
        FROM UNNEST(nodes.links) as links_arr, UNNEST(links_arr.Links) as links, UNNEST(links.probes) as probes
        WHERE (probes.replyc != 0) AND (probes.flowid = 1)
      ) as next_addrs,
      LEAD(nodes.addr) OVER (ORDER BY offset) as next_hop
    FROM unnest(exp_nodes) as nodes WITH OFFSET AS `offset`
  )));

CREATE TEMP FUNCTION HopsInsideEdgeAS(hops ANY TYPE, edgeASN INT64)
AS (
    array(SELECT hops.hop_addr FROM unnest(hops) hops WHERE hops.hop_ASN = edgeASN)
);

CREATE TEMP FUNCTION HopsOutsideEdgeAS(hops ANY TYPE, edgeASN INT64)
AS (
    array(SELECT hops.hop_addr FROM unnest(hops) hops WHERE hops.hop_ASN != edgeASN)
);

CREATE TEMP FUNCTION LongestTraceMatch(hops1 ARRAY<STRING>, hops2 ARRAY<STRING>)
RETURNS ARRAY<STRING>
LANGUAGE js AS """
    common_path = []
    for (let i = 0; i < Math.min(hops1.length, hops2.length); i++) {
        if (hops1[i] == hops2[i]) { common_path.push(hops1[i])}
        else { break}
    }
    return common_path
""";

CREATE TEMP FUNCTION CheckForIntersection(hops1 ARRAY<STRING>, hops2 ARRAY<STRING>)
RETURNS BOOL
LANGUAGE js AS """
    hops2_set = new Set(hops2)
    intersections = hops1.filter(element => hops2_set.has(element))
    return intersections.length != 0
""";



-- y_topologies: a temporary table filled with the final Y-shaped topologies
CREATE TEMP TABLE y_topologies (
  client_ip STRING OPTIONS (description = 'The destination user IP'),
  client_ASN INT64 OPTIONS (description = 'The destination user AS number'),
  servers STRUCT<
    s1 STRUCT<server_ip STRING, server_ASN INT64, server_site STRING>,
    s2 STRUCT<server_ip STRING, server_ASN INT64, server_site STRING>
  > OPTIONS (description = 'The server-pair: their IP, AS number, and site'),
  common_hops ARRAY<STRING> OPTIONS (description = 'hops IPs which form the common path')
);


-- Find the users (destination)
-- TODO: replace later with users from the Wehe tests rather than traceroutes
SET users = ARRAY(
  SELECT dst
  FROM (
    SELECT DISTINCT raw.Tracelb.dst
    FROM `measurement-lab.wehe.scamper1`
    WHERE date BETWEEN start_date AND end_date AND LOWER(client.Network.ASName) NOT LIKE '%google%'
  )
);


--
-- Apply topology finder algorithm for each user
--
FOR user in (SELECT * FROM unnest(users) user)
DO
    INSERT INTO y_topologies

    -- select traceroute records
    WITH scamper1 AS (
    SELECT *
    FROM `measurement-lab.wehe.scamper1`
    WHERE (date BETWEEN start_date AND end_date) AND (raw.Tracelb.dst = user.user)
    ),

    -- convert scamper format to single path - then remove duplicates
    single_path_traceroute AS (
    SELECT ARRAY_AGG(spt LIMIT 1)[ORDINAL(1)].*
    FROM (
        SELECT
        id,
        raw.Tracelb.src as server_ip,
        server.Network.ASNumber as server_ASN,
        server.Site as server_site,
        raw.Tracelb.dst as client_ip,
        client.Network.ASNumber as client_ASN,
        FindPath(raw.Tracelb.nodes) as tr
        FROM scamper1) as spt
    GROUP BY FARM_FINGERPRINT(CONCAT(spt.server_ip, spt.client_ip, TO_JSON_STRING(spt.tr)))
    ),

    -- annotate with the ASNumber and ASName from hopannotation2
    annotated_traceroute AS (
    SELECT
        spt.id, spt.server_ip, spt.server_ASN, spt.server_site, spt.client_ip, spt.client_ASN,
        ARRAY_AGG(STRUCT(
        hops.offset, hops.hop_id, hops.hop_addr, ha2.raw.Annotations.Network.ASNumber AS hop_ASN, ha2.raw.Annotations.Network.ASName AS hop_ASName, hops.next_addrs, hops.is_next_missing
        ) ORDER BY hops.offset) as hops
    FROM single_path_traceroute as spt, UNNEST(spt.tr) as hops

    LEFT JOIN `measurement-lab.wehe_raw.hopannotation2` as ha2 ON (hops.hop_id = ha2.id)
    WHERE hops.hop_addr != spt.client_ip
    GROUP BY 1, 2, 3, 4, 5, 6
    ),

    -- step1 of the algorithm: divide trace into hops outside the edge ISP and hops inside the edge ISP
    step1 AS (
        SELECT
            *, --EXCEPT (hops),
            HopsInsideEdgeAS(tr.hops, tr.client_ASN) as inside_hops,
            HopsOutsideEdgeAS(tr.hops, tr.client_ASN) as outside_hops
        FROM annotated_traceroute as tr
    ),

    -- step2 of the agorithm: join the table of step 1 with itself to create server pairs, and compute the following:
    --  1. find the longest common path inside the edge ISP
    --  2. find if there exists intersecting hops outside the edge ISP
    step2 AS (
        SELECT
            right_tr.client_ip,
            right_tr.client_ASN,
            STRUCT(
                STRUCT(right_tr.server_ip, right_tr.server_ASN, right_tr.server_site) as s1,
                STRUCT(left_tr.server_ip, left_tr.server_ASN, left_tr.server_site) as s2) as servers,
            ARRAY_REVERSE(LongestTraceMatch(ARRAY_REVERSE(right_tr.inside_hops), ARRAY_REVERSE(left_tr.inside_hops))) as common_hops,
            CheckForIntersection(right_tr.outside_hops, left_tr.outside_hops) as outside_intersection
        FROM step1 as right_tr
        CROSS JOIN step1 as left_tr
        WHERE right_tr.server_ASN < left_tr.server_ASN
    ),

    -- step3 of the algorithm: select pairs from step2 that have:
    --  (1) no intersection outside the edge ISP
    --  (2) at least one common hop before the user itself
    step3 AS (
        SELECT * EXCEPT(outside_intersection)
        FROM step2
        WHERE step2.outside_intersection = false AND ARRAY_LENGTH(step2.common_hops) != 0
    )

    -- append step3 output to y_topologies
    SELECT * FROM step3;
END FOR;

-- final results
SELECT ARRAY_AGG(y_topologies LIMIT 1)[ORDINAL(1)].*
FROM y_topologies
GROUP BY FARM_FINGERPRINT(TO_JSON_STRING(y_topologies))