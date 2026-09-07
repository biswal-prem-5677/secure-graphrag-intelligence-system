"""
Parameterized Cypher query templates preventing injection attacks.
"""

ENTITY_LOOKUP_QUERY = """
MATCH (n)
WHERE toLower(n.name) CONTAINS toLower($name)
   OR toLower(n.id) = toLower($name)
RETURN n.id AS id, n.name AS name, labels(n)[0] AS label, properties(n) AS properties
LIMIT 25
"""

ONE_HOP_NEIGHBORS_QUERY = """
MATCH (source)-[r]-(target)
WHERE source.id = $entity_id OR toLower(source.name) = toLower($entity_id)
RETURN source.id AS source_id, source.name AS source_name, labels(source)[0] AS source_label,
       type(r) AS rel_type, properties(r) AS rel_properties,
       target.id AS target_id, target.name AS target_name, labels(target)[0] AS target_label,
       target.properties AS target_properties
LIMIT 50
"""

MULTI_HOP_PATHS_QUERY = """
MATCH path = (source)-[r*1..3]-(target)
WHERE (source.id = $entity_id OR toLower(source.name) = toLower($entity_id))
RETURN [n IN nodes(path) | {id: n.id, name: n.name, label: labels(n)[0]}] AS path_nodes,
       [rel IN relationships(path) | {type: type(rel), properties: properties(rel)}] AS path_rels
LIMIT $limit
"""

EVIDENCE_LOOKUP_QUERY = """
MATCH (n)-[:SUPPORTED_BY]->(e:Evidence)
WHERE n.id IN $entity_ids
RETURN e.id AS source_id, e.title AS title, e.source_type AS source_type,
       e.confidence AS confidence, e.summary AS summary, e.date AS date
LIMIT 50
"""
