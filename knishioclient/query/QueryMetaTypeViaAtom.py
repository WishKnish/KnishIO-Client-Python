# -*- coding: utf-8 -*-
from ..response import ResponseMetaTypeViaAtom
from .Query import Query


class QueryMetaTypeViaAtom(Query):
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super(QueryMetaTypeViaAtom, self).__init__(knish_io_client, query)
        self.default_query = 'query ($metaTypes: [String!], $metaIds: [String!], $values: [String!], $keys: [String!], $latest: Boolean, $filter: [MetaFilter!], $queryArgs: QueryArgs, $countBy: String, $atomValues: [String!], $cellSlugs: [String!] ) { MetaTypeViaAtom(metaTypes: $metaTypes, metaIds: $metaIds, atomValues: $atomValues, cellSlugs: $cellSlugs, filter: $filter, latest: $latest, queryArgs: $queryArgs, countBy: $countBy) @fields }'
        self.fields = {
            "metaType": None,
            "instanceCount": {
                "key": None,
                "value": None
            },
            "instances": {
                "metaType": None,
                "metaId": None,
                "createdAt": None,
                "metas(values: $values, keys: $keys )": {
                    "molecularHash": None,
                    "position": None,
                    "key": None,
                    "value": None,
                    "createdAt": None
                }
            },
            "paginatorInfo": {
                "currentPage": None,
                "total": None
            }
        }

        self.query = query or self.default_query

    def create_response(self, response):
        return ResponseMetaTypeViaAtom(self, response)

    @classmethod
    def create_variables(
            cls,
            *,
            meta_type: str | list = None,
            meta_id: str | list = None,
            key: str = None,
            value: str = None,
            keys: list = None,
            values: list = None,
            atom_values: list = None,
            latest: bool = None,
            filter: list = None,
            query_args: dict = None,
            count_by:str = None,
            cell_slug: str | list = None,
    ) -> dict:
        variables = {}

        if atom_values is not None:
            variables["atomValues"] = atom_values
        if keys is not None:
            variables["keys"] = keys
        if values is not None:
            variables["values"] = values
        if meta_type is not None:
            variables["metaTypes"] = meta_type if isinstance(meta_type, list) else [meta_type]
        if meta_id is not None:
            variables["metaIds"] = meta_id if isinstance(meta_id, list) else [meta_id]
        if count_by is not None:
            variables["countBy"] = count_by
        if filter is not None:
            variables["filter"] = filter
        if key is not None and value is not None:
            if "filter" not in variables:
                variables["filter"] = []
            variables["filter"].append({
                "key": key,
                "value": value,
                "comparison": "="
            })
        if query_args is not None:
            if "limit" not in query_args or query_args.get("limit") == 0:
                query_args["limit"] = "*"
            variables["queryArgs"] = query_args

        variables["latest"] = latest == True
        
        if cell_slug is not None:
            variables["cellSlugs"] = cell_slug if isinstance(cell_slug, list) else [cell_slug]

        return variables