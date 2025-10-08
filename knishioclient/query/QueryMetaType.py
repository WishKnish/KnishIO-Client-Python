# -*- coding: utf-8 -*-
from ..response import ResponseMetaType
from .Query import Query


class QueryMetaType(Query):
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super(QueryMetaType, self).__init__(knish_io_client, query)
        self.default_query = 'query( $metaType: String, $metaTypes: [ String! ], $metaId: String, $metaIds: [ String! ], $key: String, $keys: [ String! ], $value: String, $values: [ String! ], $count: String, $latest: Boolean, $filter: [ MetaFilter! ], $queryArgs: QueryArgs, $countBy: String, $cellSlug: String ) { MetaType( metaType: $metaType, metaTypes: $metaTypes, metaId: $metaId, metaIds: $metaIds, key: $key, keys: $keys, value: $value, values: $values, count: $count, filter: $filter, queryArgs: $queryArgs, countBy: $countBy, cellSlug: $cellSlug ) @fields }'
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
              "metas(latest:$latest)": {
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
        return ResponseMetaType(self, response)

    @classmethod
    def create_variables(
            cls,
            meta_type: str | list = None,
            meta_id: str | list = None,
            key: str | list = None,
            value: str | list = None,
            latest: bool = None,
            filter: dict = None,
            query_args: dict = None,
            count: str = None,
            count_by: str = None,
            cell_slug: str = None
    ) -> dict:
        variables = {}

        if meta_type is not None:
            if isinstance(meta_type, str):
                variables.update({'metaType': meta_type})
            else:
                variables.update({'metaTypes': meta_type})
        if meta_id is not None:
            if isinstance(meta_id, str):
                variables.update({'metaId': meta_id})
            else:
                variables.update({'metaIds': meta_id})
        if key is not None:
            if isinstance(key, str):
                variables.update({'key': key})
            else:
                variables.update({'keys': key})
        if value is not None:
            if isinstance(value, str):
                variables.update({'value': value})
            else:
                variables.update({'values': value})

        variables.update({'latest': latest == True})

        if filter is not None:
            variables.update({'filter': filter})
        if query_args is not None:
            if "limit" not in query_args or query_args.get("limit") == 0:
                query_args["limit"] = "*"
            variables["queryArgs"] = query_args
        if count_by is not None:
            variables["countBy"] = count_by
        if count is not None:
            variables["count"] = count
        if cell_slug is not None:
            variables["cellSlug"] = cell_slug

        return variables