# -*- coding: utf-8 -*-
from .Query import Query


class QueryAtom(Query):
    """
    Query for getting atomic data from the ledger
    """
    
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super().__init__(knish_io_client, query)
        self.default_query = '''query(
            $molecularHashes: [String!],
            $bundleHashes: [String!],
            $positions:[String!],
            $walletAddresses: [String!],
            $isotopes: [String!],
            $tokenSlugs: [String!],
            $cellSlugs: [String!],
            $batchIds: [String!],
            $values: [String!],
            $metaTypes: [String!],
            $metaIds: [String!],
            $indexes: [String!],
            $filter: [ MetaFilter! ],
            $latest: Boolean,
            $queryArgs: QueryArgs,
        ) {
            Atom(
                molecularHashes: $molecularHashes,
                bundleHashes: $bundleHashes,
                positions: $positions,
                walletAddresses: $walletAddresses,
                isotopes: $isotopes,
                tokenSlugs: $tokenSlugs,
                cellSlugs: $cellSlugs,
                batchIds: $batchIds,
                values: $values,
                metaTypes: $metaTypes,
                metaIds: $metaIds,
                indexes: $indexes,
                filter: $filter,
                latest: $latest,
                queryArgs: $queryArgs,
            ) {
                instances {
                    position,
                    walletAddress,
                    tokenSlug,
                    isotope,
                    index,
                    molecularHash,
                    metaId,
                    metaType,
                    metasJson,
                    batchId,
                    value,
                    bundleHashes,
                    cellSlugs,
                    createdAt,
                    otsFragment
                },
                paginatorInfo {
                    currentPage,
                    total
                }
            }
        }'''
        
        self.query = query or self.default_query
    
    def create_response(self, response: dict):
        from ..response.Response import Response
        return Response(self, response)