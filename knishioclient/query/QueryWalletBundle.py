# -*- coding: utf-8 -*-
from ..response import ResponseWalletBundle
from .Query import Query


class QueryWalletBundle(Query):
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super(QueryWalletBundle, self).__init__(knish_io_client, query)
        self.default_query = 'query( $bundleHash: String, $bundleHashes: [ String! ], $key: String, $keys: [ String! ], $value: String, $values: [ String! ], $keys_values: [ MetaInput ], $latest: Boolean, $limit: Int, $order: String ) { WalletBundle( bundleHash: $bundleHash, bundleHashes: $bundleHashes, key: $key, keys: $keys, value: $value, values: $values, keys_values: $keys_values, latest: $latest, limit: $limit, order: $order ) @fields }'
        self.fields = {
            'bundleHash': None,
            'slug': None,
            'metas': {
                'molecularHash': None,
                'position': None,
                'key': None,
                'value': None,
                'createdAt': None,
            },
            # 'molecules',
            # 'wallets',
            'createdAt': None,
        }

        self.query = query or self.default_query

    @classmethod
    def create_variables(cls, bundle_hash=None, key=None, value=None, latest=True):
        variables = {
            'latest': latest,
        }

        if bundle_hash is not None:
            if isinstance(bundle_hash, (str, bytes)):
                variables.update({'bundleHash': bundle_hash})
            else:
                variables.update({'bundleHashes': bundle_hash})

        if key is not None:
            if isinstance(key, (str, bytes)):
                variables.update({'key': key})
            else:
                variables.update({'keys': key})

        if value is not None:
            if isinstance(value, (str, bytes)):
                variables.update({'value': value})
            else:
                variables.update({'values': value})

        return variables

    def create_response(self, response):
        return ResponseWalletBundle(self, response)