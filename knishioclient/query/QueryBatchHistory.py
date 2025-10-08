# -*- coding: utf-8 -*-
from .Query import Query


class QueryBatchHistory(Query):
    """
    Query for retrieving batch history information
    """
    
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super().__init__(knish_io_client, query)
        
        # Reuse the same batch fields structure
        batch_fields = '''
            batchId,
            molecularHash,
            type,
            status,
            createdAt,
            wallet {
                address,
                bundleHash,
                amount,
                tokenSlug,
                token {
                    name,
                    amount
                },
                tokenUnits {
                    id,
                    name,
                    metas
                }
            },
            fromWallet {
                address,
                bundleHash,
                amount,
                batchId
            },
            toWallet {
                address,
                bundleHash,
                amount,
                batchId
            },
            sourceTokenUnits {
                id,
                name,
                metas
            },
            transferTokenUnits {
                id,
                name,
                metas
            },
            metas {
                key,
                value,
            },
            throughMetas {
                key,
                value
            }
        '''
        
        self.default_query = f'''query( $batchId: String ) {{
            BatchHistory( batchId: $batchId ) {{
                {batch_fields}
            }}
        }}'''
        
        self.query = query or self.default_query
    
    def create_response(self, response: dict):
        from ..response.Response import Response
        return Response(self, response)