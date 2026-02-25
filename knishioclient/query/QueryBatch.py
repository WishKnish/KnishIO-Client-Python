# -*- coding: utf-8 -*-
from .Query import Query


class QueryBatch(Query):
    """
    Query for retrieving batch information
    """
    
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super().__init__(knish_io_client, query)
        
        # Define batch fields once for reuse
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
            Batch( batchId: $batchId ) {{
                {batch_fields},
                children {{
                    {batch_fields}
                }}
            }}
        }}'''
        
        self.query = query or self.default_query
    
    def create_response(self, response: dict):
        from ..response.Response import Response
        return Response(self, response)