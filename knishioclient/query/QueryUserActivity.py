# -*- coding: utf-8 -*-
from .Query import Query


class QueryUserActivity(Query):
    """
    Query for retrieving information about user activity
    """
    
    def __init__(self, knish_io_client: 'KnishIOClient', query: str = None):
        super().__init__(knish_io_client, query)
        
        # Simplified recursive structure (KISS principle - 3 levels deep is enough)
        self.default_query = '''query UserActivity (
            $bundleHash:String,
            $metaType: String,
            $metaId: String,
            $ipAddress: String,
            $browser: String,
            $osCpu: String,
            $resolution: String,
            $timeZone: String,
            $countBy: [CountByUserActivity],
            $interval: span
        ) {
            UserActivity (
                bundleHash: $bundleHash,
                metaType: $metaType,
                metaId: $metaId,
                ipAddress: $ipAddress,
                browser: $browser,
                osCpu: $osCpu,
                resolution: $resolution,
                timeZone: $timeZone,
                countBy: $countBy,
                interval: $interval
            ) {
                createdAt,
                bundleHash,
                metaType,
                metaId,
                instances {
                    bundleHash,
                    metaType,
                    metaId,
                    jsonData,
                    createdAt,
                    updatedAt
                },
                instanceCount {
                    id,
                    count,
                    instances {
                        id,
                        count,
                        instances {
                            id,
                            count
                        }
                    }
                }
            }
        }'''
        
        self.query = query or self.default_query
    
    def create_response(self, response: dict):
        from ..response.Response import Response
        return Response(self, response)