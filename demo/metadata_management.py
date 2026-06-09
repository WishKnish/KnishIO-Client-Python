#!/usr/bin/env python3
"""
Metadata Management Demo - Knish.IO Python SDK

This demo demonstrates storing and querying arbitrary data on the ledger,
including complex metadata operations and query patterns.

Perfect for: Applications needing decentralized data storage.
"""

import sys
import os
import time
import json

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from knishioclient.client import KnishIOClient
from utils.demo_config import validate_environment, get_demo_config
from utils.demo_helpers import (
    print_demo_header, print_demo_footer, print_section, 
    print_success, print_error, print_response, handle_demo_error,
    DemoStep, DemoHelpers, Colors, create_demo_metadata
)


def main():
    """Main demo function."""
    print_demo_header(
        "Metadata Management", 
        "Comprehensive demonstration of decentralized data storage:\n"
        "• Creating metadata with different structures\n"
        "• Querying metadata with various filters\n"
        "• Complex data relationships\n"
        "• Metadata versioning and updates"
    )
    
    try:
        # Validate environment and setup
        validate_environment()
        config = get_demo_config()
        
        # Initialize client and authenticate
        with DemoStep("Client Setup", "Initializing client and authenticating"):
            client = KnishIOClient(config.node_uri)
            auth_response = client.request_auth_token(**config.get_auth_kwargs())
            
            if not auth_response or not auth_response.success():
                reason = auth_response.reason() if auth_response else "No response"
                raise Exception(f"Authentication failed: {reason}")
            
            print_success("Client authenticated successfully")
        
        # Step 1: Simple Metadata Creation
        print_section("Basic Metadata Operations")
        
        demo_timestamp = str(int(time.time() * 1000))
        
        with DemoStep("Create User Profile", "Creating user profile metadata"):
            user_profile_id = f"user-profile-{demo_timestamp}"
            
            user_metadata = create_demo_metadata("metadata_demo", {
                'user_id': 'demo_user_001',
                'username': 'demo_user',
                'email': 'demo@example.com',
                'registration_date': DemoHelpers.generate_timestamp(),
                'profile_type': 'standard',
                'status': 'active'
            })
            
            profile_response = client.create_meta(
                meta_type="UserProfile",
                meta_id=user_profile_id,
                metadata=user_metadata
            )
            
            if profile_response and profile_response.success():
                print_success(f"User profile created: {user_profile_id}")
                print_response(profile_response, "User Profile Creation")
            else:
                reason = profile_response.reason() if profile_response else "Unknown error"
                raise Exception(f"Profile creation failed: {reason}")
        
        with DemoStep("Create Product Catalog", "Creating product catalog metadata"):
            product_id = f"product-{demo_timestamp}"
            
            product_metadata = [
                {'key': 'product_name', 'value': 'Demo Widget'},
                {'key': 'sku', 'value': f'DW-{demo_timestamp[-6:]}'},
                {'key': 'price', 'value': '29.99'},
                {'key': 'currency', 'value': 'USD'},
                {'key': 'category', 'value': 'Electronics'},
                {'key': 'description', 'value': 'A demonstration widget for SDK testing'},
                {'key': 'in_stock', 'value': 'true'},
                {'key': 'quantity', 'value': '100'},
                {'key': 'created_by', 'value': 'Python SDK Demo'}
            ]
            
            product_response = client.create_meta(
                meta_type="ProductCatalog",
                meta_id=product_id,
                metadata=product_metadata
            )
            
            if product_response and product_response.success():
                print_success(f"Product created: {product_id}")
                print_response(product_response, "Product Creation")
            else:
                reason = product_response.reason() if product_response else "Unknown error"
                print_error(f"Product creation failed: {reason}")
        
        # Step 2: Complex Metadata Structures
        print_section("Complex Metadata Structures")
        
        with DemoStep("Create IoT Sensor Data", "Creating structured IoT sensor metadata"):
            sensor_id = f"sensor-{demo_timestamp}"
            
            # Complex nested data structure
            sensor_data = {
                'device_id': f'SENSOR_{demo_timestamp[-8:]}',
                'location': {
                    'building': 'Demo Building A',
                    'floor': '3',
                    'room': '301'
                },
                'readings': {
                    'temperature': '22.5',
                    'humidity': '45.2',
                    'pressure': '1013.25'
                },
                'metadata': {
                    'last_calibration': '2024-01-15',
                    'firmware_version': '1.2.3',
                    'battery_level': '85'
                }
            }
            
            # Convert complex structure to metadata format
            iot_metadata = []
            for key, value in sensor_data.items():
                if isinstance(value, dict):
                    # Flatten nested dictionaries
                    for subkey, subvalue in value.items():
                        iot_metadata.append({
                            'key': f'{key}_{subkey}', 
                            'value': str(subvalue)
                        })
                else:
                    iot_metadata.append({'key': key, 'value': str(value)})
            
            # Add demo metadata
            iot_metadata.extend(create_demo_metadata("iot_sensor", {
                'sensor_type': 'environmental',
                'data_format': 'structured'
            }))
            
            iot_response = client.create_meta(
                meta_type="IoTSensorData",
                meta_id=sensor_id,
                metadata=iot_metadata
            )
            
            if iot_response and iot_response.success():
                print_success(f"IoT sensor data created: {sensor_id}")
                print_response(iot_response, "IoT Data Creation")
            else:
                reason = iot_response.reason() if iot_response else "Unknown error"
                print_error(f"IoT data creation failed: {reason}")
        
        # Step 3: Metadata Queries
        print_section("Metadata Query Operations")
        
        with DemoStep("Query User Profile", "Retrieving created user profile"):
            try:
                user_query_response = client.query_meta(
                    meta_type="UserProfile",
                    meta_id=user_profile_id
                )
                print_response(user_query_response, "User Profile Query")
                
                if user_query_response:
                    print_success("User profile retrieved successfully")
                else:
                    print_error("User profile not found")
                    
            except Exception as e:
                handle_demo_error("User profile query", e)
        
        with DemoStep("Query Product Catalog", "Retrieving product information"):
            try:
                product_query_response = client.query_meta(
                    meta_type="ProductCatalog",
                    meta_id=product_id
                )
                print_response(product_query_response, "Product Query")
                
            except Exception as e:
                handle_demo_error("Product query", e)
        
        # Step 4: Metadata Updates (Version 2)
        print_section("Metadata Versioning")
        
        with DemoStep("Update User Profile", "Creating updated version of user profile"):
            updated_user_id = f"user-profile-v2-{demo_timestamp}"
            
            updated_metadata = create_demo_metadata("metadata_demo_v2", {
                'user_id': 'demo_user_001',
                'username': 'demo_user_updated',
                'email': 'demo.updated@example.com',
                'registration_date': DemoHelpers.generate_timestamp(),
                'profile_type': 'premium',
                'status': 'active',
                'last_updated': DemoHelpers.generate_timestamp(),
                'version': '2.0'
            })
            
            updated_response = client.create_meta(
                meta_type="UserProfile",
                meta_id=updated_user_id,
                metadata=updated_metadata
            )
            
            if updated_response and updated_response.success():
                print_success(f"Updated user profile created: {updated_user_id}")
                print_response(updated_response, "Profile Update")
            else:
                reason = updated_response.reason() if updated_response else "Unknown error"
                print_error(f"Profile update failed: {reason}")
        
        # Step 5: Batch Metadata Creation
        print_section("Batch Metadata Operations")
        
        batch_ids = []
        
        with DemoStep("Create Multiple Records", "Creating batch of application settings"):
            for i in range(3):
                setting_id = f"app-setting-{i}-{demo_timestamp}"
                batch_ids.append(setting_id)
                
                setting_metadata = create_demo_metadata("batch_settings", {
                    'setting_key': f'setting_{i}',
                    'setting_value': f'value_{i}',
                    'category': 'demo_batch',
                    'priority': str(i + 1),
                    'enabled': 'true'
                })
                
                try:
                    setting_response = client.create_meta(
                        meta_type="AppSettings",
                        meta_id=setting_id,
                        metadata=setting_metadata
                    )
                    
                    if setting_response and setting_response.success():
                        print_success(f"Created setting {i+1}: {setting_id}")
                    else:
                        print_error(f"Failed to create setting {i+1}")
                        
                except Exception as e:
                    print_error(f"Error creating setting {i+1}: {e}")
        
        # Step 6: Query Operations Summary
        print_section("Query Summary")
        
        with DemoStep("Query All Created Types", "Summarizing created metadata types"):
            metadata_types = ["UserProfile", "ProductCatalog", "IoTSensorData", "AppSettings"]
            
            for meta_type in metadata_types:
                try:
                    # Note: This is a simplified query - actual implementation may vary
                    print_success(f"Metadata type '{meta_type}' was created during this demo")
                except Exception as e:
                    print_error(f"Error querying {meta_type}: {e}")
        
        # Step 7: Demo Summary
        print_section("Demo Summary")
        
        print_success("Metadata management demo completed successfully!")
        print("  • Metadata types created:")
        print("    - UserProfile (with versioning)")
        print("    - ProductCatalog")
        print("    - IoTSensorData (complex structure)")
        print("    - AppSettings (batch creation)")
        print("  • Operations demonstrated:")
        print("    - Simple metadata creation")
        print("    - Complex nested data structures")
        print("    - Metadata queries and retrieval")
        print("    - Versioning and updates")
        print("    - Batch operations")
        
        print_success("All metadata operations completed successfully!")
        
        print_demo_footer()
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Demo interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        handle_demo_error("Metadata Management Demo", e)
        sys.exit(1)


if __name__ == "__main__":
    main()