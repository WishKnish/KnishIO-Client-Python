# Knish.IO Python SDK Demo Scripts

This directory contains practical demonstration scripts showcasing the capabilities of the Knish.IO Python SDK. Each script is self-contained and demonstrates different aspects of post-blockchain distributed ledger technology.

## Prerequisites

Before running the demos, ensure you have:

1. **Python 3.8+** installed
2. **Virtual environment** activated:
   ```bash
   cd /path/to/KnishIO-Client-Python
   source venv/bin/activate
   ```
3. **Dependencies installed**:
   ```bash
   pip install -r requirements.txt
   ```
4. **Server access** - either set up your own or use the demo node
5. **Environment variables** (optional):
   - `KNISHIO_NODE_URI` - GraphQL endpoint (default: http://localhost:8000/graphql)
   - `KNISHIO_SECRET` - Your secret (auto-generated if not provided)
   - `KNISHIO_CELL` - Application cell slug (default: demo-cell)

## Running Demos

From the demo directory:

```bash
# Run a specific demo
python basic_usage.py

# Or with custom configuration
KNISHIO_NODE_URI=https://your-node.com/graphql python basic_usage.py

# With verbose output
DEMO_VERBOSE=true python token_operations.py
```

## Available Demos

### 1. **basic_usage.py** - Getting Started
The simplest introduction to the SDK covering:
- Client initialization and configuration
- Authentication (profile and guest modes)
- Balance queries and wallet operations
- Bundle information and basic queries

**Perfect for:** First-time users wanting to understand the basics.

### 2. **token_operations.py** - Token Management
Comprehensive token operations including:
- Creating fungible tokens
- Token transfers between wallets
- Burning and replenishing tokens
- Balance verification and token properties

**Perfect for:** Developers building token-based applications.

### 3. **metadata_management.py** - Data Storage
Store and query arbitrary data on the ledger:
- User profiles and application data
- Product catalogs and inventories
- IoT sensor data and measurements
- Complex queries with filters
- Metadata versioning and history

**Perfect for:** Applications needing decentralized data storage.

### 4. **wallet_management.py** - Wallet Operations
Advanced wallet management features:
- Wallet generation and mechanics
- Multi-token wallet operations
- ContinuID position tracking
- Wallet bundle operations
- Address generation patterns

**Perfect for:** Understanding wallet architecture and identity management.

### 5. **message_encryption.py** - Secure Communication
Wallet-to-wallet message encryption:
- Public/private key generation
- Message encryption and decryption
- Cross-wallet secure communication
- Key sharing and management

**Perfect for:** Building secure messaging applications.

### 6. **event_factory.py** - Event Tracking
Event creation and management system:
- Factory pattern for event creation
- Automatic metadata collection
- Event querying and filtering
- UUID generation and tracking

**Perfect for:** Applications requiring event logging and tracking.

### 7. **complete_workflow.py** - Full Feature Demo
Comprehensive demonstration of all SDK features:
- Complete workflow from authentication to complex operations
- All major SDK operations in sequence
- Error handling patterns and best practices
- Production-ready code structure

**Perfect for:** Understanding how all features work together.

## Demo Patterns

### Basic Pattern
```python
# 1. Initialize client
from knishioclient.client import KnishIOClient
client = KnishIOClient('http://localhost:8000/graphql')

# 2. Authenticate
client.request_auth_token(secret='your-secret', cell_slug='demo-cell')

# 3. Perform operations
response = client.query_balance('USER')
```

### Environment Configuration
```python
import os
from demo.utils.demo_config import DemoConfig

# Use environment variables with defaults
config = DemoConfig()
client = KnishIOClient(config.node_uri)
```

### Error Handling
```python
try:
    response = client.some_operation()
    if response.success():
        # Handle success
        data = response.data()
    else:
        # Handle failure
        print(f"Failed: {response.reason()}")
except Exception as e:
    print(f"Error: {e}")
```

## Security Notes

⚠️ **Important Security Considerations:**

1. **Never hardcode secrets** in production code
2. **Use secure key management** systems in production
3. **Enable encryption** for node communication when available
4. **Validate all inputs** before ledger operations
5. **Handle errors gracefully** without exposing sensitive data

## Demo vs Production

These demos use simplified patterns for clarity:

**Demo Pattern:**
```python
secret = generate_demo_secret()  # Auto-generated for demo
```

**Production Pattern:**
```python
secret = os.getenv('KNISHIO_SECRET')  # From secure storage
if not secret:
    raise ValueError("Secret must be provided in production")
```

## Configuration

### Environment Variables

- `KNISHIO_NODE_URI`: GraphQL endpoint URL
- `KNISHIO_SECRET`: Client secret (2048 character hex string)
- `KNISHIO_CELL`: Cell slug for application isolation
- `DEMO_VERBOSE`: Enable verbose logging (true/false)
- `DEMO_MODE`: Demo mode vs production mode (demo/production)

### Local Server Setup

If running against a local server:
```bash
# Example with local server
export KNISHIO_NODE_URI=http://localhost:8000/graphql
export KNISHIO_CELL=test-cell
python basic_usage.py
```

## Troubleshooting

### Common Issues

1. **Authentication fails**
   - Check node URI is correct and accessible
   - Verify secret format (should be hex string)
   - Ensure network connectivity

2. **Import errors**
   - Ensure virtual environment is activated
   - Verify knishioclient package is installed
   - Check Python path includes SDK directory

3. **Connection timeouts**
   - Verify server is running and accessible
   - Check firewall settings
   - Try with different node URI

### Debug Mode

Enable verbose logging:
```bash
DEMO_VERBOSE=true python basic_usage.py
```

Or programmatically:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Next Steps

After running these demos:

1. Read the [Python SDK documentation](../README.md) for detailed API reference
2. Check the [integration tests](../../../test_python_server_integration.py) for additional examples
3. Explore the [validation system](../../../validation/) for cross-SDK compatibility
4. Join the community for support and discussions

## Contributing

Have a demo idea? We welcome contributions! Please:
1. Follow the existing demo patterns
2. Include comprehensive error handling
3. Add clear documentation and comments
4. Test against multiple node configurations

## License

These demos are part of the Knish.IO Python SDK and follow the same license terms.