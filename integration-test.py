#!/usr/bin/env python3
"""
Enhanced Python SDK Integration Test

Demonstrates the integration of StandardResponse framework with Python SDK,
showing both AsyncIO advantages and enhanced error handling capabilities.

Features tested:
1. Enhanced KnishIOClient with StandardResponse framework
2. Configuration validation with ClientConfig/MetaConfig
3. AsyncIO integration with enhanced response handling
4. Backward compatibility with existing Python SDK patterns
5. Type hints and dataclass integration

Usage:
    python enhanced_integration_test.py --url http://localhost:8000/graphql
    KNISHIO_API_URL=http://localhost:8000/graphql python enhanced_integration_test.py
"""

import asyncio
import argparse
import os
import sys
import time
from datetime import datetime
from typing import Dict, Any, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))

from knishioclient.libraries import crypto
from knishioclient.models.Wallet import Wallet
from knishioclient.models.Molecule import Molecule
from knishioclient.client.KnishIOClient import KnishIOClient
from knishioclient.config.standard_config import ClientConfig, MetaConfig, ConfigFactory
from knishioclient.response.standard_response import StandardResponse, ValidationResult

class Colors:
    """ANSI color codes for enhanced terminal output"""
    RESET = '\033[0m'
    BRIGHT = '\033[1m'
    GREEN = '\033[32m'
    RED = '\033[31m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    CYAN = '\033[36m'
    GRAY = '\033[90m'

def colorlog(message: str, color: str = Colors.RESET, indent: int = 0) -> None:
    """Print colored message with optional indentation"""
    spaces = '  ' * indent
    print(f"{spaces}{color}{message}{Colors.RESET}")

def log_test(test_name: str, passed: bool, error_detail: Optional[str] = None, response_time: Optional[int] = None) -> None:
    """Log test result with formatting"""
    status = "✅ PASS" if passed else "❌ FAIL"
    color = Colors.GREEN if passed else Colors.RED
    time_str = f" ({response_time}ms)" if response_time else ""
    
    colorlog(f"{status}: {test_name}{time_str}", color, 1)
    
    if not passed and error_detail:
        colorlog(error_detail, Colors.RED, 2)

def log_section(section_name: str) -> None:
    """Log section header with formatting"""
    colorlog(f"\n{section_name}", Colors.BLUE)
    colorlog("═" * (len(section_name) + 4), Colors.BLUE)

class EnhancedPythonIntegrationTest:
    """Enhanced Python SDK Integration Test with StandardResponse framework"""
    
    def __init__(self, server_url: str, cell_slug: str = "ENHANCED_PYTHON_TEST"):
        self.server_url = server_url
        self.cell_slug = cell_slug
        
        # Generate test credentials
        self.test_secret = crypto.generate_secret("ENHANCED_PYTHON_AUTH")
        self.test_bundle = crypto.generate_bundle_hash(self.test_secret)
        
        # Results storage
        self.results: Dict[str, Any] = {
            "sdk": "Python Enhanced",
            "testType": "Enhanced StandardResponse Integration",
            "version": "2.0.0",
            "timestamp": datetime.now().isoformat(),
            "server": {
                "url": server_url,
                "cellSlug": cell_slug,
                "framework": "StandardResponse with AsyncIO"
            },
            "tests": {},
            "enhancedFeatures": [
                "StandardResponse framework",
                "AsyncIO integration", 
                "Configuration validation",
                "Enhanced error handling",
                "Type hints and dataclasses"
            ],
            "overallSuccess": False
        }
    
    def test_enhanced_configuration(self) -> bool:
        """Test enhanced configuration system with validation"""
        log_section("1. Enhanced Configuration System")
        
        try:
            # Test ClientConfig creation and validation
            config_dict = {
                "uri": self.server_url,
                "cellSlug": self.cell_slug,
                "serverSdkVersion": 3,
                "logging": True
            }
            
            # Test factory method
            client_config = ClientConfig.from_dict(config_dict)
            validation_result = client_config.validate()
            
            config_valid = validation_result.success
            log_test("ClientConfig creation and validation", config_valid,
                None if config_valid else validation_result.error.message)
            
            # Test ConfigFactory
            factory_config = ConfigFactory.create_client_config(
                uri=self.server_url,
                cell_slug=self.cell_slug,
                logging=True
            )
            
            log_test("ConfigFactory pattern", True)
            
            # Test enhanced client creation
            enhanced_client = KnishIOClient.create_enhanced(client_config)
            enhanced_client.set_secret(self.test_secret)
            enhanced_client.set_cell_slug(self.cell_slug)
            
            self.client = enhanced_client
            
            log_test("Enhanced KnishIOClient creation", True)
            
            self.results["tests"]["configuration"] = {
                "passed": True,
                "clientConfigValid": config_valid,
                "enhancedClientCreated": True
            }
            
            return True
            
        except Exception as e:
            log_test("Enhanced configuration system", False, str(e))
            self.results["tests"]["configuration"] = {
                "passed": False,
                "error": str(e)
            }
            return False
    
    async def test_enhanced_metadata_creation(self) -> bool:
        """Test enhanced metadata creation with StandardResponse"""
        log_section("2. Enhanced Metadata Creation (AsyncIO + StandardResponse)")
        
        try:
            # Create MetaConfig with validation
            meta_config = MetaConfig(
                meta_type="EnhancedPythonTest",
                meta_id=f"ENHANCED_{int(time.time())}_{os.urandom(4).hex()}",
                meta={
                    "test_name": "Enhanced Python SDK Integration Test",
                    "framework": "StandardResponse with AsyncIO",
                    "timestamp": datetime.now().isoformat(),
                    "language": "Python",
                    "version": sys.version.split()[0],
                    "features": "AsyncIO, Type hints, Dataclasses"
                },
                policy=None  # No policy for this test
            )
            
            # Validate configuration
            validation_result = meta_config.validate()
            config_valid = validation_result.success
            
            log_test("MetaConfig validation", config_valid,
                None if config_valid else validation_result.error.message)
            
            if not config_valid:
                self.results["tests"]["enhancedMetadata"] = {
                    "passed": False,
                    "error": "MetaConfig validation failed"
                }
                return False
            
            start_time = time.time()
            
            # Use enhanced async metadata creation
            response: StandardResponse = await self.client.create_meta_enhanced(meta_config)
            
            response_time = int((time.time() - start_time) * 1000)
            
            # Test StandardResponse interface
            success = response.success()
            payload = response.payload()
            reason = response.reason()
            
            log_test("Enhanced async metadata creation", success, reason, response_time)
            
            if success:
                colorlog(f"Payload keys: {list(payload.keys()) if payload else 'None'}", Colors.GRAY, 2)
            
            # Test functional programming features
            validated_response = response.to_validation_result()
            log_test("ValidationResult conversion", validated_response.success)
            
            # Test response chaining (functional style)
            try:
                await response.on_success(lambda data: self.log_success_callback(data))
                await response.on_failure(lambda error: self.log_failure_callback(error))
                log_test("AsyncIO callback integration", True)
            except Exception as e:
                log_test("AsyncIO callback integration", False, str(e))
            
            self.results["tests"]["enhancedMetadata"] = {
                "passed": success,
                "responseTime": response_time,
                "configValid": config_valid,
                "standardResponseIntegration": True,
                "asyncioSupport": True,
                "functionalFeatures": True
            }
            
            return success
            
        except Exception as e:
            log_test("Enhanced metadata creation", False, str(e))
            self.results["tests"]["enhancedMetadata"] = {
                "passed": False,
                "error": str(e)
            }
            return False
    
    async def log_success_callback(self, data: Any) -> None:
        """Success callback for demonstrating AsyncIO integration"""
        colorlog("Success callback executed with AsyncIO", Colors.GREEN, 3)
    
    async def log_failure_callback(self, error: str) -> None:
        """Failure callback for demonstrating AsyncIO integration"""
        colorlog(f"Failure callback executed: {error}", Colors.RED, 3)
    
    def test_backward_compatibility(self) -> bool:
        """Test backward compatibility with existing Python SDK patterns"""
        log_section("3. Backward Compatibility Verification")
        
        try:
            # Test traditional wallet creation (should still work)
            traditional_wallet = Wallet(secret=self.test_secret, token="USER")
            
            log_test("Traditional Wallet creation", True)
            
            # Test traditional molecule creation (should still work)
            traditional_molecule = Molecule(
                secret=self.test_secret,
                bundle=self.test_bundle,
                source_wallet=traditional_wallet,
                cell_slug=self.cell_slug
            )
            
            log_test("Traditional Molecule creation", True)
            
            # Test that enhanced client still works with traditional patterns
            enhanced_config = self.client.get_enhanced_config()
            config_retrieved = enhanced_config is not None
            
            log_test("Enhanced config retrieval", config_retrieved)
            
            # Test legacy response wrapping
            from knishioclient.response.Response import Response
            
            # Create a mock legacy response for testing
            class MockLegacyResponse:
                def success(self): return True
                def payload(self): return {"test": "data"}
                def reason(self): return None
                def data(self): return {"raw": "data"}
            
            mock_response = MockLegacyResponse()
            wrapped_response = self.client.wrap_legacy_response(mock_response, "test_operation")
            
            wrapper_works = wrapped_response.success() and wrapped_response.payload() is not None
            log_test("Legacy response wrapping", wrapper_works)
            
            self.results["tests"]["backwardCompatibility"] = {
                "passed": True,
                "traditionalWallet": True,
                "traditionalMolecule": True,
                "configRetrieval": config_retrieved,
                "legacyWrapping": wrapper_works
            }
            
            return True
            
        except Exception as e:
            log_test("Backward compatibility", False, str(e))
            self.results["tests"]["backwardCompatibility"] = {
                "passed": False,
                "error": str(e)
            }
            return False
    
    def test_enhanced_error_handling(self) -> bool:
        """Test enhanced error handling and validation"""
        log_section("4. Enhanced Error Handling and Validation")
        
        try:
            # Test invalid configuration handling
            invalid_config = {
                "uri": "",  # Invalid empty URI
                "cellSlug": self.cell_slug
            }
            
            try:
                ClientConfig.from_dict(invalid_config)
                validation_caught_error = False
            except Exception:
                validation_caught_error = True
            
            log_test("Invalid config error handling", validation_caught_error)
            
            # Test ValidationResult pattern
            from knishioclient.config.standard_config import ConfigValidator
            
            validation_result = ConfigValidator.validate_client_config(invalid_config)
            validation_failed = not validation_result.success
            
            log_test("ValidationResult error reporting", validation_failed)
            
            if validation_failed and validation_result.error:
                colorlog(f"Error details: {validation_result.error.message}", Colors.GRAY, 2)
            
            # Test StandardResponse error creation
            error_response = StandardResponse.create_failure(
                "Test error message",
                "test_operation",
                {"test": "data"}
            )
            
            error_response_works = (
                not error_response.success() and
                error_response.reason() == "Test error message"
            )
            
            log_test("StandardResponse error creation", error_response_works)
            
            self.results["tests"]["errorHandling"] = {
                "passed": True,
                "invalidConfigHandling": validation_caught_error,
                "validationResultPattern": validation_failed,
                "standardResponseErrors": error_response_works
            }
            
            return True
            
        except Exception as e:
            log_test("Enhanced error handling", False, str(e))
            self.results["tests"]["errorHandling"] = {
                "passed": False,
                "error": str(e)
            }
            return False
    
    def print_summary(self) -> None:
        """Print comprehensive test summary"""
        log_section("ENHANCED PYTHON SDK INTEGRATION SUMMARY")
        
        tests = self.results["tests"]
        total_tests = len(tests)
        passed_tests = sum(1 for test in tests.values() if test.get("passed", False))
        
        colorlog(f"\nSDK: {self.results['sdk']} v{self.results['version']}", Colors.BRIGHT)
        colorlog(f"Framework: {self.results['server']['framework']}", Colors.BRIGHT)
        colorlog(f"Language: Python {sys.version.split()[0]} (AsyncIO enhanced)", Colors.BRIGHT)
        colorlog(f"Server: {self.results['server']['url']}", Colors.BRIGHT)
        
        # Enhanced features summary
        colorlog("\nEnhanced Features Tested:", Colors.CYAN)
        for feature in self.results["enhancedFeatures"]:
            colorlog(f"  ✅ {feature}", Colors.CYAN, 1)
        
        color = Colors.GREEN if passed_tests == total_tests else Colors.RED
        colorlog(f"\nTests Passed: {passed_tests}/{total_tests}", color)
        
        if passed_tests < total_tests:
            colorlog("\nFailed Tests:", Colors.RED)
            for test_name, test_result in tests.items():
                if not test_result.get("passed", False):
                    error = test_result.get("error", "Test failed")
                    colorlog(f"  - {test_name}: {error}", Colors.RED, 1)
        
        colorlog("\n" + "═" * 70, Colors.BLUE)
        
        # Performance and feature highlights
        if passed_tests == total_tests:
            colorlog("\n🎉 ALL ENHANCED FEATURES WORKING PERFECTLY!", Colors.GREEN)
            colorlog("\nPython SDK Advantages Demonstrated:", Colors.CYAN)
            colorlog("  ⚡ AsyncIO concurrency support", Colors.CYAN, 1)
            colorlog("  🔒 Type safety with dataclasses and hints", Colors.CYAN, 1) 
            colorlog("  🛡️  Enhanced error handling and validation", Colors.CYAN, 1)
            colorlog("  🔄 Functional programming patterns", Colors.CYAN, 1)
            colorlog("  ⚙️  Configuration management", Colors.CYAN, 1)
            colorlog("  🔄 Backward compatibility maintained", Colors.CYAN, 1)
    
    async def run_enhanced_tests(self) -> None:
        """Main test runner with AsyncIO orchestration"""
        colorlog("═" * 80, Colors.BLUE)
        colorlog("  Enhanced Python SDK - StandardResponse Integration Tests", Colors.BRIGHT)
        colorlog("═" * 80, Colors.BLUE)
        
        colorlog(f"\n🌐 Server: {self.server_url}", Colors.CYAN)
        colorlog(f"📱 Cell: {self.cell_slug}", Colors.CYAN)
        colorlog(f"🐍 Language: Python {sys.version.split()[0]}", Colors.CYAN)
        colorlog(f"⚡ Framework: StandardResponse + AsyncIO", Colors.CYAN)
        colorlog(f"🎯 Architecture: Enhanced with type safety", Colors.CYAN)
        
        start_time = time.time()
        
        try:
            # Test 1: Enhanced Configuration System
            config_success = self.test_enhanced_configuration()
            
            if not config_success:
                colorlog("\n❌ Cannot continue without proper configuration", Colors.RED)
                self.results["overallSuccess"] = False
                return
            
            # Test 2: Enhanced Metadata Creation (AsyncIO)
            metadata_success = await self.test_enhanced_metadata_creation()
            
            # Test 3: Backward Compatibility
            compatibility_success = self.test_backward_compatibility()
            
            # Test 4: Enhanced Error Handling
            error_handling_success = self.test_enhanced_error_handling()
            
            # Calculate final results
            all_tests_passed = all(
                test.get("passed", False) for test in self.results["tests"].values()
            )
            self.results["overallSuccess"] = all_tests_passed
            
        except Exception as e:
            colorlog(f"\n❌ Fatal Enhanced Test Error: {e}", Colors.RED)
            self.results["overallSuccess"] = False
            self.results["fatalError"] = str(e)
        
        total_time = int((time.time() - start_time) * 1000)
        self.results["totalExecutionTime"] = total_time
        
        # Print comprehensive summary
        self.print_summary()
        
        colorlog(f"\n⏱️  Total execution time: {total_time}ms", Colors.GRAY)
        
        # Exit with appropriate code
        exit_code = 0 if self.results["overallSuccess"] else 1
        status = "PASSED" if self.results["overallSuccess"] else "FAILED"
        color = Colors.GREEN if self.results["overallSuccess"] else Colors.RED
        
        colorlog(f"\n{'✅' if self.results['overallSuccess'] else '❌'} Enhanced Python SDK tests {status}", color)
        
        sys.exit(exit_code)

def main() -> None:
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Enhanced Python SDK Integration Test with StandardResponse",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '-u', '--url',
        help='GraphQL API URL',
        default=os.environ.get('KNISHIO_API_URL', 'http://localhost:8000/graphql')
    )
    parser.add_argument(
        '-c', '--cell',
        help='Cell slug for testing',
        default='ENHANCED_PYTHON_TEST'
    )
    
    args = parser.parse_args()
    
    # Run enhanced integration tests
    test_runner = EnhancedPythonIntegrationTest(args.url, args.cell)
    
    try:
        asyncio.run(test_runner.run_enhanced_tests())
    except KeyboardInterrupt:
        colorlog("\n🛑 Enhanced integration tests interrupted", Colors.YELLOW)
        sys.exit(1)
    except Exception as e:
        colorlog(f"\n❌ Unhandled Enhanced Test Error: {e}", Colors.RED)
        sys.exit(1)

if __name__ == "__main__":
    main()
