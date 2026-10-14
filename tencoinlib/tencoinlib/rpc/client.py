import json
import socket
import time
from typing import Dict, Any, Optional, List
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import http.client

from ..constants import DEFAULT_RPC_PORT, DEFAULT_RPC_TOKEN
from .exceptions import (
    RPCError, ConnectionError, AuthenticationError, 
    TimeoutError, ResponseError, InvalidMethodError,
    PublicKeyNotFoundError
)
from .publickey import PublicKeyInfo, parse_get_public_key_response

class RPCClient:
    """
    Synchronous JSON-RPC client for Tencoin nodes.
    
    Example:
        >>> client = RPCClient("127.0.0.1", 10111, "your_token")
        >>> balance = client.get_balance("tc1q...")
        >>> txid = client.send_raw_transaction("hex_data")
    """
    
    def __init__(
        self, 
        host: str = "127.0.0.1", 
        port: int = DEFAULT_RPC_PORT,
        token: str = DEFAULT_RPC_TOKEN,
        timeout: int = 30,
        use_ssl: bool = False
    ):
        """
        Initialize RPC client.
        
        Args:
            host: Node hostname or IP
            port: RPC port (default: 10111)
            token: RPC authentication token
            timeout: Request timeout in seconds
            use_ssl: Use HTTPS instead of HTTP
        """
        self.host = host
        self.port = port
        self.token = token
        self.timeout = timeout
        self.use_ssl = use_ssl
        
        # Build base URL
        protocol = "https" if use_ssl else "http"
        self.url = f"{protocol}://{host}:{port}/"
        
        # Test connection
        self._test_connection()
    
    def _make_request(self, method: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Make JSON-RPC request.
        
        Args:
            method: RPC method name
            params: Method parameters
            
        Returns:
            Response dictionary
        """
        payload = {
            "token": self.token,
            "command": method,
            "params": params or {}
        }
        
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Tencoin-Core/0.1.0"
        }
        
        try:
            # Convert to JSON
            data = json.dumps(payload).encode('utf-8')
            
            # Create request
            req = Request(self.url, data=data, headers=headers, method="POST")
            
            # Send request
            with urlopen(req, timeout=self.timeout) as response:
                response_data = response.read().decode('utf-8')
                
                # Parse JSON response
                result = json.loads(response_data)
                
                # Check for error in response
                if "error" in result:
                    error_msg = result.get("error", "Unknown error")
                    raise ResponseError(f"RPC error: {error_msg}")
                
                return result
                
        except HTTPError as e:
            if e.code == 403:
                raise AuthenticationError("Invalid RPC token")
            elif e.code == 404:
                raise InvalidMethodError(f"Method not found: {method}")
            else:
                raise ConnectionError(f"HTTP error {e.code}: {e.reason}")
        except URLError as e:
            raise ConnectionError(f"Connection error: {e.reason}")
        except socket.timeout:
            raise TimeoutError(f"Request timeout after {self.timeout} seconds")
        except json.JSONDecodeError as e:
            raise ResponseError(f"Invalid JSON response: {e}")
        except Exception as e:
            raise RPCError(f"Unexpected error: {e}")
    
    def _test_connection(self):
        """Test connection to node"""
        try:
            self.get_block_count()
        except AuthenticationError:
            # Authentication failed but connection is OK
            pass
        except Exception as e:
            raise ConnectionError(f"Cannot connect to {self.host}:{self.port}: {e}")
    
    # --- Wallet Methods ---
    
    def get_balance(self, address: str) -> int:
        """
        Get balance for an address.
        
        Args:
            address: Tencoin address
            
        Returns:
            Balance in Tenos
        """
        result = self._make_request("getbalance", {"address": address})
        return result.get("balance", 0)
    
    def list_unspent(self, address: str, minconf: int = 1) -> List[Dict[str, Any]]:
        """
        List unspent transaction outputs for an address.
        
        Args:
            address: Tencoin address
            minconf: Minimum confirmations
            
        Returns:
            List of UTXOs
        """
        result = self._make_request("listunspent", {
            "address": address,
            "minconf": minconf
        })
        return result.get("utxos", [])
    
    # --- Transaction Methods ---
    
    def send_raw_transaction(self, tx_hex: str) -> str:
        """
        Broadcast a raw transaction.
        
        Args:
            tx_hex: Hexadecimal transaction data
            
        Returns:
            Transaction ID
        """
        result = self._make_request("submittransaction", {"tx_hex": tx_hex})
        
        if "error" in result:
            raise ResponseError(f"Failed to send transaction: {result['error']}")
        
        return result.get("txid", "")
    
    def test_mempool_accept(self, tx_hex: str) -> Dict[str, Any]:
        """
        Test if a transaction would be accepted to mempool.
        
        Args:
            tx_hex: Hexadecimal transaction data
            
        Returns:
            Test result
        """
        return self._make_request("testmempoolaccept", {"hex": tx_hex})
    
    def get_transaction(self, txid: str) -> Dict[str, Any]:
        """
        Get transaction details.
        
        Args:
            txid: Transaction ID
            
        Returns:
            Transaction details
        """
        return self._make_request("gettransaction", {"txid": txid})
    
    def get_raw_transaction(self, txid: str) -> str:
        """
        Get raw transaction hex.
        
        Args:
            txid: Transaction ID
            
        Returns:
            Raw transaction hex
        """
        result = self._make_request("gettransaction", {"txid": txid})
        return result.get("hex", "")
    
    def get_public_key(self, address: str) -> PublicKeyInfo:
        """
        Find the public key of an address on the blockchain (node command ``getpublickey``).

        An address is only the HASH160 of a key. The key itself appears on-chain the first
        time the address spends an output (in the scriptSig or witness), so an address that
        never spent has no public key to find.

        The returned key is checked locally: it must hash to ``address``, otherwise
        PublicKeyVerificationError is raised and the node's answer is not used.

        Args:
            address: Tencoin address (tc1q..., P2PKH or P2SH-P2WPKH)

        Returns:
            PublicKeyInfo (``.public_key``, ``.compressed``, ``.format``, ``.txid``,
            ``.input_index``, ``.location``, ``.height``)

        Raises:
            PublicKeyNotFoundError:     the address has never been used as a spending input
            PublicKeyVerificationError: the node's key does not match the address
        """
        try:
            result = self._make_request("getpublickey", {"address": address})
        except ResponseError as exc:
            if "no public key" in str(exc).lower():
                raise PublicKeyNotFoundError(address) from exc
            raise
        return parse_get_public_key_response(address, result)

    # --- Blockchain Methods ---
    
    def get_block_count(self) -> int:
        """
        Get current block height.
        
        Returns:
            Block height
        """
        result = self._make_request("getblockcount", {})
        return result.get("height", 0)
    
    def get_best_block_hash(self) -> str:
        """
        Get hash of best block.
        
        Returns:
            Block hash
        """
        result = self._make_request("getbestblockhash", {})
        return result.get("hash", "")
    
    def get_block(self, block_hash: str = None, height: int = None) -> Dict[str, Any]:
        """
        Get block information.
        
        Args:
            block_hash: Block hash (optional)
            height: Block height (optional)
            
        Returns:
            Block information
        """
        params = {}
        if block_hash:
            params["hash"] = block_hash
        elif height is not None:
            params["height"] = height
        else:
            raise ValueError("Either block_hash or height must be provided")
        
        return self._make_request("getblock", params)
    
    def get_block_header(self, block_hash: str) -> Dict[str, Any]:
        """
        Get block header.
        
        Args:
            block_hash: Block hash
            
        Returns:
            Block header
        """
        return self._make_request("getblockheader", {"hash": block_hash})
    
    # --- Network Methods ---
    
    def get_peer_info(self) -> List[Dict[str, Any]]:
        """
        Get peer information.
        
        Returns:
            List of peers
        """
        result = self._make_request("getpeerinfo", {})
        return result.get("peers", [])
    
    def get_network_info(self) -> Dict[str, Any]:
        """
        Get network information.
        
        Returns:
            Network info
        """
        return self._make_request("getnetworkinfo", {})
    
    # --- Mining Methods ---
    
    def get_work(self) -> Dict[str, Any]:
        """
        Get work for mining.
        
        Returns:
            Mining work
        """
        return self._make_request("getwork", {})
    
    def submit_block(self, block_hex: str) -> Dict[str, Any]:
        """
        Submit a mined block.
        
        Args:
            block_hex: Hexadecimal block data
            
        Returns:
            Submission result
        """
        return self._make_request("submitblock", {"block_hex": block_hex})
    
    # --- Utility Methods ---
    
    def validate_address(self, address: str) -> Dict[str, Any]:
        """
        Validate a Tencoin address.
        
        Args:
            address: Address to validate
            
        Returns:
            Validation result
        """
        return self._make_request("validateaddress", {"address": address})
    
    def decode_raw_transaction(self, tx_hex: str) -> Dict[str, Any]:
        """
        Decode raw transaction.
        
        Args:
            tx_hex: Raw transaction hex
            
        Returns:
            Decoded transaction
        """
        return self._make_request("decoderawtransaction", {"hex": tx_hex})
    
    def get_difficulty(self) -> Dict[str, Any]:
        """
        Get current difficulty.
        
        Returns:
            Difficulty information
        """
        return self._make_request("getdifficulty", {})
    
    def estimate_fee(self, blocks: int = 6) -> Dict[str, Any]:
        """
        Estimate transaction fee.
        
        Args:
            blocks: Target confirmation blocks
            
        Returns:
            Fee estimate
        """
        return self._make_request("estimatefee", {"blocks": blocks})
    
    def get_blockchain_info(self) -> Dict[str, Any]:
        """
        Get blockchain information.
        
        Returns:
            Blockchain info
        """
        return self._make_request("getblockchaininfo", {})
    
    def get_mempool_info(self) -> Dict[str, Any]:
        """
        Get mempool information.
        
        Returns:
            Mempool info
        """
        return self._make_request("getmempoolinfo", {})
    
    def get_raw_mempool(self) -> Dict[str, Any]:
        """
        Get raw mempool transactions.
        
        Returns:
            Mempool transactions
        """
        return self._make_request("getmempool", {})