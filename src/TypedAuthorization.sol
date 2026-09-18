// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TypedAuthorization {
    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
    //Implement a minimal typed authorization

    // ```text
    // Authorization
    // ├── user
    // ├── recipient
    // ├── amount
    // ├── nonce
    // └── deadline
    bytes32 private constant AUTHORIZATION_TYPEHASH =
        keccak256(
            "Authorization(address user,address recipient,uint256 amount,uint256 nonce,uint256 deadline)"
        );

    bytes32 public immutable DOMAIN_SEPARATOR;

    mapping(address => uint256) public nonce;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("TypedAuthorization")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    struct Authorization {
        address user;
        address recipient;
        uint256 amount;
        uint256 nonce;
        uint256 deadline;
    }

    function execute(
        Authorization calldata authorization,
        bytes calldata signature
    ) external {
        require(block.timestamp <= authorization.deadline, "Expired");

        require(
            authorization.nonce == nonce[authorization.user],
            "Invalid nonce"
        );

        bytes32 structHash = keccak256(
            abi.encode(
                AUTHORIZATION_TYPEHASH,
                authorization.user,
                authorization.recipient,
                authorization.amount,
                authorization.nonce,
                authorization.deadline
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = _splitSignature(signature);

        address signer = ecrecover(digest, v, r, s);

        require(signer == authorization.user, "Invalid signer");

        // Consume nonce BEFORE execution.
        nonce[authorization.user]++;

        (bool success, ) = authorization.recipient.call{
            value: authorization.amount
        }("");

        require(success, "Transfer failed");
    }

    function _splitSignature(
        bytes calldata signature
    ) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        require(signature.length == 65, "Invalid signature");

        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
    }

    receive() external payable {}
}
