# Naive Receiver

## Vulnerability
`FlashLoanReceiver.onFlashLoan` only checks that the caller is the pool. It never checks who started the loan, so anyone can make it pay the fixed 1 WETH fee.
`NaiveReceiverPool._msgSender()` trusts the last 20 bytes of calldata whenever `msg.sender == trustedForwarder`. Because `Multicall.multicall` uses `delegatecall` on `address(this)`, `msg.sender` stays the forwarder while each sub-call's calldata is fully attacker-controlled. Any address can then be spoofed in `withdraw`.

## Exploit
One player transaction ([test](../test/naive-receiver/NaiveReceiver.t.sol)):

1. Build 10 sub-calls `flashLoan(receiver, weth, 0, "")`. Each one charges the receiver 1 WETH, so the receiver goes 10 → 0 WETH. The fees are credited to `deposits[deployer]` (the fee receiver).
2. Build an 11th sub-call: `withdraw(1010e18, recovery)` with the `deployer` address appended (`abi.encodePacked(call, deployer)`). `deposits[deployer]` is 1000e18 (constructor deposit) + 10e18 (fees).
3. Wrap the 11 sub-calls in `pool.multicall(calls)` and put that in a `BasicForwarder.Request` with `from = player`.
4. Sign the EIP-712 digest (`"\x19\x01" ‖ domainSeparator ‖ getDataHash(request)`) with the player key and call `forwarder.execute`.

The forwarder validates only `request.from = player` and appends it to the outer calldata. Inside the delegatecall, `msg.data` is just `data[10]`, so `_msgSender()` reads `deployer` from its last 20 bytes. The ABI decoder ignores the 20 extra bytes, so `withdraw` sends all 1010 WETH to `recovery`.

| Step | receiver | pool | `deposits[deployer]` |
|---|---|---|---|
| Start | 10e18 | 1000e18 | 1000e18 |
| After 10 loans | 0 | 1010e18 | 1010e18 |
| After withdraw | 0 | 0 | 0 |

## Fix
Receiver: only accept loans it started itself.

```solidity
function onFlashLoan(address initiator, address token, uint256 amount, uint256 fee, bytes calldata)
    external returns (bytes32)
{
    if (msg.sender != pool) revert Unauthorized();
    if (initiator != address(this)) revert Unauthorized();
    // ...
}
```

Pool: when the call comes from the forwarder, `multicall` must forward the trusted sender suffix to every sub-call (this is how OpenZeppelin patched `Multicall` for `ERC2771Context`).

```solidity
function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
    bytes memory context = msg.sender == trustedForwarder
        ? msg.data[msg.data.length - 20:]
        : new bytes(0);
    results = new bytes[](data.length);
    for (uint256 i = 0; i < data.length; i++) {
        results[i] = Address.functionDelegateCall(address(this), bytes.concat(data[i], context));
    }
}
```

The real sender is then always the last 20 bytes, so a suffix inside `data[i]` is ignored.

## Real-world parallel
- **TIME token, 7 Dec 2023 (Ethereum):** ERC-2771 forwarder + `Multicall` spoofing let the attacker call `burn` as a Uniswap pool and drain about 84.6 ETH (~$188K). [CertiK analysis](https://www.certik.com/resources/blog/time)
- OpenZeppelin disclosed the same `ERC2771Context` + `Multicall` issue the same day and patched 4.x and 5.x. [Disclosure](https://www.openzeppelin.com/news/arbitrary-address-spoofing-vulnerability-erc2771context-multicall-public-disclosure)