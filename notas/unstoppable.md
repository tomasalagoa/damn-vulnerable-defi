# Unstoppable

## Vulnerability
`UnstoppableVault.flashLoan()` requires `convertToShares(totalSupply) == totalAssets()`.
`totalAssets()` reads the vault's real token balance, so the check assumes tokens only ever enter through `deposit()`. It also compares shares with assets, which only holds at a 1:1 ratio.

## Exploit
Transfer 1 wei of DVT straight to the vault with `token.transfer(address(vault), 1)`.
The balance goes up without minting shares, the equality breaks, and every `flashLoan` call reverts with `InvalidBalance()` forever. A permanent denial of service for the cost of 1 wei. See `test/unstoppable/Unstoppable.t.sol`.

## Fix
Track deposited assets in an internal variable updated only by `deposit`/`withdraw`, and drop the strict equality against the live token balance.
