// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Test, console } from "forge-std/Test.sol";
import { GuardianValidator } from "../src/GuardianValidator.sol";

contract PrintAddressesScript is Test {
    address internal constant ENTRY_POINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    function test_printAddresses() public {
        GuardianValidator validator = new GuardianValidator(ENTRY_POINT_V07);
        address account = makeAddr("cross-verify-account");
        console.log("VALIDATOR_ADDR=%s", address(validator));
        console.log("ACCOUNT_ADDR=%s", account);
        console.log("ENTRY_POINT=%s", ENTRY_POINT_V07);
    }
}
