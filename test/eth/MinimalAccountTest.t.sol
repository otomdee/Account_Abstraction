// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {DeployMinimal} from "../../script/DeployMinimal.s.sol";
import {MinimalAccount} from "../../src/eth/MinimalAccount.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";
import {SendPackedUserOp, PackedUserOperation, IEntryPoint} from "script/SendPackedUserOp.s.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract MinimalAccountTest is Test {
    HelperConfig helperConfig;
    HelperConfig.NetworkConfig activeNetworkConfig;
    MinimalAccount minimalAccount;
    address owner;
    SendPackedUserOp sendPackedUserOpScript;
    ERC20Mock usdc;
    uint256 constant AMOUNT = 1e18;
    address randomUser = makeAddr("user");

    using MessageHashUtils for bytes32;

    function setUp() public {
        DeployMinimal deployMinimal = new DeployMinimal();
        // Deploy MinimalAccount using deployment script
        (helperConfig, minimalAccount) = deployMinimal.deployMinimalAccount();
        activeNetworkConfig = helperConfig.getConfig();
        // Deploy a mock USDC token for interaction
        usdc = new ERC20Mock();
        sendPackedUserOpScript = new SendPackedUserOp();
    }

    function testOwnerCanExecuteCommands() public {
        assertEq(usdc.balanceOf(address(minimalAccount)), 0, "Initial USDC balance should be 0");
        address dest = address(usdc); // Target contract is the mock USDC
        uint256 value = 0; // No ETH value sent in the internal call from account to USDC

        // Prepare calldata for: usdc.mint(address(minimalAccount), AMOUNT)
        bytes memory functionData = abi.encodeWithSelector(
            ERC20Mock.mint.selector, // Function selector for mint(address,uint256)
            address(minimalAccount), // Argument 1: recipient of minted tokens
            AMOUNT // Argument 2: amount to mint
        );

        //call execute on minimal account, as owner
        vm.prank(minimalAccount.owner());
        minimalAccount.execute(dest, value, functionData); // Owner calls execute

        // Assert
        // Check if MinimalAccount now has the minted USDC
        assertEq(usdc.balanceOf(address(minimalAccount)), AMOUNT, "MinimalAccount should have minted USDC");
    }

    function testNonOwnerCannotExecuteCommands() public {
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory functionData = abi.encodeWithSelector(ERC20Mock.mint.selector, address(minimalAccount), AMOUNT);

        vm.prank(randomUser); // call with a random, non-owner address

        // Expect the call to revert with the specific error from the modifier
        // MinimalAccount__NotFromEntryPointOrOwner is the custom error
        vm.expectRevert(MinimalAccount.MinimalAccount__NotFromEntryPointOrOwner.selector);
        minimalAccount.execute(dest, value, functionData); // Attempt to call execute
    }

    function testRecoverSignedOp() public view {
        //this tests if packedUserOp script's generateUserOperation generates the signed operation correctly.

        bytes memory functionDataForUSDCMint =
            abi.encodeWithSelector(usdc.mint.selector, address(minimalAccount), AMOUNT);

        // 2. Define the callData for MinimalAccount.execute
        // This is what the EntryPoint should use to call the smart account(minimalAccount).
        bytes memory executeCallData = abi.encodeWithSelector(
            minimalAccount.execute.selector,
            address(usdc), // dest: the USDC contract
            0, // value: no ETH sent with this call
            functionDataForUSDCMint // data: the encoded call to usdc.mint
        );
        // 3. Generate the signed PackedUserOperation

        PackedUserOperation memory packedUserOp =
            sendPackedUserOpScript.generateUserOperation(executeCallData, activeNetworkConfig, address(minimalAccount));

        // 4. Get the hash of the signed PackedUserOperation struct, from the EntryPoint
        console.logAddress(activeNetworkConfig.entryPoint);
        bytes32 userOperationHash = IEntryPoint(activeNetworkConfig.entryPoint).getUserOpHash(packedUserOp);

        address actualSigner = ECDSA.recover(userOperationHash.toEthSignedMessageHash(), packedUserOp.signature);

        assertEq(actualSigner, minimalAccount.owner());
    }
}
