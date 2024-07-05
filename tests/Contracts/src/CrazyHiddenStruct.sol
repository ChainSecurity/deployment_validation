// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract CrazyHiddenStruct {
    enum Enum {
        A,
        B
    }

    struct Struct2 {
        uint256 a;
        uint192 b;
    }

    type Type is uint128;

    struct Struct1 {
        uint192 _uint192;
        uint8[3] _arrayUint8;
        int192 _int192;
        bool _bool;
        uint40[] _dynArrayUint40;
        address _address;
        CrazyHiddenStruct _contract;
        uint256[3] _arrayUint256;
        mapping(address _address => uint256 _uint256) _mapping;
        string _string;
        bytes _bytes;
        Enum _enum;
        Struct2 _struct2;
        Type _type;
    }

    struct AddressSlot {
        address value;
    }

    bytes32 private constant StorageLocation1 = 0x41ef84cfd2398a02556624f13effd41aa790a48ce39e70d3a0dc298f7a4dec8a;
    bytes32 private constant StorageLocation2 = 0x852cbd6b186221cbf354c68826ab57cef1512cf2f5d959ca4501e155cbea7ae8;
    bytes32 private constant StorageLocation3 = 0x9482765040f1c978ae595e69b3ad0e4697ca0d1e0581a09be85cfb4a8462e752;
    bytes32 private constant StorageLocation4 = 0xe82aa111a62567be9a414850f7168d2e6c9f9d61a82b90598df0a59035cd53a6;
    bytes32 private constant DirectStorageLocation1 = 0xbfbceebbfa6e5996c6a04ac6db0e347528756a4f073935304cc6139dcc2fb653;
    bytes32 private constant DirectStorageLocation2 = 0x42d0407cb447148fd182bf527909ab1ba2fbaefe3f25cbe9851153586910b294;
    bytes32 private constant KeccakStorageLocation1 = keccak256("keccak1");
    bytes32 private constant KeccakStorageLocation2 = bytes32(uint256(keccak256("keccak2")) - 1);

    constructor() {
        Struct1 storage $1 = _getStorage1();
        $1._uint192 = 20;
        $1._arrayUint8[0] = 21;
        $1._arrayUint8[1] = 22;
        $1._arrayUint8[2] = 23;
        $1._int192 = -24;
        $1._bool = true;
        $1._dynArrayUint40.push(25);
        $1._dynArrayUint40.push(26);
        $1._dynArrayUint40.push(27);
        $1._address = address(this);
        $1._contract = CrazyHiddenStruct(address(this));
        $1._arrayUint256[0] = 28;
        $1._arrayUint256[1] = 29;
        $1._arrayUint256[2] = 30;
        $1._mapping[address(this)] = 32;
        $1._string = "test";
        $1._bytes = bytes("testitest");
        $1._enum = Enum.B;
        $1._struct2 = Struct2(33, 34);
        $1._type = Type.wrap(35);

        Struct1 storage $2 = _getStorage2();
        $2._uint192 = 36;
        $2._arrayUint8[0] = 37;
        $2._arrayUint8[1] = 38;
        $2._arrayUint8[2] = 39;
        $2._int192 = -40;
        $2._bool = false;
        $2._dynArrayUint40.push(41);
        $2._dynArrayUint40.push(42);
        $2._dynArrayUint40.push(43);
        $2._address = address(this);
        $2._contract = CrazyHiddenStruct(address(this));
        $2._arrayUint256[0] = 44;
        $2._arrayUint256[1] = 45;
        $2._arrayUint256[2] = 46;
        $2._mapping[address(this)] = 47;
        $2._string = "test2";
        $2._bytes = bytes("testitest2");
        $2._enum = Enum.A;
        $2._struct2 = Struct2(48, 49);
        $2._type = Type.wrap(50);

        Struct2 storage $3 = _getStorage3();
        $3.a = 51;
        $3.b = 52;

        Struct2 storage $4 = _getStorage4();
        $4.a = 53;
        $4.b = 54;

        _setDirect1(55);
        _setDirect2(56);
        _setDirect3(57);
        _setDirect4(58);

        _setImplementation(address(this));
        _setAdmin(address(this));
        _setOwner(address(this));

        Struct2 storage $5 = _getKeccakStorage1();
        $5.a = 59;
        $5.b = 60;

        Struct2 storage $6 = _getKeccakStorage2();
        $6.a = 61;
        $6.b = 62;
    }

    function _getStorage1() internal pure returns (Struct1 storage $) {
        assembly {
            $.slot := StorageLocation1
        }
    }

    function _getStorage2() internal pure returns (Struct1 storage $) {
        bytes32 slot = StorageLocation2;

        assembly {
            $.slot := slot
        }
    }

    function _getStorage3() internal pure returns (Struct2 storage $) {
        bytes32 slot = 0x35651ad27f3aefbb385b9ec8083a43fa66a530f8d5c595761b795067f1e74a1e;

        assembly {
            $.slot := slot
        }
    }

    function _getStorage4() internal pure returns (Struct2 storage $) {
        assembly {
            $.slot := 0x15a25abce1e290903dfb3bf850cde568a79974bd708fad6773051983c8f32392
        }
    }

    function _setDirect1(uint256 data) internal {
        assembly {
            sstore(DirectStorageLocation1, data)
        }
    }

    function _setDirect2(uint256 data) internal {
        bytes32 slot = DirectStorageLocation2;

        assembly {
            sstore(slot, data)
        }
    }

    function _setDirect3(uint256 data) internal {
        bytes32 slot = 0xd63cda19032c797bc0681e2077ae95a9a76af0fdb8f771b8f1cfcdf6578aca6c;

        assembly {
            sstore(slot, data)
        }
    }

    function _setDirect4(uint128 data) internal {
        assembly {
            sstore(0x4a7aec098045e3d96a6592c68c6dbd22bd3358e23bcaa52ab70d20bef4f890ef, data)
        }
    }

    function getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    function _setImplementation(address newImplementation) private {
        getAddressSlot(StorageLocation3).value = newImplementation;
    }

    function _setAdmin(address newAdmin) private {
        AddressSlot storage slot = getAddressSlot(StorageLocation4);
        slot.value = newAdmin;
    }

    function _setOwner(address newOwner) private {
        AddressSlot storage slot = getAddressSlot(0xa83659c989cfe332581a2ed207e0e6d23d9199b0de773442a1e23a9b8c5138f0);
        slot.value = newOwner;
    }

    function _getKeccakStorage1() internal pure returns (Struct2 storage $) {
        bytes32 slot = KeccakStorageLocation1;

        assembly {
            $.slot := slot
        }
    }

    function _getKeccakStorage2() internal pure returns (Struct2 storage $) {
        bytes32 slot = KeccakStorageLocation2;

        assembly {
            $.slot := slot
        }
    }

    function dummy() external {}
}
