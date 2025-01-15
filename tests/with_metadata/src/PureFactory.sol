contract PureChild {
    constructor() {
        uint256 index;
        if (gasleft() > 1) {
            index = 6;
        }
        some_map[index] = 7;
    }

    uint256 public very_important = 42;

    uint256 public some_function = 23;

    mapping(uint256 => uint256) public some_map;
}

contract PureDeployer {
    address x;

    constructor() {
        x = address(new PureChild());
    }

    function dummy() external {}
}
        